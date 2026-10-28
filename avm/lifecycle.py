"""Conservative finding lifecycle and daily ranking snapshot.

A missing match is never labelled 'fixed' or 'remediated'. Changes from a
successful inventory scan are recorded as 'not_observed'; a full validation
still requires vendor/product evidence. Feed-only refreshes cannot close items.
"""
from collections import defaultdict
from datetime import timedelta
from sqlalchemy import select

from avm.matching import is_affected
from avm.models import (AffectedPackage, Asset, Finding, FindingEvent, Installation,
                        RiskSnapshot, Software, Vulnerability, now)
from avm.risk import priority_score, evidence_packet, remediation_plan


SLA_DAYS = {'P1': 7, 'P2': 30, 'P3': 90, 'P4': 180}


def _event(session, finding, action, reason):
    session.flush()
    session.add(FindingEvent(finding_id=finding.id, action=action,
                             actor='system:worker', reason=reason))


def recalculate_findings(session, *, allow_disappearance=False, sla_days=None):
    """Rebuild potential matches; closure only with an explicitly complete scan."""
    deadlines = dict(SLA_DAYS)
    if sla_days is not None:
        if not isinstance(sla_days, dict) or set(sla_days) != set(SLA_DAYS):
            raise ValueError('risk.sla_days requires exactly P1, P2, P3, P4')
        for level, days in sla_days.items():
            if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 3650:
                raise ValueError('Each SLA duration must be 1..3650 days')
        deadlines.update(sla_days)
    stamp = now()
    packages = defaultdict(list)
    for affected in session.scalars(select(AffectedPackage)):
        if affected.evidence_status not in (None, 'current'):
            continue
        packages[(affected.ecosystem.casefold(), affected.package_name.casefold())].append(affected)
    software = {row.id: row for row in session.scalars(select(Software))}
    assets = {row.id: row for row in session.scalars(select(Asset))}
    vulnerabilities = {row.id: row for row in session.scalars(select(Vulnerability))}
    existing = {(row.installation_id, row.vulnerability_id): row
                for row in session.scalars(select(Finding))}
    observed = set()

    for installed in session.scalars(select(Installation).where(Installation.active.is_(True))):
        asset = assets.get(installed.asset_id)
        product = software.get(installed.software_id)
        if not asset or not asset.active or not product or not product.ecosystem or not product.package_name:
            continue
        grouped = defaultdict(list)
        # Only a *definite* FALSE from a comparable, explicit affected range
        # can be called a potential disagreement; silence is not a negative vote.
        evaluated_by_source = defaultdict(lambda: defaultdict(list))
        for affected in packages.get((product.ecosystem.casefold(), product.package_name.casefold()), []):
            if affected.matched_version is not None and affected.matched_version != installed.version:
                continue
            evaluated = is_affected(installed.version, affected.affected_spec)
            if evaluated is not None:
                evaluated_by_source[affected.vulnerability_id][affected.source or 'cve_now'].append(evaluated)
            if evaluated is True:
                grouped[affected.vulnerability_id].append(affected)
        for cve_id, matched_evidence in grouped.items():
            specs = [row.affected_spec for row in matched_evidence]
            vulnerability = vulnerabilities.get(cve_id)
            if vulnerability is None:
                continue
            key = (installed.id, cve_id)
            observed.add(key)
            record = existing.get(key)
            if record is None:
                record = Finding(
                    installation_id=installed.id, vulnerability_id=cve_id,
                    confidence='potential-structured-range',
                    evidence='Approved identity and affected range; requires vendor verification.')
                session.add(record)
                session.flush()
                existing[key] = record
                _event(session, record, 'detected', 'Potential match from approved product identity and affected version')
            elif not record.active or record.workflow_state == 'not_observed':
                _event(session, record, 'reopened', 'Previously unobserved match was detected again')
                record.workflow_state = 'open'
                record.accepted_until = None
                record.accepted_by = None
                record.acceptance_reason = None
                record.state_updated_at = stamp

            if record.workflow_state == 'accepted' and (record.accepted_until is None
                                                        or record.accepted_until <= stamp):
                _event(session, record, 'acceptance_expired', 'Risk acceptance expired')
                record.workflow_state = 'open'
                record.state_updated_at = stamp

            result = priority_score(cvss=vulnerability.cvss, epss=(vulnerability.epss if (vulnerability.synthetic or vulnerability.epss_asof is not None) else None),
                                    kev=(bool(vulnerability.kev_verified) or (vulnerability.synthetic and bool(vulnerability.kev))),
                                    criticality=asset.criticality or 'unknown',
                                    internet_facing=asset.internet_facing)
            evidence = evidence_packet(asset=asset, software=product, installation=installed,
                                       vulnerability=vulnerability, affected_specs=specs,
                                       matched_at=stamp)
            record.active = True
            record.last_detected = stamp
            record.confidence = 'potential-structured-range'
            record.evidence = ('Approved package identity and structured affected-version range; '
                               'requires vendor/backport verification.')
            evidence['reporting_sources'] = sorted(set(
                row.source or 'cve_now' for row in matched_evidence))
            evidence['source_evidence'] = [
                {'source': row.source or 'cve_now',
                 'source_id': row.source_id or row.vulnerability_id,
                 'match_method': ('osv_package_version_lookup'
                                  if row.source == 'osv' else 'structured_affected_range'),
                 'matched_version': row.matched_version}
                for row in matched_evidence][:30]
            explicit_negative = sorted([
                name for name, decisions in evaluated_by_source[cve_id].items()
                if decisions and not any(decisions)])
            positive = {row.source or 'cve_now' for row in matched_evidence}
            evidence['range_disagreement_sources'] = (
                explicit_negative if positive else [])
            evidence['source_conflict'] = (
                'potential_range_disagreement' if explicit_negative and positive
                else 'none_observed')
            evidence['source_agreement'] = (
                'multiple_reporting_paths_not_independent'
                if len(evidence['reporting_sources']) > 1 else 'single_reporting_path')
            record.evidence_packet = evidence
            record.remediation = remediation_plan(evidence=evidence,
                                                  kev_action=vulnerability.kev_action)
            record.risk_score = result['score']
            record.priority = result['priority']
            record.risk_factors = result
            record.sla_due_at = record.first_detected + timedelta(days=deadlines[record.priority])
            if record.workflow_state in (None, ''):
                record.workflow_state = 'open'
            if record.state_updated_at is None:
                record.state_updated_at = stamp

    # A threat-intel or CVE-only refresh cannot prove an asset was remediated.
    for key, finding in existing.items():
        if key in observed:
            continue
        installed = session.get(Installation, finding.installation_id)
        asset = assets.get(installed.asset_id) if installed else None
        # A feed correction/retraction alone cannot prove patching. An
        # existing installation must actually disappear before not_observed.
        observed_installation_gone = (
            installed is None or not installed.active or asset is None or not asset.active)
        if allow_disappearance and finding.active and observed_installation_gone:
            finding.active = False
            finding.workflow_state = 'not_observed'
            finding.state_updated_at = stamp
            _event(session, finding, 'not_observed',
                   'Installation absent from completed inventory; not proof of remediation')
        elif finding.active:
            if allow_disappearance and finding.workflow_state not in ('needs_review', 'accepted'):
                finding.workflow_state = 'needs_review'
                finding.state_updated_at = stamp
                _event(session, finding, 'source_evidence_missing',
                       'Previously matched version still installed but no current source match; manual review required')
            vulnerability = vulnerabilities.get(finding.vulnerability_id)
            installed = session.get(Installation, finding.installation_id)
            asset = assets.get(installed.asset_id) if installed else None
            if vulnerability and asset:
                score = priority_score(cvss=vulnerability.cvss, epss=(vulnerability.epss if (vulnerability.synthetic or vulnerability.epss_asof is not None) else None),
                                       kev=(bool(vulnerability.kev_verified) or (vulnerability.synthetic and bool(vulnerability.kev))),
                                       criticality=asset.criticality or 'unknown',
                                       internet_facing=asset.internet_facing)
                finding.risk_score = score['score']
                finding.priority = score['priority']
                finding.risk_factors = score
                finding.sla_due_at = finding.first_detected + timedelta(days=deadlines[score['priority']])
                if finding.workflow_state == 'accepted' and (
                        finding.accepted_until is None or finding.accepted_until <= stamp):
                    _event(session, finding, 'acceptance_expired', 'Risk acceptance expired')
                    finding.workflow_state = 'open'
                    finding.state_updated_at = stamp

    # One daily point, idempotently updated at each calculation.
    active_findings = [
        x for x in existing.values()
        if x.active and x.risk_score is not None
        and ((install := session.get(Installation, x.installation_id)) is not None)
        and install.active and assets.get(install.asset_id) is not None
        and assets[install.asset_id].active
    ]
    today = stamp.date().isoformat()
    snapshot = session.scalar(select(RiskSnapshot).where(RiskSnapshot.day == today))
    if snapshot is None:
        snapshot = RiskSnapshot(day=today)
        session.add(snapshot)
    snapshot.active_findings = len(active_findings)
    snapshot.p1_findings = sum(row.priority == 'P1' for row in active_findings)
    snapshot.priority_points = round(sum(float(row.risk_score) for row in active_findings), 2)
    snapshot.created_at = stamp
    return len(observed)
