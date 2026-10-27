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


def recalculate_findings(session, *, allow_disappearance=False):
    """Rebuild potential matches; closure only with an explicitly complete scan."""
    stamp = now()
    packages = defaultdict(list)
    for affected in session.scalars(select(AffectedPackage)):
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
        for affected in packages.get((product.ecosystem.casefold(), product.package_name.casefold()), []):
            if is_affected(installed.version, affected.affected_spec) is True:
                grouped[affected.vulnerability_id].append(affected.affected_spec)
        for cve_id, specs in grouped.items():
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
            record.evidence_packet = evidence
            record.remediation = remediation_plan(evidence=evidence,
                                                  kev_action=vulnerability.kev_action)
            record.risk_score = result['score']
            record.priority = result['priority']
            record.risk_factors = result
            record.sla_due_at = record.first_detected + timedelta(days=SLA_DAYS[record.priority])
            if record.workflow_state in (None, ''):
                record.workflow_state = 'open'
            if record.state_updated_at is None:
                record.state_updated_at = stamp

    # A threat-intel or CVE-only refresh cannot prove an asset was remediated.
    for key, finding in existing.items():
        if key in observed:
            continue
        if allow_disappearance and finding.active:
            finding.active = False
            finding.workflow_state = 'not_observed'
            finding.state_updated_at = stamp
            _event(session, finding, 'not_observed',
                   'No matching active installation in a completed inventory; not proof of remediation')
        elif finding.active:
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
                finding.sla_due_at = finding.first_detected + timedelta(days=SLA_DAYS[score['priority']])
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
