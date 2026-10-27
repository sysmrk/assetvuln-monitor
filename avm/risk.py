"""Deterministic explainable prioritization—not an exploit prediction.

No guessed asset criticality, internet reachability, exploitability or fixes.
A risk score is an operational ranking, NOT a probability of exploitation.
"""
from datetime import datetime, timezone
from packaging.version import InvalidVersion, Version


CRITICALITY_POINTS = {'unknown': 0, 'low': 2, 'medium': 5, 'high': 8, 'critical': 10}


def priority_score(*, cvss=None, epss=None, kev=False,
                   criticality='unknown', internet_facing=None):
    missing = []
    if cvss is None:
        missing.append('cvss')
        cvss_part = 0.0
    else:
        cvss = float(cvss)
        if not 0 <= cvss <= 10:
            raise ValueError('CVSS must be in the range 0..10')
        cvss_part = 4.0 * cvss

    if epss is None:
        missing.append('epss')
        epss_part = 0.0
    else:
        epss = float(epss)
        if not 0 <= epss <= 1:
            raise ValueError('EPSS must be in the range 0..1')
        epss_part = 20.0 * epss ** .5

    if criticality not in CRITICALITY_POINTS:
        raise ValueError('Unsupported asset criticality')
    if criticality == 'unknown':
        missing.append('asset_criticality')
    if internet_facing not in (True, False, None):
        raise ValueError('Internet-facing must be true, false or unknown')
    if internet_facing is None:
        missing.append('internet_exposure')

    factors = {
        'cvss': round(cvss_part, 2),
        'epss': round(epss_part, 2),
        'cisa_kev': 25 if kev else 0,
        'asset_criticality': CRITICALITY_POINTS[criticality],
        'internet_exposure': 5 if internet_facing is True else 0,
    }
    weighted = sum(factors.values())
    floor_applied = bool(kev and weighted < 75)
    score = round(min(100, max(weighted, 75 if kev else 0)), 2)
    label = ('P1' if score >= 75 else 'P2' if score >= 50
             else 'P3' if score >= 25 else 'P4')
    return {
        'score': score,
        'priority': label,
        'components': factors,
        'kev_floor_applied': floor_applied,
        'missing_signals': missing,
        'method': 'AVM-priority-v1',
        'disclaimer': 'Operational prioritization score, not exploit probability or validated exposure.',
    }


def fixed_version_candidates(affected_specs):
    """Explicit OSV-style fixed events only; never invent upgrade targets."""
    output = set()
    for spec in affected_specs:
        if not isinstance(spec, dict):
            continue
        for item in spec.get('ranges', []) or []:
            if not isinstance(item, dict) or str(item.get('type', '')).upper() not in ('SEMVER', 'ECOSYSTEM'):
                continue
            for event in item.get('events', []) or []:
                if isinstance(event, dict) and 'fixed' in event:
                    raw = str(event['fixed']).strip()
                    try:
                        Version(raw.lstrip('v'))
                    except InvalidVersion:
                        continue
                    output.add(raw)
    return sorted(output, key=lambda v: Version(v.lstrip('v')))[:10]


def evidence_packet(*, asset, software, installation, vulnerability,
                    affected_specs, matched_at=None):
    """Snapshot of machine-readable evidence for a potential finding."""
    versions = fixed_version_candidates(affected_specs)
    return {
        'schema_version': 1,
        'observed_at': (matched_at or datetime.now(timezone.utc)).isoformat(),
        'asset_source_id': asset.source_id,
        'asset_hostname': asset.hostname,
        'software_vendor': software.vendor,
        'software_name': software.name,
        'software_version': installation.version,
        'approved_package': {
            'ecosystem': software.ecosystem,
            'name': software.package_name,
        },
        'vulnerability_id': vulnerability.id,
        'source': 'cve.now-structured-affected',
        'matching': 'approved-package-identity-and-osv-range',
        'threat_intelligence': {
            'cisa_kev_verified': bool(getattr(vulnerability, 'kev_verified', False)),
            'epss_officially_retrieved': getattr(vulnerability, 'epss_asof', None) is not None,
            'epss_retrieved_at': (
                vulnerability.epss_asof.isoformat()
                if getattr(vulnerability, 'epss_asof', None) is not None else None),
            'synthetic_demo': bool(getattr(vulnerability, 'synthetic', False)),
        },
        'affected_ranges': affected_specs[:12],
        'candidate_fixed_versions': versions,
        'limitations': [
            'Software identity and version-based correlation is not proof of exploitability.',
            'Vendor backports and configuration-specific mitigations require human verification.',
            'CVE feed coverage may be incomplete; candidate fixed versions are not validated patches.',
        ],
    }


def remediation_plan(*, evidence, kev_action=None):
    fixed = evidence.get('candidate_fixed_versions') or []
    return {
        'classification': 'requires_vendor_verification',
        'candidate_fixed_versions': fixed,
        'required_action_from_kev': kev_action or None,
        'guidance': ('Check the authoritative vendor advisory and approved update path. '
                     'Verify backports and deploy changes through normal change control; '
                     'reassess after the next successful inventory sync.'),
    }


def scenario_summary(items, remove_ids=(), max_items=None):
    """Read-only score-removal simulation, never a real-world risk prediction."""
    values = {}
    for identifier, score in items:
        if not isinstance(identifier, (str, int)) or score is None:
            continue
        value = float(score)
        if not 0 <= value <= 100:
            raise ValueError('Invalid risk score')
        values[str(identifier)] = value
    if max_items is not None:
        if max_items < 0:
            raise ValueError('max_items must be nonnegative')
        ranked = sorted(values, key=lambda k: (-values[k], k))
        removed = set(ranked[:max_items])
    else:
        removed = {str(i) for i in remove_ids} & values.keys()
    before = round(sum(values.values()), 2)
    delta = round(sum(values[i] for i in removed), 2)
    return {
        'findings_count': len(values),
        'simulated_removals': len(removed),
        'before_score_sum': before,
        'after_score_sum': round(before - delta, 2),
        'modeled_score_reduction_pct': round(100 * delta / before, 2) if before else 0.0,
        'notice': 'Hypothetical removal of ranking points, not a guaranteed security improvement.',
    }
