"""Multi-source advisory identity, provenance and package evidence.

Public CVEs are the canonical key when an advisory has exactly one explicit
CVE alias; never guess CPE-to-PURL identity or infer matches from titles.
All operations change only the application's PostgreSQL data.
"""
import re
from datetime import datetime, timezone
from sqlalchemy import select

from avm.models import (AffectedPackage, AdvisoryObservation, OsvPackageCheck,
                        Vulnerability, now)
from avm.matching import is_affected


CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,}$', re.ASCII)
OSV_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{2,99}$', re.ASCII)
SOURCE_ORDER = {'nvd': 4, 'euvd': 3, 'cve_now': 2, 'osv': 1}


def ids_from_aliases(value):
    """Return sorted, normalized, explicit CVE aliases only."""
    if isinstance(value, str):
        candidates = re.split(r'[\s,;]+', value)
    elif isinstance(value, (list, tuple)):
        candidates = value
    else:
        candidates = []
    return sorted({raw.strip().upper() for raw in candidates
                   if isinstance(raw, str) and CVE_ID.fullmatch(raw.strip().upper())})


def canonical_id(source_id, aliases=()):
    sources = ids_from_aliases([source_id] + list(aliases or []))
    # Conflicting CVE identifiers cannot be merged automatically.
    if len(sources) == 1:
        return sources[0]
    if not isinstance(source_id, str) or not OSV_ID.fullmatch(source_id):
        raise ValueError('Invalid advisory source identifier')
    return source_id


def valid_cvss(value):
    try:
        parsed = float(value)
        return round(parsed, 1) if 0 <= parsed <= 10 else None
    except (ValueError, TypeError, OverflowError):
        return None


def note_advisory(session, *, source, source_id, aliases=(), original_source=None,
                  title=None, summary=None, cvss=None, updated_at=None,
                  raw=None, withdrawn=False, synthetic=False):
    """Upsert source-specific metadata without overwriting another source's data."""
    if source not in SOURCE_ORDER or not isinstance(source_id, str) or not OSV_ID.fullmatch(source_id):
        raise ValueError('Unsupported source or invalid advisory ID')
    aliases = ids_from_aliases(aliases)
    canonical = canonical_id(source_id, aliases)
    existing = session.scalar(select(AdvisoryObservation).where(
        AdvisoryObservation.source == source, AdvisoryObservation.source_id == source_id))
    # If a previously non-CVE OSV ID acquires a CVE alias, do not silently
    # repoint old findings: it needs an explicit audited migration.
    if existing is not None and existing.vulnerability_id != canonical:
        canonical = existing.vulnerability_id

    vuln = session.get(Vulnerability, canonical)
    if vuln is None:
        vuln = Vulnerability(id=canonical, synthetic=bool(synthetic))
        session.add(vuln)
    if not vuln.title and title:
        vuln.title = str(title)[:500]
    if not vuln.summary and summary:
        vuln.summary = str(summary)[:5000]
    score = valid_cvss(cvss)
    if score is not None and not synthetic:
        old_rank = SOURCE_ORDER.get(vuln.cvss_source or '', 0)
        if SOURCE_ORDER[source] >= old_rank:
            vuln.cvss = score
            vuln.cvss_source = source
            vuln.severity = ('CRITICAL' if score >= 9 else 'HIGH' if score >= 7
                             else 'MEDIUM' if score >= 4 else 'LOW')
    if existing is None:
        existing = AdvisoryObservation(source=source, source_id=source_id)
        session.add(existing)
    existing.vulnerability_id = canonical
    existing.aliases = aliases
    existing.original_source = (str(original_source)[:300] if original_source else None)
    existing.cvss = score
    existing.status = 'withdrawn' if withdrawn else 'published'
    existing.updated_at = updated_at
    existing.fetched_at = now()
    # A small normalized excerpt, never megabytes of descriptions or HTML.
    existing.raw = raw if isinstance(raw, dict) else None
    session.flush()
    return canonical


def mark_query_evidence(session, *, ecosystem, package_name, version, source_records):
    """Record current successful OSV batch results for one approved package/version.

    Never treat an empty response as proof of remediation. Previously reported
    positives become 'retracted' evidence, still available for audit.
    """
    key = (ecosystem.casefold(), package_name.casefold(), version)
    cache = session.scalar(select(OsvPackageCheck).where(
        OsvPackageCheck.ecosystem == key[0],
        OsvPackageCheck.package_name == key[1], OsvPackageCheck.version == key[2]))
    if cache is None:
        cache = OsvPackageCheck(ecosystem=key[0], package_name=key[1],
                                version=key[2])
        session.add(cache)
    session.flush()
    positives = {}
    for record in source_records:
        if not isinstance(record, dict) or not isinstance(record.get('id'), str):
            raise ValueError('Malformed OSV vulnerability')
        osv_id = record['id']
        if not OSV_ID.fullmatch(osv_id):
            raise ValueError('Invalid OSV ID')
        if record.get('withdrawn'):
            continue
        # A match returned by querybatch is only accepted if the detailed
        # advisory independently refers to the same exact approved package.
        affected = record.get('affected') or []
        if not isinstance(affected, list):
            raise ValueError('OSV affected must be an array')
        supported = False
        for item in affected:
            if not isinstance(item, dict) or not isinstance(item.get('package'), dict):
                continue
            pkg = item['package']
            if str(pkg.get('ecosystem', '')).casefold() != key[0] or str(pkg.get('name', '')).casefold() != key[1]:
                continue
            spec = {'ranges': item.get('ranges') or [], 'versions': item.get('versions') or []}
            # The positive result from the official OSV package/version API
            # is acceptable even if local range parsing is unsupported.
            # Label it as a query-specific potential match, never an exact
            # proven version-range match.
            supported = True
            break
        if not supported:
            continue
        canonical = note_advisory(
            session, source='osv', source_id=osv_id, aliases=record.get('aliases') or [],
            original_source=(record.get('database_specific') or {}).get('source')
                            if isinstance(record.get('database_specific'), dict) else None,
            title=record.get('summary'), summary=record.get('details'),
            updated_at=parse_time(record.get('modified')),
            raw={'references': (record.get('references') or [])[:8],
                 'withdrawn': False})
        positives[osv_id] = canonical

    old = session.scalars(select(AffectedPackage).where(
        AffectedPackage.source == 'osv', AffectedPackage.ecosystem == key[0],
        AffectedPackage.package_name == key[1],
        AffectedPackage.matched_version == version)).all()
    for row in old:
        # Retracted evidence remains in the DB for analysts.
        if row.source_id not in positives:
            row.evidence_status = 'retracted'
    for osv_id, canonical in positives.items():
        row = next((r for r in old if r.source_id == osv_id), None)
        if row is None:
            row = AffectedPackage(source='osv', source_id=osv_id,
                                  vulnerability_id=canonical, ecosystem=key[0],
                                  package_name=key[1], matched_version=version)
            session.add(row)
        row.evidence_status = 'current'
        # Scoped exact-version evidence: OSV querybatch was authoritative
        # about this specific tuple; we do not extrapolate to other versions.
        row.affected_spec = {'versions': [version],
                             'osv_query': 'package_and_version'}
    cache.checked_at = now()
    cache.source_ids = sorted(positives)
    return len(positives)


def parse_time(raw):
    if not raw or not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def source_for_finding(affected):
    return {'source': affected.source or 'cve_now',
            'source_id': affected.source_id or affected.vulnerability_id,
            'status': affected.evidence_status or 'current',
            'query_version': affected.matched_version}


def source_count(session, canonical):
    return session.scalars(select(AdvisoryObservation).where(
        AdvisoryObservation.vulnerability_id == canonical)).all()
