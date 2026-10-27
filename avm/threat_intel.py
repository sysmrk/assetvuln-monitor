"""Daily GET-only enrichment from public CISA KEV and FIRST EPSS sources.

Both sources have fixed HTTPS origins. No API keys, new containers or database
credentials. Ingestion is atomic: upstream failures never clear past signals.
"""
import re
from datetime import datetime, timezone
from sqlalchemy import select

from avm.collectors import ReadOnlyClient
from avm.models import Vulnerability


_CVE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.ASCII)
_MAX_CVE_BATCH = 1800  # FIRST limits comma-joined query to <= 2000 chars


class PublicThreatIntel:
    def __init__(self, timeout=25):
        self.kev = ReadOnlyClient('https://www.cisa.gov', timeout=timeout)
        self.epss = ReadOnlyClient('https://api.first.org', timeout=timeout)

    def fetch_kev(self):
        response = self.kev.get('/sites/default/files/feeds/known_exploited_vulnerabilities.json')
        if not isinstance(response, dict) or not isinstance(response.get('vulnerabilities'), list):
            raise ValueError('Invalid CISA KEV catalogue format')
        rows = response['vulnerabilities']
        # A partial/truncated or unexpected empty response must not clear the catalog.
        if len(rows) < 100:
            raise ValueError('CISA KEV catalog unexpectedly small')
        result = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get('cveID'), str):
                raise ValueError('Unexpected KEV row structure')
            ident = row['cveID'].upper()
            if not _CVE.fullmatch(ident) or ident in result:
                raise ValueError('Invalid or duplicate CISA CVE identifier')
            action = row.get('requiredAction') or ''
            result[ident] = str(action)[:1800] if isinstance(action, str) else ''
        return result

    def fetch_epss(self, cves):
        valid = sorted({str(c).upper() for c in cves if _CVE.fullmatch(str(c).upper())})
        output = {}
        batch = []
        length = 0

        def read_batch(ids):
            payload = self.epss.get('/data/v1/epss', {'cve': ','.join(ids)})
            if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
                raise ValueError('Invalid FIRST EPSS response')
            requested = set(ids)
            for item in payload['data']:
                if not isinstance(item, dict) or item.get('cve') not in requested:
                    raise ValueError('Unexpected EPSS entry')
                value = float(item.get('epss'))
                if not 0 <= value <= 1:
                    raise ValueError('Out-of-range EPSS probability')
                output[item['cve']] = value

        for ident in valid:
            if batch and length + len(ident) + 1 > _MAX_CVE_BATCH:
                read_batch(batch)
                batch, length = [], 0
            batch.append(ident)
            length += len(ident) + (1 if len(batch) > 1 else 0)
        if batch:
            read_batch(batch)
        return output


def enrich_vulnerabilities(session, *, kev_catalog, epss_values):
    """Apply a *complete* KEV catalogue and returned EPSS values to known CVEs."""
    if not isinstance(kev_catalog, dict) or len(kev_catalog) < 100:
        raise ValueError('Refusing incomplete KEV refresh')
    stamp = datetime.now(timezone.utc)
    count = 0
    for item in session.scalars(select(Vulnerability)).all():
        if item.synthetic:
            continue
        if not _CVE.fullmatch(item.id.upper()):
            continue
        action = kev_catalog.get(item.id.upper())
        item.kev = action is not None
        item.kev_verified = action is not None
        item.kev_action = action if action else None
        if item.id in epss_values:
            value = float(epss_values[item.id])
            if not 0 <= value <= 1:
                raise ValueError('Invalid EPSS score')
            item.epss = value
            item.epss_asof = stamp
        item.intel_checked_at = stamp
        count += 1
    return count
