"""Daily FIRST EPSS CSV: bounded streaming ingestion with no API key.

FIRST specifically recommends the published daily CSV, not its lookup API,
for local synchronization at scale. Only CVEs already in the AVM database are
updated. Never clear scores on download, parse, or validation failure.
"""
import csv
import gzip
import io
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from sqlalchemy import select

from avm.models import Vulnerability, now
from avm.source_engine import CVE_ID


EPSS_CSV_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
MAX_ROWS = 1_000_000
MAX_CSV_BYTES = 128 * 1024 * 1024


class DailyEpssCsv:
    def __init__(self, timeout=90):
        self.timeout = timeout

    def rows(self):
        with requests.get(EPSS_CSV_URL, timeout=self.timeout, stream=True,
                          headers={'User-Agent': 'AssetVulnMonitor/0.3'},
                          allow_redirects=True) as response:
            if urlparse(response.url).scheme != 'https':
                raise RuntimeError('FIRST EPSS file redirected away from HTTPS')
            response.raise_for_status()
            response.raw.decode_content = False
            with gzip.GzipFile(fileobj=response.raw) as compressed:
                stream = io.TextIOWrapper(compressed, encoding='utf-8-sig',
                                          errors='strict', newline='')
                total = [0]
                def valid_lines():
                    for line in stream:
                        total[0] += len(line.encode('utf-8'))
                        if total[0] > MAX_CSV_BYTES:
                            raise ValueError('EPSS CSV decompressed size exceeded')
                        if not line.startswith('#'):
                            yield line
                reader = csv.DictReader(valid_lines())
                if not reader.fieldnames or not {'cve', 'epss', 'percentile'}.issubset(
                        set(reader.fieldnames)):
                    raise ValueError('Invalid FIRST EPSS CSV header')
                count = 0
                for row in reader:
                    count += 1
                    if count > MAX_ROWS:
                        raise ValueError('FIRST EPSS CSV row cap exceeded')
                    ident = (row.get('cve') or '').upper()
                    if not CVE_ID.fullmatch(ident):
                        raise ValueError('Invalid CVE ID in EPSS CSV')
                    try:
                        score, percentile = float(row['epss']), float(row['percentile'])
                    except (TypeError, ValueError):
                        raise ValueError('Invalid EPSS numeric fields') from None
                    if not 0 <= score <= 1 or not 0 <= percentile <= 1:
                        raise ValueError('EPSS values outside expected range')
                    yield ident, score, percentile


def sync_epss_csv(session, *, provider=None, min_rows=10000, stamp=None):
    """Stage all matched scores before touching ORM records.

    Failure midway through reading a gzip file does not mutate any CVE row.
    Only local CVE IDs are retained, not the entire external daily dataset.
    """
    api = provider or DailyEpssCsv()
    known = set(session.scalars(select(Vulnerability.id)).all())
    matched = {}
    read_count = 0
    for cve, score, percentile in api.rows():
        read_count += 1
        if cve in known:
            matched[cve] = (score, percentile)
    if read_count < min_rows:
        raise ValueError('Refusing incomplete FIRST EPSS CSV snapshot')
    checked = stamp or now()
    for cve, (score, percentile) in matched.items():
        v = session.get(Vulnerability, cve)
        if v is None or v.synthetic:
            continue
        v.epss = score
        v.epss_percentile = percentile
        v.epss_asof = checked
        v.epss_date = checked.date().isoformat()
    return len(matched)
