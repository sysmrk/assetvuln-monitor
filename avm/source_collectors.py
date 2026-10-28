"""Bounded public vulnerability collectors; no managed-asset writes.

OSV uses POST only to the fixed public querybatch endpoint (pure lookup).
NVD and EUVD use GET-only, windowed cursor synchronization. No extra service,
no mandatory API keys, no CVE-ID guesses from product names.
"""
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import requests
from sqlalchemy import select, or_
from sqlalchemy.orm import aliased

from avm.collectors import ReadOnlyClient
from avm.models import (AdvisoryObservation, Asset, FeedCheckpoint, Installation,
                        OsvPackageCheck, Software, Vulnerability, now)
from avm.source_engine import (CVE_ID, OSV_ID, ids_from_aliases, note_advisory,
                               mark_query_evidence, parse_time, valid_cvss)

log = logging.getLogger('avm.source_collectors')


def _checkpoint(session, source):
    obj = session.get(FeedCheckpoint, source)
    if obj is None:
        obj = FeedCheckpoint(source=source, state={})
        session.add(obj)
        session.flush()
    return obj


def _rows(response, key):
    if not isinstance(response, dict) or not isinstance(response.get(key), list):
        raise ValueError('Unexpected public feed shape: ' + key)
    return response[key]


def approved_unique_packages(session, limit=200, ttl_hours=24, reference=None):
    """Query distinct approved product/version triples, not every asset.

    Joins are filtered by currently active assets/installations. Staleness
    ordering ensures newly seen packages are checked before cached packages.
    """
    current = reference or now()
    pairs = (select(Software.ecosystem.label('ecosystem'),
                    Software.package_name.label('package_name'),
                    Installation.version.label('version'))
             .join(Installation, Installation.software_id == Software.id)
             .join(Asset, Asset.id == Installation.asset_id)
             .where(Asset.active.is_(True), Installation.active.is_(True),
                    Software.ecosystem.is_not(None), Software.package_name.is_not(None),
                    Installation.version.is_not(None),
                    Installation.version.notin_(['', 'unknown', 'n/a']))
             .distinct().subquery())
    cache = aliased(OsvPackageCheck)
    cutoff = current - timedelta(hours=ttl_hours)
    statement = (select(pairs.c.ecosystem, pairs.c.package_name, pairs.c.version)
                 .outerjoin(cache, (cache.ecosystem == pairs.c.ecosystem) &
                            (cache.package_name == pairs.c.package_name) &
                            (cache.version == pairs.c.version))
                 .where(or_(cache.id.is_(None), cache.checked_at < cutoff))
                 .order_by(cache.checked_at.asc().nullsfirst(),
                           pairs.c.ecosystem, pairs.c.package_name, pairs.c.version)
                 .limit(limit))
    # Normalize only after the approved mapping has been verified; if two
    # case variants collide, the caller sends a single query.
    distinct = {}
    for ecosystem, package, version in session.execute(statement):
        key = (ecosystem.casefold(), package.casefold(), version)
        distinct[key] = key
    return list(distinct)


class OsvBatchClient:
    def __init__(self, timeout=35):
        self.url = 'https://api.osv.dev'
        self.timeout = timeout
        self.http = requests.Session()
        self.http.headers.update({'Accept': 'application/json',
                                  'Content-Type': 'application/json',
                                  'User-Agent': 'AssetVulnMonitor/0.3'})

    def _post(self, queries):
        if not 1 <= len(queries) <= 250:
            raise ValueError('Invalid OSV batch size')
        for attempt in range(4):
            response = self.http.post(
                self.url + '/v1/querybatch', json={'queries': queries},
                timeout=self.timeout, allow_redirects=False)
            if response.status_code in (301, 302, 307, 308):
                raise RuntimeError('OSV batch redirect rejected')
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(min(2 ** attempt, 8))
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError('OSV batch retry limit')

    def get_record(self, osv_id, modified, session):
        if not isinstance(osv_id, str) or not OSV_ID.fullmatch(osv_id):
            raise ValueError('Unsafe OSV source ID')
        cached = session.scalar(select(AdvisoryObservation).where(
            AdvisoryObservation.source == 'osv',
            AdvisoryObservation.source_id == osv_id))
        if (cached and cached.raw and 'affected' in cached.raw
                and cached.raw.get('modified') == modified):
            return dict(cached.raw, id=osv_id)
        client = ReadOnlyClient(self.url, timeout=self.timeout,
                                headers={'User-Agent': 'AssetVulnMonitor/0.3'})
        result = client.get('/v1/vulns/' + quote(osv_id, safe=''))
        if not isinstance(result, dict) or result.get('id') != osv_id:
            raise ValueError('OSV detail record ID mismatch')
        if not isinstance(result.get('affected', []), list):
            raise ValueError('OSV affected section must be an array')
        return result

    def resolve(self, session, triples, max_pages=12):
        """Return complete (triple -> full OSV records) map or raise.

        No partial answers are persisted; the caller commits only after
        *every* page and referenced detail is retrieved successfully.
        """
        if not triples:
            return {}
        if len(triples) > 250:
            raise ValueError('OSV query budget exceeded')
        states = {t: {'token': None, 'seen': set(), 'vulns': {}} for t in triples}
        pending = list(triples)
        for _ in range(max_pages):
            if not pending:
                break
            query = []
            for eco, pkg, version in pending:
                item = {'package': {'ecosystem': eco, 'name': pkg}, 'version': version}
                if states[(eco, pkg, version)]['token']:
                    item['page_token'] = states[(eco, pkg, version)]['token']
                query.append(item)
            response = self._post(query)
            rows = _rows(response, 'results')
            if len(rows) != len(pending):
                raise ValueError('OSV batch response not aligned with requests')
            next_pending = []
            for triple, row in zip(pending, rows):
                if not isinstance(row, dict):
                    raise ValueError('Invalid OSV result entry')
                refs = row.get('vulns') or []
                if not isinstance(refs, list):
                    raise ValueError('OSV vulnerability refs must be an array')
                for v in refs:
                    if not isinstance(v, dict) or not OSV_ID.fullmatch(str(v.get('id', ''))):
                        raise ValueError('Malformed OSV vulnerability reference')
                    states[triple]['vulns'][v['id']] = v.get('modified')
                token = row.get('next_page_token')
                if token:
                    if not isinstance(token, str) or len(token) > 5000 or token in states[triple]['seen']:
                        raise ValueError('Invalid or repeated OSV pagination token')
                    states[triple]['seen'].add(token)
                    states[triple]['token'] = token
                    next_pending.append(triple)
            pending = next_pending
        if pending:
            raise ValueError('OSV pagination safety cap reached; do not save incomplete data')

        records = {}
        for triple in triples:
            records[triple] = []
            for osv_id, modified in states[triple]['vulns'].items():
                full = self.get_record(osv_id, modified, session)
                records[triple].append(full)
        return records


def sync_osv(session, config=None, *, provider=None):
    settings = config or {}
    batch_size = max(1, min(100, int(settings.get('batch_size', 50))))
    max_batches = max(1, min(50, int(settings.get('max_batches_per_cycle', 4))))
    ttl = max(1, int(settings.get('cache_hours', 24)))
    triples = approved_unique_packages(session, batch_size * max_batches, ttl)
    api = provider or OsvBatchClient()
    count = 0
    for offset in range(0, len(triples), batch_size):
        chunk = triples[offset:offset + batch_size]
        complete = api.resolve(session, chunk)
        for eco, pkg, version in chunk:
            count += mark_query_evidence(session, ecosystem=eco, package_name=pkg,
                                         version=version, source_records=complete[(eco, pkg, version)])
        session.flush()
    return len(triples)


def _nvd_score(raw):
    metrics = raw.get('metrics')
    if not isinstance(metrics, dict):
        return None
    for group in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'):
        rows = metrics.get(group) or []
        if not isinstance(rows, list):
            continue
        # Prefer an authoritative primary source when available.
        for candidate in sorted((x for x in rows if isinstance(x, dict)),
                                key=lambda x: x.get('type') != 'Primary'):
            data = candidate.get('cvssData') or {}
            if isinstance(data, dict):
                score = valid_cvss(data.get('baseScore'))
                if score is not None:
                    return score
    return None


class NvdClient:
    def __init__(self, timeout=45, api_key=None):
        key = api_key if api_key is not None else os.environ.get('NVD_API_KEY')
        headers = {'User-Agent': 'AssetVulnMonitor/0.3',
                   'Accept': 'application/json'}
        if key:
            headers['apiKey'] = key
        self.client = ReadOnlyClient('https://services.nvd.nist.gov',
                                     timeout=timeout, headers=headers)
        self.pause = 1 if key else 6

    def page(self, start, end, index=0, size=300):
        if not 1 <= size <= 2000 or index < 0:
            raise ValueError('NVD pagination outside safe limits')
        data = self.client.get('/rest/json/cves/2.0', {
            'lastModStartDate': start, 'lastModEndDate': end,
            'startIndex': index, 'resultsPerPage': size})
        rows = _rows(data, 'vulnerabilities')
        total = data.get('totalResults')
        if not isinstance(total, int) or total < 0 or len(rows) > size:
            raise ValueError('Invalid NVD totals / page size')
        if int(data.get('startIndex', index)) != index:
            raise ValueError('NVD page index mismatch')
        if total > index and not rows:
            raise ValueError('NVD unexpected empty page')
        return rows, total


class EuvdClient:
    def __init__(self, timeout=40):
        self.client = ReadOnlyClient('https://euvdservices.enisa.europa.eu',
                                     timeout=timeout,
                                     headers={'User-Agent': 'AssetVulnMonitor/0.3',
                                              'Accept': 'application/json'})

    def page(self, start_day, end_day, page=0, size=100):
        if not 1 <= size <= 100 or page < 0:
            raise ValueError('Invalid EUVD page size/index')
        result = self.client.get('/api/vulnerabilities', {
            'fromDate': start_day, 'toDate': end_day,
            'page': page, 'size': size})
        rows = _rows(result, 'items')
        total = result.get('total')
        if not isinstance(total, int) or total < 0 or len(rows) > size:
            raise ValueError('Invalid EUVD totals / page size')
        if total > page * size and not rows:
            raise ValueError('EUVD unexpected empty page')
        return rows, total


def _new_window(state, kind, stamp):
    if state.get('start') and state.get('end'):
        return state
    if kind == 'nvd':
        previous = parse_time(state.get('last_complete'))
        begin = (previous - timedelta(hours=2)) if previous else stamp - timedelta(hours=48)
        return {'start': begin.isoformat(timespec='milliseconds'),
                'end': stamp.isoformat(timespec='milliseconds'), 'offset': 0,
                'last_complete': state.get('last_complete')}
    # EUVD dates filter on publication, not all modifications; 7-day initial
    # lookback and a 2-day overlap. Older edited EUVD records are not covered.
    previous = parse_time(state.get('last_complete'))
    begin = (previous - timedelta(days=2)) if previous else stamp - timedelta(days=7)
    return {'start': begin.date().isoformat(),
            'end': stamp.date().isoformat(), 'offset': 0,
            'last_complete': state.get('last_complete')}


def sync_nvd(session, config=None, *, provider=None, clock=None):
    cfg = config or {}
    client = provider or NvdClient()
    page_size = max(1, min(2000, int(cfg.get('page_size', 300))))
    budget = max(1, min(20, int(cfg.get('max_pages_per_cycle', 2))))
    cp = _checkpoint(session, 'nvd')
    state = _new_window(dict(cp.state or {}), 'nvd', clock or now())
    count = 0
    for i in range(budget):
        if i and provider is None:
            time.sleep(client.pause)
        rows, total = client.page(state['start'], state['end'], state['offset'], page_size)
        for item in rows:
            if not isinstance(item, dict) or not isinstance(item.get('cve'), dict):
                raise ValueError('Malformed NVD CVE row')
            raw = item['cve']
            ident = raw.get('id')
            if not isinstance(ident, str) or not CVE_ID.fullmatch(ident):
                raise ValueError('Malformed NVD CVE ID')
            note_advisory(session, source='nvd', source_id=ident, title=ident,
                          summary=next((x['value'] for x in raw.get('descriptions', [])
                                        if isinstance(x, dict) and x.get('lang') == 'en'
                                        and isinstance(x.get('value'), str)), None),
                          cvss=_nvd_score(raw), updated_at=parse_time(raw.get('lastModified')),
                          withdrawn=str(raw.get('vulnStatus', '')).lower() in ('rejected', 'withdrawn'),
                          raw={'status': raw.get('vulnStatus'),
                               'configurations_present': bool(raw.get('configurations')),
                               'published': raw.get('published')})
            count += 1
        state['offset'] += len(rows)
        if state['offset'] >= total:
            cp.state = {'last_complete': state['end']}
            cp.updated_at = now()
            break
        cp.state = dict(state)
        cp.updated_at = now()
    return count


def sync_euvd(session, config=None, *, provider=None, clock=None):
    cfg = config or {}
    client = provider or EuvdClient()
    size = max(1, min(100, int(cfg.get('page_size', 100))))
    budget = max(1, min(30, int(cfg.get('max_pages_per_cycle', 3))))
    cp = _checkpoint(session, 'euvd')
    state = _new_window(dict(cp.state or {}), 'euvd', clock or now())
    count = 0
    for _ in range(budget):
        rows, total = client.page(state['start'], state['end'], state['offset'], size)
        for item in rows:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                raise ValueError('Malformed EUVD record')
            aliases = item.get('aliases') or ''
            note_advisory(session, source='euvd', source_id=item['id'],
                          aliases=aliases, title=item['id'],
                          summary=item.get('description'), cvss=item.get('baseScore'),
                          updated_at=parse_time(item.get('dateUpdated')),
                          raw={'references': str(item.get('references') or '')[:3000],
                               'datePublished': item.get('datePublished'),
                               'baseScoreVersion': item.get('baseScoreVersion')})
            count += 1
        state['offset'] += 1
        if state['offset'] * size >= total:
            # Store the processed window boundary, not the wall clock after
            # a slow backlog. This prevents gaps if paging spans many cycles.
            cp.state = {'last_complete': state['end'] + 'T00:00:00+00:00'}
            cp.updated_at = now()
            break
        cp.state = dict(state)
        cp.updated_at = now()
    return count
