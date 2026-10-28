"""Offline provider integration tests: no actual public API calls."""
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import pytest

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from avm.models import Base, FeedCheckpoint, Vulnerability, AdvisoryObservation
from avm.source_collectors import (OsvBatchClient, NvdClient, EuvdClient,
                                   sync_nvd, sync_euvd, _nvd_score)
from avm.epss_csv import sync_epss_csv


def _db():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    return engine


def test_osv_pagination_per_query_and_batch_order_are_complete():
    client = OsvBatchClient()
    calls = []
    def fake_post(queries):
        calls.append(queries)
        if len(calls) == 1:
            assert len(queries) == 2
            assert not any('page_token' in q for q in queries)
            return {'results':[
                {'vulns':[{'id':'GHSA-aaaa-bbbb-cccc','modified':'2026-10-20'}],
                 'next_page_token':'next-a'},
                {'vulns':[]}
            ]}
        assert len(queries) == 1
        assert queries[0]['page_token'] == 'next-a'
        return {'results':[{'vulns':[
            {'id':'GHSA-dddd-eeee-ffff', 'modified':'2026-10-21'}]}]}
    client._post = fake_post
    def fake_detail(osv_id, modified, session):
        return {'id':osv_id, 'affected':[], 'modified':modified}
    client.get_record = fake_detail
    triples = [('PyPI','testpkg','1.0'),('npm','other','2.0')]
    engine = _db()
    with Session(engine) as db:
        result = client.resolve(db, triples)
    assert [r['id'] for r in result[triples[0]]] == [
        'GHSA-aaaa-bbbb-cccc', 'GHSA-dddd-eeee-ffff']
    assert result[triples[1]] == []
    engine.dispose()


def test_osv_response_incomplete_or_cyclic_fails_closed():
    client = OsvBatchClient()
    triples = [('pypi','pkg','1.0')]
    engine = _db()
    with Session(engine) as db:
        client._post = lambda queries: {'results':[]}
        with pytest.raises(ValueError, match='aligned'):
            client.resolve(db, triples)
        client._post = lambda queries: {'results':[{
            'next_page_token':'cycle', 'vulns':[]}]}
        with pytest.raises(ValueError, match='repeated'):
            client.resolve(db, triples)
    engine.dispose()


class NvdFake:
    def __init__(self):
        self.requests = []
    def page(self, start, end, index, size):
        self.requests.append((start, end, index, size))
        if index == 0:
            return [{'cve': {'id':'CVE-2026-22222',
                             'vulnStatus':'Analyzed',
                             'metrics':{'cvssMetricV31':[{
                                 'type':'Primary',
                                 'cvssData':{'baseScore':9.8}}]},
                             'lastModified':'2026-10-20T00:00:00Z'}}], 2
        return [{'cve': {'id':'CVE-2026-33333',
                         'vulnStatus':'Analyzed', 'metrics':{}}}], 2


def test_nvd_page_checkpoint_and_authoritative_cvss():
    engine = _db()
    now = datetime(2026, 10, 28, tzinfo=timezone.utc)
    fake = NvdFake()
    with Session(engine) as db:
        assert sync_nvd(db, {'page_size':1,'max_pages_per_cycle':1},
                        provider=fake, clock=now) == 1
        db.commit()
        cp = db.get(FeedCheckpoint, 'nvd')
        assert cp.state['offset'] == 1
        first_window = (cp.state['start'], cp.state['end'])
        assert sync_nvd(db, {'page_size':1,'max_pages_per_cycle':1},
                        provider=fake, clock=now + timedelta(minutes=1)) == 1
        db.commit()
        assert db.get(FeedCheckpoint, 'nvd').state.get('offset') is None
        assert fake.requests[1][:2] == first_window
        assert float(db.get(Vulnerability, 'CVE-2026-22222').cvss) == 9.8
        assert db.get(Vulnerability, 'CVE-2026-22222').cvss_source == 'nvd'
        assert db.get(Vulnerability, 'CVE-2026-33333').cvss is None
    engine.dispose()


class EuvdFake:
    def __init__(self):
        self.calls = []
    def page(self, start, end, page, size):
        self.calls.append((start, end, page))
        return [{'id':'EUVD-2026-12345', 'aliases':'CVE-2026-22222\nGHSA-aaaa-bbbb-cccc',
                 'description':'Example EUVD advisory', 'baseScore':7.4}], 1


def test_euvd_aliases_merge_into_single_cve_and_do_not_erase_nvd_cvss():
    engine = _db()
    with Session(engine) as db:
        db.add(Vulnerability(id='CVE-2026-22222', cvss=9.8, cvss_source='nvd'))
        db.flush()
        assert sync_euvd(db, provider=EuvdFake()) == 1
        db.flush()
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        obs = db.scalar(select(AdvisoryObservation))
        assert obs.source == 'euvd' and obs.source_id == 'EUVD-2026-12345'
        assert obs.vulnerability_id == 'CVE-2026-22222'
        assert float(db.get(Vulnerability, obs.vulnerability_id).cvss) == 9.8
    engine.dispose()


class EpssFake:
    def __init__(self, broken=False):
        self.broken = broken
    def rows(self):
        yield 'CVE-2026-22222', .6, .98
        if self.broken:
            raise ValueError('download truncated')
        yield 'CVE-2026-33333', .2, .65


def test_first_csv_atomic_on_failed_stream():
    engine = _db()
    with Session(engine) as db:
        db.add(Vulnerability(id='CVE-2026-22222', epss=.1, synthetic=False))
        db.flush()
        with pytest.raises(ValueError, match='truncated'):
            sync_epss_csv(db, provider=EpssFake(broken=True), min_rows=2)
        assert float(db.get(Vulnerability,'CVE-2026-22222').epss) == .1
        assert sync_epss_csv(db, provider=EpssFake(), min_rows=2) == 1
        db.flush()
        v = db.get(Vulnerability,'CVE-2026-22222')
        assert float(v.epss) == .6 and float(v.epss_percentile) == .98
        assert v.epss_asof is not None
    engine.dispose()



def test_euvd_checkpoint_does_not_skip_dates_after_slow_backlog():
    engine = _db()
    class SlowProvider:
        def page(self, start, end, page, size):
            return ([{'id':f'EUVD-2026-1000{page}',
                      'aliases':'CVE-2026-22222'}], 2)
    first = datetime(2026, 10, 28, tzinfo=timezone.utc)
    later = datetime(2026, 11, 10, tzinfo=timezone.utc)
    with Session(engine) as db:
        assert sync_euvd(db, {'page_size':1,'max_pages_per_cycle':1},
                         provider=SlowProvider(), clock=first) == 1
        db.commit()
        checkpoint = db.get(FeedCheckpoint,'euvd')
        assert checkpoint.state['start'] == '2026-10-21'
        assert checkpoint.state['end'] == '2026-10-28'
        assert sync_euvd(db, {'page_size':1,'max_pages_per_cycle':1},
                         provider=SlowProvider(), clock=later) == 1
        db.commit()
        assert checkpoint.state['last_complete'].startswith('2026-10-28')
        # A new polling window starts from the processed date, not Nov 10.
        assert sync_euvd(db, {'page_size':1,'max_pages_per_cycle':1},
                         provider=SlowProvider(), clock=later) == 1
        assert checkpoint.state['start'] == '2026-10-26'
    engine.dispose()
