"""Public threat enrichment remains GET-only and fails closed on invalid feeds."""
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
import pytest

from avm.models import Base, Vulnerability
from avm.threat_intel import PublicThreatIntel, enrich_vulnerabilities


def test_cisa_catalog_validation_and_fixed_https_origin():
    source = PublicThreatIntel()
    assert source.kev.base == 'https://www.cisa.gov'
    assert source.epss.base == 'https://api.first.org'
    assert not hasattr(source.kev, 'post')
    payload = {'vulnerabilities': [
        {'cveID': f'CVE-2025-{1000+n}', 'requiredAction': 'Update after vendor verification'}
        for n in range(101)]}
    requests = []
    def fake_get(path, params=None):
        requests.append((path, params))
        return payload
    source.kev.get = fake_get
    result = source.fetch_kev()
    assert len(result) == 101
    assert result['CVE-2025-1000'] == 'Update after vendor verification'
    assert requests[0][0].endswith('known_exploited_vulnerabilities.json')
    payload['vulnerabilities'].pop()
    for row in payload['vulnerabilities'][1:]:
        row['cveID'] = 'CVE-2025-1000'
    with pytest.raises(ValueError):
        source.fetch_kev()


def test_first_epss_batch_validation():
    source = PublicThreatIntel()
    requests = []
    def fake_get(path, params=None):
        assert path == '/data/v1/epss'
        requests.append(params['cve'])
        return {'data': [{'cve': c, 'epss': '0.782'} for c in params['cve'].split(',')]}
    source.epss.get = fake_get
    vals = source.fetch_epss(['CVE-2024-12345', 'CVE-2025-44444'])
    assert vals == {'CVE-2024-12345': .782, 'CVE-2025-44444': .782}
    assert len(requests) == 1
    source.epss.get = lambda path, params=None: {
        'data': [{'cve': 'CVE-2024-12345', 'epss': '-1'}]}
    with pytest.raises(ValueError):
        source.fetch_epss(['CVE-2024-12345'])


def test_atomic_merge_keeps_demo_and_missing_epss_safe():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        real = Vulnerability(id='CVE-2024-12345', synthetic=False,
                             kev=False, epss=None)
        demo = Vulnerability(id='CVE-DEMO-0001', synthetic=True, kev=True, epss=.52)
        session.add_all([real, demo])
        session.flush()
        catalog = {f'CVE-2025-{1000+n}': '' for n in range(100)}
        catalog[real.id] = 'Vendor mitigation needed'
        assert enrich_vulnerabilities(session, kev_catalog=catalog,
                                      epss_values={real.id: .81}) == 1
        session.commit()
        assert real.kev is True
        assert real.kev_verified is True
        assert float(real.epss) == .81
        assert real.kev_action == 'Vendor mitigation needed'
        assert demo.kev is True
        assert demo.kev_verified is False
        assert float(demo.epss) == .52
        assert real.intel_checked_at is not None
    engine.dispose()
