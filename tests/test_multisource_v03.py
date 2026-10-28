"""Multi-source source-of-truth behavior, deduplication, withdrawal safety."""
from datetime import datetime, timezone
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from avm.models import (Base, Asset, Software, Installation, AffectedPackage, Finding,
                        AdvisoryObservation, OsvPackageCheck, FindingEvent, Vulnerability)
from avm.source_engine import (ids_from_aliases, canonical_id, note_advisory,
                               mark_query_evidence)
from avm.source_collectors import approved_unique_packages, sync_osv
from avm.lifecycle import recalculate_findings
from avm.worker import upsert_vulnerabilities


def _setup(db):
    assets = [Asset(source_id=str(i), hostname='test'+str(i), active=True)
              for i in (100, 101)]
    soft = Software(name='Example Package', vendor='Example',
                    ecosystem='pypi', package_name='example-package')
    db.add_all(assets + [soft])
    db.flush()
    for asset in assets:
        db.add(Installation(asset_id=asset.id, software_id=soft.id,
                            version='1.0.0', active=True))
    db.flush()


def _osv_record():
    return {'id':'GHSA-aaaa-bbbb-cccc', 'aliases':['CVE-2026-32100'],
            'summary':'Test package advisory', 'modified':'2026-10-25T00:00:00Z',
            'affected':[{'package':{'ecosystem':'PyPI', 'name':'example-package'},
                         'ranges':[{'type':'SEMVER','events':[{'introduced':'0'},
                                                           {'fixed':'1.5.0'}]}]}]}


def test_aliases_are_not_guessed_or_inaccurately_merged():
    assert ids_from_aliases('GHSA-aaaa-bbbb-cccc CVE-2026-32100') == ['CVE-2026-32100']
    assert canonical_id('GHSA-aaaa-bbbb-cccc', ['CVE-2026-32100']) == 'CVE-2026-32100'
    assert canonical_id('GHSA-aaaa-bbbb-cccc',
                        ['CVE-2026-32100','CVE-2026-32101']) == 'GHSA-aaaa-bbbb-cccc'


def test_osv_is_single_query_for_many_assets_and_one_finding_per_install():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _setup(db)
        assert approved_unique_packages(db) == [('pypi', 'example-package', '1.0.0')]
        class Provider:
            def __init__(self):
                self.calls = []
            def resolve(self, session, triples):
                self.calls.append(triples)
                return {triple: [_osv_record()] for triple in triples}
        provider = Provider()
        assert sync_osv(db, provider=provider) == 1
        assert len(provider.calls) == 1
        db.flush()
        assert db.scalar(select(func.count()).select_from(OsvPackageCheck)) == 1
        assert db.scalar(select(func.count()).select_from(AdvisoryObservation)) == 1
        assert recalculate_findings(db, allow_disappearance=True) == 2
        db.commit()
        findings = db.scalars(select(Finding)).all()
        assert len(findings) == 2
        assert all(f.vulnerability_id == 'CVE-2026-32100' for f in findings)
        assert all(f.evidence_packet['reporting_sources'] == ['osv'] for f in findings)
        assert all(f.remediation['candidate_fixed_versions'] == ['1.5.0']
                   for f in findings)
        assert approved_unique_packages(db) == []

        # Same CVE from cve.now adds a second evidence source without
        # creating a duplicate Finding.
        upsert_vulnerabilities(db, [{
            'id': 'CVE-2026-32100', 'title': 'Same example advisory',
            'affected': [{'package':{'ecosystem':'PyPI', 'name':'example-package'},
                          'ranges':[{'type':'SEMVER', 'events':[
                              {'introduced':'0'}, {'fixed':'1.5.0'}]}]}]
        }])
        assert recalculate_findings(db, allow_disappearance=True) == 2
        db.commit()
        assert db.scalar(select(func.count()).select_from(Finding)) == 2
        assert all(f.evidence_packet['reporting_sources'] == ['cve_now','osv']
                   for f in findings)

        # Source-specific refresh must not delete another source's evidence.
        assert len(db.scalars(select(AffectedPackage)).all()) == 2
        db.flush()
        assert db.scalar(select(func.count()).select_from(FindingEvent)) == 2
    engine.dispose()


def test_withdrawal_of_only_source_does_not_auto_close_installed_finding():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _setup(db)
        record = _osv_record()
        mark_query_evidence(db, ecosystem='pypi', package_name='example-package',
                            version='1.0.0', source_records=[record])
        recalculate_findings(db, allow_disappearance=True)
        db.commit()
        mark_query_evidence(db, ecosystem='pypi', package_name='example-package',
                            version='1.0.0', source_records=[])
        assert recalculate_findings(db, allow_disappearance=True) == 0
        db.commit()
        rows = db.scalars(select(Finding)).all()
        assert len(rows) == 2
        assert all(f.active for f in rows)
        assert all(f.workflow_state == 'needs_review' for f in rows)
        assert db.scalar(select(AffectedPackage.evidence_status)) == 'retracted'
    engine.dispose()


def test_authoritative_cvss_source_is_not_overwritten_by_cve_now():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        note_advisory(db, source='nvd', source_id='CVE-2026-32100',
                      cvss=9.8, title='Official NVD')
        upsert_vulnerabilities(db, [{'id':'CVE-2026-32100',
                                      'title':'Aggregator', 'cvss':4.2, 'affected':[]}])
        db.flush()
        v = db.get(Vulnerability, 'CVE-2026-32100')
        assert float(v.cvss) == 9.8 and v.cvss_source == 'nvd'
        assert {(o.source, o.source_id) for o in db.scalars(
            select(AdvisoryObservation)).all()} == {
            ('nvd','CVE-2026-32100'), ('cve_now','CVE-2026-32100')}
    engine.dispose()



def test_many_assets_still_generate_only_one_osv_tuple():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        product = Software(name='Example App', vendor='Example',
                           ecosystem='pypi', package_name='example-package')
        db.add(product)
        assets = [Asset(source_id=f'S{idx}', hostname=f'host-{idx}', active=True)
                  for idx in range(500)]
        db.add_all(assets)
        db.flush()
        db.add_all([
            Installation(asset_id=a.id, software_id=product.id,
                         version='1.2.3', active=True) for a in assets
        ])
        db.flush()
        assert len(approved_unique_packages(db)) == 1
    engine.dispose()
