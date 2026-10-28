"""V3 PostgreSQL integration against disposable GitHub Actions PostgreSQL only.

Requires AVM_TEST_POSTGRES_URL on loopback; never touches a real user database.
"""
import os
import pytest

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from avm.models import (Asset, Installation, Software, Vulnerability, AffectedPackage,
                        Finding, initialize)
from avm.lifecycle import recalculate_findings


URL = os.environ.get('AVM_TEST_POSTGRES_URL')


@pytest.mark.skipif(not URL, reason='Requires throwaway GitHub Actions PostgreSQL')
def test_v03_postgres_schema_and_risk_dashboard():
    if not any(s in URL for s in ('@127.0.0.1:', '@localhost:')):
        pytest.fail('Refusing non-loopback database for integration tests')
    engine = create_engine(URL)
    try:
        initialize(engine)
        inspector = inspect(engine)
        assert {'risk_score', 'priority', 'evidence_packet', 'workflow_state',
                'remediation', 'accepted_until', 'sla_due_at'}.issubset(
                    {c['name'] for c in inspector.get_columns('findings')})
        assert {'criticality', 'internet_facing', 'business_service', 'owner'}.issubset(
                    {c['name'] for c in inspector.get_columns('assets')})
        assert {'finding_events', 'risk_snapshots'}.issubset(set(inspector.get_table_names()))

        with Session(engine) as db:
            asset = Asset(source_id='V03-CI-500', hostname='V3-TEST',
                          criticality='high', internet_facing=True,
                          business_service='Test System', owner='CI Team', active=True)
            product = Software(vendor='Test Vendor', name='Test App',
                               ecosystem='pypi', package_name='v03-test-app')
            issue = Vulnerability(id='CVE-2026-55555', synthetic=True, cvss=9.1,
                                  epss=.3, kev=True)
            db.add_all([asset, product, issue])
            db.flush()
            db.add(Installation(asset_id=asset.id, software_id=product.id,
                                version='1.0', active=True))
            db.add(AffectedPackage(
                vulnerability_id=issue.id, ecosystem='pypi',
                package_name='v03-test-app', affected_spec={
                    'ranges': [{'type':'SEMVER', 'events':[
                        {'introduced':'0'}, {'fixed':'2.0'}]}]}))
            db.flush()
            assert recalculate_findings(db, allow_disappearance=True) >= 1
            db.commit()

        with engine.connect() as conn:
            assert conn.execute(text('SELECT active_findings FROM reporting.risk_overview')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.risk_queue')).scalar() >= 1
            assert conn.execute(text("SELECT count(*) FROM reporting.risk_queue WHERE kev AND cve_id='CVE-2026-55555'")).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.finding_evidence')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.risk_trend')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.risk_by_owner')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.risk_by_service')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.source_advisories')).scalar() >= 0
            assert conn.execute(text('SELECT count(*) FROM reporting.source_evidence')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.finding_source_details')).scalar() >= 1
            assert conn.execute(text('SELECT count(*) FROM reporting.source_sync_health')).scalar() >= 0
            assert conn.execute(text('SELECT count(*) FROM reporting.source_cursor_status')).scalar() >= 0
            assert conn.execute(text('SELECT count(*) FROM reporting.osv_cache_coverage')).scalar() == 1
            assert conn.execute(text('SELECT count(*) FROM reporting.source_retractions')).scalar() >= 0
            assert conn.execute(text('SELECT count(*) FROM reporting.source_conflicts')).scalar() >= 0
            assert conn.execute(text("SELECT has_table_privilege('avm_reader','public.finding_events','INSERT')")).scalar() is False
        reader = create_engine('postgresql+psycopg://avm_reader:ci_reader_local_only@127.0.0.1:5432/avm')
        try:
            with reader.connect() as conn:
                assert conn.execute(text('SELECT count(*) FROM reporting.risk_queue')).scalar() >= 1
        finally:
            reader.dispose()
    finally:
        engine.dispose()
