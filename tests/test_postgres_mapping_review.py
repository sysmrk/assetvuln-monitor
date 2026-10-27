"""Opt-in PostgreSQL integration: v0.2 schema, reporting grants, review decisions.

Runs only when AVM_TEST_POSTGRES_URL is provided. Never use a production URL.
CI provisions a temporary PostgreSQL database with throwaway credentials.
"""
import os

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from avm.mapping_review import propose_manual, review_decision
from avm.models import (Asset, Base, Installation, Software, MappingReview,
                        MappingDecision, initialize)


URL = os.environ.get('AVM_TEST_POSTGRES_URL')


@pytest.mark.skipif(not URL, reason='Temporary CI PostgreSQL is not configured')
def test_postgres_review_schema_reporting_views_and_reader_permissions():
    # Guard against accidental execution against a real database.
    if not URL or not any(value in URL for value in ('@127.0.0.1:', '@localhost:')):
        pytest.fail('Integration test requires loopback-only, throwaway PostgreSQL URL')

    engine = create_engine(URL)
    try:
        initialize(engine)
        with Session(engine) as session:
            asset = Asset(source_id='CI-100', hostname='CI-TEST-100', active=True)
            product = Software(name='Example Client', vendor='Example Vendor',
                               ecosystem=None, package_name=None)
            session.add_all([asset, product])
            session.flush()
            session.add(Installation(asset_id=asset.id, software_id=product.id,
                                     version='unknown', active=True))
            item, created = propose_manual(
                session, vendor='Example Vendor', name='Example Client',
                ecosystem='PyPI', package='example-client',
                actor='ci_proposer', evidence='Synthetic CI evidence for candidate review validation.')
            assert created
            session.commit()

            review_decision(
                session, review_id=item.id, action='approved',
                actor='ci_reviewer', reason='Synthetic CI second-party decision for schema tests.')
            session.commit()
            assert session.scalar(select(MappingReview.status).where(MappingReview.id == item.id)) == 'approved'
            assert len(session.scalars(select(MappingDecision)).all()) == 2

        with engine.connect() as conn:
            overview = conn.execute(text('SELECT * FROM reporting.data_quality_overview')).mappings().one()
            assert overview['active_products'] == 1
            assert overview['unmapped_products'] == 1
            assert overview['pending_reviews'] == 0
            assert overview['approved_reviews'] == 1
            assert overview['unknown_version_installations'] == 1
            assert overview['mapping_coverage_pct'] == 0
            for name in ('data_quality_products', 'data_quality_by_vendor',
                         'data_quality_by_os', 'data_quality_by_domain',
                         'mapping_review_queue', 'mapping_review_audit',
                         'data_quality_sync_freshness'):
                conn.execute(text(f'SELECT * FROM reporting.{name} LIMIT 1')).all()

        # Verify that Metabase's reader gets only the reporting view, not base table access.
        reader = create_engine(
            'postgresql+psycopg://avm_reader:ci_reader_local_only@127.0.0.1:5432/avm')
        try:
            with reader.connect() as conn:
                assert conn.execute(text('SELECT approved_reviews FROM reporting.data_quality_overview')).scalar() == 1
            with reader.connect() as conn:
                from sqlalchemy.exc import DBAPIError
                with pytest.raises(DBAPIError):
                    conn.execute(text('INSERT INTO public.mapping_reviews (id) VALUES (-1)'))
        finally:
            reader.dispose()
    finally:
        engine.dispose()
