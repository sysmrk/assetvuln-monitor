"""Mapping review workflow is tested against an actual SQLAlchemy SQL database.

SQLite is used for unit tests; PostgreSQL locking/grants still need an integration test.
"""
import pytest

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from avm.mapping_review import (ReviewError, approved_runtime_lookup, propose_manual,
                                refresh_review_queue, review_decision)
from avm.models import (Base, ApprovedSoftwareMapping, Asset, Installation,
                        MappingDecision, MappingReview, Software)


CATALOG = [
    {'vendor': 'Acme Corp', 'name': 'Example Secure Client',
     'ecosystem': 'PyPI', 'package': 'example-secure-client'},
]


@pytest.fixture
def db():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def test_manual_proposal_requires_independent_approval_and_audit(db):
    review, created = propose_manual(
        db, vendor='ACME CORP', name='Example Client Variant',
        ecosystem='PyPI', package='example-client-variant',
        actor='engineer_a', evidence='Confirmed vendor and product identifier in advisory.')
    assert created and review.status == 'pending'
    db.flush()
    assert approved_runtime_lookup(db, []) == {}
    with pytest.raises(ReviewError, match='different'):
        review_decision(db, review_id=review.id, action='approved', actor='engineer_a',
                        reason='Verified package and affected versions against advisory.')
    assert approved_runtime_lookup(db, []) == {}

    approved = review_decision(db, review_id=review.id, action='approved', actor='engineer_b',
                               reason='Validated package identity against vendor advisory.')
    db.commit()
    assert approved.status == 'approved'
    assert approved_runtime_lookup(db, [])[('example client variant', 'acme corp')] == (
        'pypi', 'example-client-variant')
    actions = db.scalars(select(MappingDecision).where(
        MappingDecision.review_id == review.id).order_by(MappingDecision.id)).all()
    assert [event.action for event in actions] == ['proposed', 'approved']
    assert actions[1].actor == 'engineer_b'
    assert db.scalar(select(func.count()).select_from(ApprovedSoftwareMapping)) == 1
    with pytest.raises(ReviewError, match='pending'):
        review_decision(db, review_id=review.id, action='rejected', actor='engineer_c',
                        reason='Subsequently found additional issue in identity mapping.')


def test_rejected_never_approved_and_no_reproposal(db):
    review, _ = propose_manual(db, vendor='Acme Corp', name='Variant A',
                               ecosystem='npm', package='variant-a',
                               actor='analyst_a',
                               evidence='Documentation shows a candidate identity only.')
    review_decision(db, review_id=review.id, action='rejected', actor='analyst_b',
                    reason='Rejected because advisory is for a different product.')
    db.commit()
    assert approved_runtime_lookup(db, []) == {}
    repeated, created = propose_manual(db, vendor='Acme Corp', name='Variant A',
                                       ecosystem='npm', package='variant-a',
                                       actor='analyst_c',
                                       evidence='New investigation still unverified identity.')
    assert not created and repeated.status == 'rejected'
    assert db.scalar(select(func.count()).select_from(MappingDecision)) == 2


def test_automatic_candidate_only_pending_until_human_review(db):
    asset = Asset(source_id='100', hostname='WS-TEST', active=True)
    software = Software(vendor='Acme Corp', name='Example Secure Clien')
    db.add_all([asset, software])
    db.flush()
    db.add(Installation(asset_id=asset.id, software_id=software.id,
                        version='1.0', active=True))
    db.flush()

    assert refresh_review_queue(db, CATALOG, min_similarity=.80) == 1
    assert refresh_review_queue(db, CATALOG, min_similarity=.80) == 0
    proposal = db.scalar(select(MappingReview))
    assert proposal.status == 'pending'
    assert proposal.origin == 'auto'
    assert 0.80 <= proposal.similarity <= 1.0
    assert ('example secure clien', 'acme corp') not in approved_runtime_lookup(db, CATALOG)
    review_decision(db, review_id=proposal.id, action='approved', actor='security_reviewer',
                    reason='Verified exact package identity using vendor advisory.',
                    operator_rows=CATALOG)
    db.commit()
    assert approved_runtime_lookup(db, CATALOG)[('example secure clien', 'acme corp')] == (
        'pypi', 'example-secure-client')


def test_automatic_queue_does_not_reopen_rejected_review(db):
    asset = Asset(source_id='101', hostname='WS-SECOND', active=True)
    software = Software(vendor='Acme Corp', name='Example Secure Clien')
    db.add_all([asset, software])
    db.flush()
    db.add(Installation(asset_id=asset.id, software_id=software.id,
                        version='2.0', active=True))
    db.flush()
    assert refresh_review_queue(db, CATALOG, min_similarity=.8) == 1
    item = db.scalar(select(MappingReview))
    review_decision(db, review_id=item.id, action='rejected', actor='security_reviewer',
                    reason='Similar name alone is insufficient as verified product identity.',
                    operator_rows=CATALOG)
    db.commit()
    assert refresh_review_queue(db, CATALOG, min_similarity=.8) == 0
    assert item.status == 'rejected'
    assert db.scalar(select(func.count()).select_from(MappingDecision)) == 2


def test_conflicting_approved_identity_is_fail_closed(db):
    row, _ = propose_manual(db, vendor='Acme Corp', name='Client Variant',
                            ecosystem='npm', package='client-variant',
                            actor='analyst_a',
                            evidence='Proposed vendor product identity requiring separate approval.')
    with pytest.raises(ReviewError, match='conflicts'):
        review_decision(
            db, review_id=row.id, action='approved', actor='analyst_b',
            reason='Verified identity after reviewing source package metadata.',
            operator_rows=[{'vendor': 'Acme Corp', 'name': 'CLIENT VARIANT',
                            'ecosystem': 'PyPI', 'package': 'another-product'}])
    assert approved_runtime_lookup(db, []) == {}


def test_invalid_reason_and_fields_rejected(db):
    with pytest.raises(ReviewError, match='12'):
        propose_manual(db, vendor='Acme', name='Client', ecosystem='npm',
                       package='client', actor='analyst_a', evidence='too short')
    with pytest.raises(ReviewError, match='vendor'):
        propose_manual(db, vendor='', name='Client', ecosystem='npm',
                       package='client', actor='analyst_a',
                       evidence='Valid documentation evidence for product.')


def test_review_tables_have_strict_unique_identity(db):
    review, _ = propose_manual(db, vendor='  Acme   Corp', name='Example Client',
                               ecosystem='PyPI', package='example-client',
                               actor='analyst_a',
                               evidence='Verification pending documented vendor scope.')
    again, created = propose_manual(db, vendor='acme corp', name='EXAMPLE CLIENT',
                                    ecosystem='pypi', package='EXAMPLE-CLIENT',
                                    actor='analyst_b',
                                    evidence='Second equivalent product identity proposal.')
    assert not created and again.id == review.id
    db.commit()
    assert db.scalar(select(func.count()).select_from(MappingReview)) == 1
