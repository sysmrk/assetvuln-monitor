"""Integration of v0.2 approved review state with actual worker inventory upsert."""
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from avm.models import Base, MappingReview, Software
from avm.mapping_review import approved_runtime_lookup, refresh_review_queue, review_decision
from avm.worker import upsert_inventory


CATALOG = [
    {'vendor': 'Acme Corp', 'name': 'Example Secure Client',
     'ecosystem': 'PyPI', 'package': 'example-secure-client'},
]


def test_pending_review_does_not_change_worker_software_identity():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    incoming = [
        ({
            'source_id': '100',
            'hostname': 'WORKSTATION-100',
            'fqdn': 'workstation-100.test.invalid',
            'ip_address': '192.0.2.10',
            'os_name': 'Test Linux',
            'os_version': '1',
            'domain': 'LAB',
            'agent_status': 'Installed Successfully'
        }, [{'name': 'Example Secure Clien',
             'vendor': 'Acme Corp', 'version': '1.0'}]),
    ]
    with Session(engine) as db:
        original = approved_runtime_lookup(db, CATALOG)
        assert upsert_inventory(db, incoming, original) == 1
        assert refresh_review_queue(db, CATALOG, min_similarity=0.8) == 1
        db.commit()
        software = db.scalar(select(Software))
        assert software.ecosystem is None and software.package_name is None
        review = db.scalar(select(MappingReview))
        assert review.status == 'pending'

        review_decision(db, review_id=review.id, action='approved',
                        actor='security_reviewer', operator_rows=CATALOG,
                        reason='Verified package identity in authoritative vendor documentation.')
        db.commit()

        # Approval is recorded separately: worker inventory is not silently
        # modified until a subsequent explicit successful inventory sync.
        db.refresh(software)
        assert software.ecosystem is None

        new_mapping = approved_runtime_lookup(db, CATALOG)
        assert ('example secure clien', 'acme corp') in new_mapping
        assert upsert_inventory(db, incoming, new_mapping) == 1
        db.commit()
        db.refresh(software)
        assert software.ecosystem == 'pypi'
        assert software.package_name == 'example-secure-client'
    engine.dispose()
