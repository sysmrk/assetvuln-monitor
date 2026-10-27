from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from avm.demo import inventory, vulnerabilities
from avm.models import Base, Asset, Installation, Finding, Software, Vulnerability
from avm.matching import is_affected
from avm.worker import upsert_inventory, upsert_vulnerabilities, recalculate


def test_full_demo_pipeline_is_idempotent():
    eng = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(eng)
    mapping = {('demo web framework','demo software foundation'):('pypi','demo-web-framework'),
               ('demo utility library','demo software foundation'):('npm','demo-util')}
    with Session(eng) as s:
        assert upsert_inventory(s, inventory(), mapping) == 10
        assert upsert_vulnerabilities(s, vulnerabilities()) == 3
        s.commit()
        assert recalculate(s) > 0
        s.commit()
        assert s.query(Asset).count() == 10
        assert s.query(Installation).count() == 40
        count = s.query(Finding).filter(Finding.active == True).count()
        assert count > 0
        # Resyncing identical data should not create duplicate rows or findings.
        upsert_inventory(s, inventory(), mapping)
        upsert_vulnerabilities(s, vulnerabilities())
        recalculate(s)
        s.commit()
        assert s.query(Finding).filter(Finding.active == True).count() == count
        assert s.query(Installation).count() == 40
        # Deleting an asset from source should deactivate, not destroy, history.
        upsert_inventory(s, inventory()[1:], mapping)
        recalculate(s)
        s.commit()
        first = s.scalars(select(Asset).where(Asset.source_id=='301')).one()
        assert first.active is False
        assert all(not i.active for i in s.query(Installation).filter_by(asset_id=first.id))
