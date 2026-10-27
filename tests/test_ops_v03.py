import json
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from avm.models import (Base, Asset, Finding, FindingEvent, Installation,
                        Software, Vulnerability)
from avm import ops


def test_simulation_and_accepted_risk_are_explicit(tmp_path, monkeypatch, capsys):
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    with maker() as db:
        asset = Asset(source_id='1', hostname='test-asset', active=True)
        product = Software(name='Demo', vendor='Demo')
        cve = Vulnerability(id='CVE-DEMO-0001', synthetic=True, kev=True)
        db.add_all([asset, product, cve])
        db.flush()
        install = Installation(asset_id=asset.id, software_id=product.id,
                               version='1.0', active=True)
        db.add(install)
        db.flush()
        finding = Finding(installation_id=install.id, vulnerability_id=cve.id,
                          confidence='structured', evidence='Example potential correlation',
                          risk_score=80, priority='P1',
                          workflow_state='open', active=True)
        db.add(finding)
        db.commit()
        fid = finding.id
    monkeypatch.setattr(ops, 'session_factory', lambda: (engine, maker))
    assert ops.main(['simulate', '--top', '1']) == 0
    score = json.loads(capsys.readouterr().out)
    assert score['modeled_score_reduction_pct'] == 100
    assert ops.main(['simulate', '--kev']) == 0
    assert json.loads(capsys.readouterr().out)['simulated_removals'] == 1
    assert ops.main(['accept', '--finding-id', str(fid), '--actor', 'risk_owner',
                     '--reason', 'Approved temporary exception with risk mitigation.',
                     '--until', '2099-01-01']) == 2
    capsys.readouterr()
    from datetime import datetime, timedelta, timezone
    allowed = (datetime.now(timezone.utc).date() + timedelta(days=2)).isoformat()
    assert ops.main(['accept', '--finding-id', str(fid), '--actor', 'risk_owner',
                     '--reason', 'Documented temporary exception for a planned patch.',
                     '--until', allowed]) == 0
    capsys.readouterr()
    with maker() as db:
        assert db.get(Finding, fid).workflow_state == 'accepted'
    assert ops.main(['release', '--finding-id', str(fid), '--actor', 'security_lead',
                     '--reason', 'Patch implemented; exception withdrawn for validation.']) == 0
    with maker() as db:
        assert db.get(Finding, fid).workflow_state == 'open'
        assert [e.action for e in db.scalars(select(FindingEvent).order_by(FindingEvent.id))] == [
            'risk_accepted', 'acceptance_released']
    engine.dispose()
