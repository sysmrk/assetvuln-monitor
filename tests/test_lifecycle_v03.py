import pytest
"""Safe finding transitions and risk ranking using an isolated SQLite database."""
from datetime import datetime, timezone
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import Session

from avm.lifecycle import recalculate_findings
from avm.models import (Base, AffectedPackage, Asset, Finding, FindingEvent,
                        Installation, RiskSnapshot, Software, Vulnerability)


def _seed(db):
    asset = Asset(source_id='301', hostname='SRV-TEST', active=True,
                  criticality='critical', internet_facing=True,
                  owner='Blue Team', business_service='Payment')
    software = Software(name='Example App', vendor='Example Vendor',
                        ecosystem='pypi', package_name='example-app')
    vuln = Vulnerability(id='CVE-2026-12345', title='Synthetic test record',
                         cvss=9.8, epss=.7, kev=True, synthetic=True,
                         kev_action='Follow vendor advisory')
    db.add_all([asset, software, vuln])
    db.flush()
    install = Installation(asset_id=asset.id, software_id=software.id,
                           version='1.2.0', active=True)
    db.add(install)
    db.add(AffectedPackage(vulnerability_id=vuln.id, ecosystem='pypi',
                           package_name='example-app',
                           affected_spec={'ranges': [{'type': 'SEMVER',
                               'events': [{'introduced': '0'}, {'fixed': '2.0.0'}]}]}))
    db.flush()
    return asset, install, vuln


def test_detection_evidence_risk_sla_history_and_idempotency():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        asset, inst, vuln = _seed(db)
        assert recalculate_findings(db, allow_disappearance=True) == 1
        db.commit()
        finding = db.scalar(select(Finding))
        assert finding.active
        assert finding.priority == 'P1'
        assert float(finding.risk_score) >= 75
        assert finding.evidence_packet['software_version'] == '1.2.0'
        assert finding.remediation['candidate_fixed_versions'] == ['2.0.0']
        assert finding.remediation['required_action_from_kev'] == 'Follow vendor advisory'
        assert finding.sla_due_at > finding.first_detected
        assert recalculate_findings(db, allow_disappearance=True) == 1
        db.commit()
        assert db.scalar(select(func.count()).select_from(FindingEvent)) == 1
        assert db.scalar(select(func.count()).select_from(RiskSnapshot)) == 1


def test_feed_only_refresh_cannot_mark_findings_resolved():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        asset, install, vuln = _seed(db)
        recalculate_findings(db, allow_disappearance=True)
        db.commit()
        installed = db.get(Installation, install.id)
        # Production installations are keyed by version, so a patched
        # version is a new row and the old installation becomes inactive.
        installed.active = False
        patched = Installation(asset_id=asset.id, software_id=installed.software_id,
                               version='2.0.0', active=True)
        db.add(patched)
        db.flush()
        # Threat-intel/CVE-only recomputation must not claim remediation.
        assert recalculate_findings(db, allow_disappearance=False) == 0
        db.commit()
        finding = db.scalar(select(Finding))
        assert finding.active
        assert finding.workflow_state == 'open'
        # The next explicitly completed inventory sync permits a
        # not_observed state, never automatic 'fixed' or 'resolved'.
        assert recalculate_findings(db, allow_disappearance=True) == 0
        db.commit()
        assert not finding.active
        assert finding.workflow_state == 'not_observed'
        assert 'not proof' in db.scalars(
            select(FindingEvent.reason).where(FindingEvent.action == 'not_observed')).one()
        # When the software becomes affected again, Reopened is audited.
        installed.active = True
        patched.active = False
        db.flush()
        assert recalculate_findings(db, allow_disappearance=True) == 1
        db.commit()
        assert finding.active and finding.workflow_state == 'open'
        actions = db.scalars(select(FindingEvent.action).order_by(FindingEvent.id)).all()
        assert actions == ['detected', 'not_observed', 'reopened']
    engine.dispose()



def test_custom_sla_targets_are_validated():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _seed(db)
        with pytest.raises(ValueError, match='requires exactly'):
            recalculate_findings(db, sla_days={'P1': 3})
        with pytest.raises(ValueError, match='1..3650'):
            recalculate_findings(db, sla_days={'P1': 0, 'P2': 10, 'P3': 20, 'P4': 90})
        custom = {'P1': 3, 'P2': 14, 'P3': 60, 'P4': 120}
        assert recalculate_findings(db, allow_disappearance=True, sla_days=custom) == 1
        db.flush()
        finding = db.scalar(select(Finding))
        assert 2 <= (finding.sla_due_at - finding.first_detected).days <= 3
    engine.dispose()
