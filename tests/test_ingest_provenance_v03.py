"""No unverified advisory threat signals in Live risk ranking."""
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from avm.models import Base, Vulnerability
from avm.worker import upsert_vulnerabilities
from avm.threat_intel import enrich_vulnerabilities


def test_live_advisory_keeps_unverified_kev_and_epss_out_of_ranking():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        assert upsert_vulnerabilities(session, [{
            'id': 'CVE-2026-12345', 'title': 'Unverified source claimed exploit',
            'kev': True, 'epss': 0.99, 'affected': [],
        }]) == 1
        session.flush()
        vuln = session.get(Vulnerability, 'CVE-2026-12345')
        assert vuln.kev is False
        assert vuln.kev_verified is False
        assert vuln.epss is None
        assert vuln.epss_asof is None

        catalog = {f'CVE-2026-{20000+n}': '' for n in range(100)}
        catalog[vuln.id] = 'Follow required vendor mitigation'
        enrich_vulnerabilities(session, kev_catalog=catalog, epss_values={vuln.id: .52})
        session.flush()
        assert vuln.kev_verified is True
        assert vuln.kev is True
        assert float(vuln.epss) == .52
        assert vuln.epss_asof is not None

        upsert_vulnerabilities(session, [{
            'id': 'CVE-2026-12345', 'title': 'Later incomplete advisory',
            'affected': [],
        }])
        session.flush()
        assert vuln.kev_verified is True
        assert float(vuln.epss) == .52
    engine.dispose()
