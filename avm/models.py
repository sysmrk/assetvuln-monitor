"""Application-owned database schema. Reporting roles only see dedicated views."""
from datetime import datetime, timezone
from sqlalchemy import (create_engine, Column, String, Integer, Boolean, DateTime,
                        ForeignKey, UniqueConstraint, Numeric, Text, JSON, text)
from sqlalchemy.orm import declarative_base, sessionmaker
from avm.settings import database_url

Base = declarative_base()


def now():
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True)
    source_id = Column(String(128), unique=True, nullable=False, index=True)
    hostname = Column(String(256), nullable=False)
    fqdn = Column(String(512))
    ip_address = Column(String(80))
    os_name = Column(String(255))
    os_version = Column(String(120))
    domain = Column(String(200))
    agent_status = Column(String(100))
    last_seen = Column(DateTime(timezone=True), nullable=False, default=now)
    active = Column(Boolean, default=True, nullable=False)


class Software(Base):
    __tablename__ = 'software'
    id = Column(Integer, primary_key=True)
    name = Column(String(500), nullable=False)
    vendor = Column(String(500), nullable=False, default='Unknown')
    ecosystem = Column(String(100))
    package_name = Column(String(500))
    __table_args__ = (UniqueConstraint('name', 'vendor', name='uq_software_name_vendor'),)


class Installation(Base):
    __tablename__ = 'installations'
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id'), nullable=False, index=True)
    software_id = Column(Integer, ForeignKey('software.id'), nullable=False, index=True)
    version = Column(String(150), nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False, default=now)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=now)
    active = Column(Boolean, default=True, nullable=False)
    __table_args__ = (UniqueConstraint('asset_id', 'software_id', 'version', name='uq_installation'),)


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    id = Column(String(100), primary_key=True)
    title = Column(Text)
    summary = Column(Text)
    severity = Column(String(20))
    cvss = Column(Numeric(4, 1))
    epss = Column(Numeric(8, 6))
    kev = Column(Boolean, nullable=False, default=False)
    published_at = Column(DateTime(timezone=True))
    modified_at = Column(DateTime(timezone=True))
    retrieved_at = Column(DateTime(timezone=True), default=now, nullable=False)
    synthetic = Column(Boolean, default=False, nullable=False)
    raw = Column(JSON)


class AffectedPackage(Base):
    __tablename__ = 'affected_packages'
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(String(100), ForeignKey('vulnerabilities.id'), nullable=False, index=True)
    ecosystem = Column(String(100), nullable=False)
    package_name = Column(String(500), nullable=False)
    affected_spec = Column(JSON, nullable=False)


class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    installation_id = Column(Integer, ForeignKey('installations.id'), nullable=False, index=True)
    vulnerability_id = Column(String(100), ForeignKey('vulnerabilities.id'), nullable=False, index=True)
    confidence = Column(String(50), nullable=False)
    evidence = Column(Text, nullable=False)
    first_detected = Column(DateTime(timezone=True), nullable=False, default=now)
    last_detected = Column(DateTime(timezone=True), nullable=False, default=now)
    active = Column(Boolean, nullable=False, default=True)
    alerted_at = Column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint('installation_id', 'vulnerability_id', name='uq_finding'),)


class SyncRun(Base):
    __tablename__ = 'sync_runs'
    id = Column(Integer, primary_key=True)
    source = Column(String(40), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=False, default=now)
    finished_at = Column(DateTime(timezone=True))
    success = Column(Boolean)
    record_count = Column(Integer, default=0)
    message = Column(Text)


def session_factory():
    engine = create_engine(database_url(), pool_pre_ping=True)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


# Only preapproved columns are exposed to Metabase. Do not GRANT public schema.
VIEWS = {
'overview_metrics': '''
 SELECT (SELECT count(*) FROM assets WHERE active) AS total_assets,
        (SELECT count(*) FROM installations WHERE active) AS active_installations,
        (SELECT count(*) FROM software) AS software_products,
        (SELECT count(DISTINCT i.asset_id) FROM findings f JOIN installations i ON i.id=f.installation_id WHERE f.active AND i.active) AS potentially_affected_assets,
        (SELECT count(*) FROM findings f JOIN installations i ON i.id=f.installation_id WHERE f.active AND i.active) AS active_matches,
        (SELECT count(*) FROM findings f JOIN installations i ON i.id=f.installation_id JOIN vulnerabilities v ON v.id=f.vulnerability_id WHERE f.active AND i.active AND v.severity='CRITICAL') AS critical_matches,
        (SELECT count(*) FROM software WHERE ecosystem IS NULL) AS unmapped_products
''',
'asset_inventory': '''
 SELECT a.source_id, a.hostname, a.fqdn, a.ip_address, a.os_name, a.os_version, a.domain,
        a.agent_status, a.last_seen, a.active,
        count(DISTINCT i.id) FILTER(WHERE i.active) AS software_installations,
        count(DISTINCT f.id) FILTER(WHERE f.active AND i.active) AS active_findings
 FROM assets a LEFT JOIN installations i ON i.asset_id=a.id
 LEFT JOIN findings f ON f.installation_id=i.id GROUP BY a.id
''',
'software_inventory': '''
 SELECT s.name AS software, s.vendor, i.version, s.ecosystem, s.package_name,
        count(DISTINCT i.asset_id) FILTER(WHERE i.active) AS asset_count,
        count(DISTINCT f.id) FILTER(WHERE f.active AND i.active) AS matched_findings
 FROM software s JOIN installations i ON i.software_id=s.id
 LEFT JOIN findings f ON f.installation_id=i.id
 GROUP BY s.id,i.version
''',
'asset_software': '''
 SELECT a.hostname, a.ip_address, a.os_name, s.name AS software, s.vendor, i.version,
        i.active, i.last_seen, s.ecosystem, s.package_name
 FROM installations i JOIN assets a ON a.id=i.asset_id JOIN software s ON s.id=i.software_id
''',
'vulnerability_findings': '''
 SELECT v.id AS vulnerability_id, v.title, v.severity, v.cvss, v.epss, v.kev,
        a.hostname, a.ip_address, a.os_name, s.name AS software, s.vendor, i.version,
        f.confidence, f.evidence, f.first_detected, f.last_detected, f.active, v.synthetic
 FROM findings f JOIN vulnerabilities v ON v.id=f.vulnerability_id
 JOIN installations i ON i.id=f.installation_id JOIN assets a ON a.id=i.asset_id
 JOIN software s ON s.id=i.software_id
''',
'vulnerability_catalog': '''
 SELECT v.id, v.title, v.severity, v.cvss, v.epss, v.kev, v.published_at, v.modified_at,
 v.synthetic, count(DISTINCT f.id) FILTER(WHERE f.active) AS active_matches
 FROM vulnerabilities v LEFT JOIN findings f ON f.vulnerability_id=v.id GROUP BY v.id
''',
'severity_distribution': '''
 SELECT COALESCE(v.severity,'UNKNOWN') AS severity, count(*) AS finding_count
 FROM findings f JOIN vulnerabilities v ON v.id=f.vulnerability_id
 JOIN installations i ON i.id=f.installation_id WHERE f.active AND i.active
 GROUP BY COALESCE(v.severity,'UNKNOWN')
''',
'top_risky_assets': '''
 SELECT a.hostname, a.ip_address, a.os_name,
 count(f.id) FILTER(WHERE f.active AND i.active) AS matched_findings,
 count(f.id) FILTER(WHERE f.active AND i.active AND v.severity='CRITICAL') AS critical_findings,
 count(f.id) FILTER(WHERE f.active AND i.active AND v.kev) AS kev_findings
 FROM assets a LEFT JOIN installations i ON i.asset_id=a.id
 LEFT JOIN findings f ON f.installation_id=i.id
 LEFT JOIN vulnerabilities v ON v.id=f.vulnerability_id WHERE a.active
 GROUP BY a.id
''',
'ingestion_health': '''
 SELECT source, started_at, finished_at, success, record_count, message
 FROM sync_runs
''',
'coverage': '''
 SELECT count(*) AS software_products,
 count(*) FILTER (WHERE ecosystem IS NOT NULL AND package_name IS NOT NULL) AS mapped_products,
 count(*) FILTER (WHERE ecosystem IS NULL OR package_name IS NULL) AS unmapped_products
 FROM software
''',
'detection_timeline': '''
 SELECT date_trunc('day',first_detected) AS detected_day, count(*) AS findings_created
 FROM findings GROUP BY 1
'''
}


def initialize(engine):
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text('CREATE SCHEMA IF NOT EXISTS reporting'))
        for name, query in VIEWS.items():
            conn.execute(text(f'CREATE OR REPLACE VIEW reporting.{name} AS {query}'))
        conn.execute(text('GRANT USAGE ON SCHEMA reporting TO avm_reader'))
        conn.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO avm_reader'))
        conn.execute(text('REVOKE ALL ON SCHEMA public FROM avm_reader'))
