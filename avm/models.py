"""Application-owned database schema. Reporting roles only see dedicated views."""
from datetime import datetime, timezone
from sqlalchemy import (create_engine, Column, String, Integer, Boolean, DateTime,
                        ForeignKey, UniqueConstraint, CheckConstraint, Numeric, Float, Text, JSON, text)
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



class MappingReview(Base):
    """Proposed identity, never automatically trusted by CVE matching."""
    __tablename__ = 'mapping_reviews'
    id = Column(Integer, primary_key=True)
    vendor = Column(String(500), nullable=False)
    name = Column(String(500), nullable=False)
    normalized_vendor = Column(String(500), nullable=False, index=True)
    normalized_name = Column(String(500), nullable=False, index=True)
    ecosystem = Column(String(100), nullable=False)
    package_name = Column(String(500), nullable=False)
    similarity = Column(Float)
    origin = Column(String(20), nullable=False)
    proposed_by = Column(String(120), nullable=False)
    evidence = Column(JSON, nullable=False)
    status = Column(String(20), nullable=False, default='pending')
    created_at = Column(DateTime(timezone=True), nullable=False, default=now)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=now)
    reviewed_at = Column(DateTime(timezone=True))
    reviewed_by = Column(String(120))
    review_reason = Column(Text)
    __table_args__ = (
        UniqueConstraint('normalized_vendor', 'normalized_name', 'ecosystem',
                         'package_name', name='uq_mapping_review_identity'),
        CheckConstraint("status IN ('pending','approved','rejected')",
                        name='ck_mapping_review_status'),
        CheckConstraint("origin IN ('auto','manual')", name='ck_mapping_review_origin'),
    )


class MappingDecision(Base):
    """Application-level append-only audit of proposals and reviewer decisions."""
    __tablename__ = 'mapping_decisions'
    id = Column(Integer, primary_key=True)
    review_id = Column(Integer, ForeignKey('mapping_reviews.id'), nullable=False, index=True)
    action = Column(String(20), nullable=False)
    actor = Column(String(120), nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now)
    __table_args__ = (
        CheckConstraint("action IN ('proposed','approved','rejected')",
                        name='ck_mapping_decision_action'),
    )


class ApprovedSoftwareMapping(Base):
    """Only reviewed identities from here, plus approved YAML, may drive findings."""
    __tablename__ = 'approved_software_mappings'
    id = Column(Integer, primary_key=True)
    normalized_vendor = Column(String(500), nullable=False)
    normalized_name = Column(String(500), nullable=False)
    vendor = Column(String(500), nullable=False)
    name = Column(String(500), nullable=False)
    ecosystem = Column(String(100), nullable=False)
    package_name = Column(String(500), nullable=False)
    review_id = Column(Integer, ForeignKey('mapping_reviews.id'), nullable=False, unique=True)
    approved_by = Column(String(120), nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=False, default=now)
    __table_args__ = (UniqueConstraint('normalized_vendor', 'normalized_name',
                                       name='uq_approved_software_identity'),)


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
''',
'data_quality_overview': '''
 WITH active_products AS (
   SELECT DISTINCT s.id, s.ecosystem, s.package_name, s.vendor
   FROM software s JOIN installations i ON i.software_id=s.id
   JOIN assets a ON a.id=i.asset_id
   WHERE i.active AND a.active
 )
 SELECT count(*) AS active_products,
        count(*) FILTER (WHERE ecosystem IS NOT NULL AND package_name IS NOT NULL)
          AS approved_mapped_products,
        count(*) FILTER (WHERE ecosystem IS NULL OR package_name IS NULL)
          AS unmapped_products,
        coalesce(round(
          100.0 * count(*) FILTER (WHERE ecosystem IS NOT NULL AND package_name IS NOT NULL)
          / nullif(count(*), 0), 2), 0) AS mapping_coverage_pct,
        count(*) FILTER (WHERE lower(trim(vendor)) IN ('','unknown','n/a','none','null'))
          AS unknown_vendor_products,
        (SELECT count(*) FROM mapping_reviews WHERE status='pending') AS pending_reviews,
        (SELECT count(*) FROM mapping_reviews WHERE status='rejected') AS rejected_reviews,
        (SELECT count(*) FROM mapping_reviews WHERE status='approved') AS approved_reviews,
        (SELECT count(*) FROM installations i JOIN assets a ON a.id=i.asset_id
         WHERE i.active AND a.active
         AND lower(trim(i.version)) IN ('','unknown','n/a','none','null')) AS unknown_version_installations,
        (SELECT count(*) FROM installations i JOIN assets a ON a.id=i.asset_id
         WHERE i.active AND a.active) AS active_installations
 FROM active_products
''',
'data_quality_products': '''
 SELECT s.name AS software, s.vendor, s.ecosystem, s.package_name,
        CASE WHEN s.ecosystem IS NOT NULL AND s.package_name IS NOT NULL
             THEN 'approved_mapping' ELSE 'unmapped' END AS mapping_status,
        count(DISTINCT i.asset_id) AS active_asset_count,
        count(*) AS active_installation_rows,
        count(*) FILTER (WHERE lower(trim(i.version)) IN
          ('','unknown','n/a','none','null')) AS unknown_version_installations,
        EXISTS (SELECT 1 FROM affected_packages p
                WHERE lower(p.ecosystem)=lower(s.ecosystem)
                AND lower(p.package_name)=lower(s.package_name))
          AS has_ingested_advisory_records
 FROM software s JOIN installations i ON i.software_id=s.id
 JOIN assets a ON a.id=i.asset_id
 WHERE i.active AND a.active
 GROUP BY s.id
''',
'data_quality_by_vendor': '''
 SELECT s.vendor,
        count(DISTINCT s.id) AS active_products,
        count(DISTINCT s.id) FILTER (WHERE s.ecosystem IS NOT NULL AND s.package_name IS NOT NULL)
          AS mapped_products,
        count(DISTINCT s.id) FILTER (WHERE s.ecosystem IS NULL OR s.package_name IS NULL)
          AS unmapped_products
 FROM software s JOIN installations i ON i.software_id=s.id
 JOIN assets a ON a.id=i.asset_id WHERE i.active AND a.active
 GROUP BY s.vendor
''',
'data_quality_by_os': '''
 SELECT a.os_name,
        count(DISTINCT s.id) AS active_products,
        count(DISTINCT s.id) FILTER (WHERE s.ecosystem IS NOT NULL AND s.package_name IS NOT NULL)
          AS mapped_products,
        count(DISTINCT s.id) FILTER (WHERE s.ecosystem IS NULL OR s.package_name IS NULL)
          AS unmapped_products
 FROM assets a JOIN installations i ON i.asset_id=a.id
 JOIN software s ON s.id=i.software_id WHERE a.active AND i.active
 GROUP BY a.os_name
''',
'data_quality_by_domain': '''
 SELECT a.domain,
        count(DISTINCT s.id) AS active_products,
        count(DISTINCT s.id) FILTER (WHERE s.ecosystem IS NOT NULL AND s.package_name IS NOT NULL)
          AS mapped_products,
        count(DISTINCT s.id) FILTER (WHERE s.ecosystem IS NULL OR s.package_name IS NULL)
          AS unmapped_products
 FROM assets a JOIN installations i ON i.asset_id=a.id
 JOIN software s ON s.id=i.software_id WHERE a.active AND i.active
 GROUP BY a.domain
''',
'mapping_review_queue': '''
 SELECT id AS review_id, vendor, name AS software, ecosystem,
        package_name, similarity, origin, proposed_by, status,
        created_at, last_seen, reviewed_at, reviewed_by, review_reason
 FROM mapping_reviews
''',
'mapping_review_audit': '''
 SELECT d.id AS event_id, d.review_id, d.action, d.actor, d.reason,
        d.created_at, r.vendor, r.name AS software, r.ecosystem, r.package_name
 FROM mapping_decisions d JOIN mapping_reviews r ON r.id=d.review_id
''',
'data_quality_sync_freshness': '''
 SELECT source, max(finished_at) FILTER (WHERE success) AS last_success_at,
        max(finished_at) FILTER (WHERE success = false) AS last_failed_at,
        count(*) FILTER (WHERE success) AS successful_runs,
        count(*) FILTER (WHERE success = false) AS failed_runs
 FROM sync_runs GROUP BY source
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
