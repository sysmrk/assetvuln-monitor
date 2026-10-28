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
    # Explicit (not guessed) organizational context.
    criticality = Column(String(12), nullable=False, default='unknown')
    internet_facing = Column(Boolean, nullable=True)
    business_service = Column(String(200), nullable=False, default='')
    owner = Column(String(200), nullable=False, default='')
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
    kev_verified = Column(Boolean, nullable=False, default=False)
    epss_asof = Column(DateTime(timezone=True))
    kev_action = Column(Text)
    intel_checked_at = Column(DateTime(timezone=True))
    published_at = Column(DateTime(timezone=True))
    modified_at = Column(DateTime(timezone=True))
    retrieved_at = Column(DateTime(timezone=True), default=now, nullable=False)
    synthetic = Column(Boolean, default=False, nullable=False)
    raw = Column(JSON)
    cvss_source = Column(String(24))
    epss_percentile = Column(Numeric(8, 6))
    epss_date = Column(String(10))


class AffectedPackage(Base):
    __tablename__ = 'affected_packages'
    id = Column(Integer, primary_key=True)
    vulnerability_id = Column(String(100), ForeignKey('vulnerabilities.id'), nullable=False, index=True)
    ecosystem = Column(String(100), nullable=False)
    package_name = Column(String(500), nullable=False)
    affected_spec = Column(JSON, nullable=False)
    # V3.1 explicit source provenance: legacy rows default to cve_now.
    source = Column(String(24), nullable=False, default='cve_now')
    source_id = Column(String(100))
    matched_version = Column(String(150))
    evidence_status = Column(String(20), nullable=False, default='current')


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
    # v0.3: ranking and evidence are explainable snapshots, not confirmed CVEs.
    risk_score = Column(Numeric(5, 2))
    priority = Column(String(3))
    risk_factors = Column(JSON)
    evidence_packet = Column(JSON)
    remediation = Column(JSON)
    workflow_state = Column(String(24), nullable=False, default='open')
    state_updated_at = Column(DateTime(timezone=True))
    accepted_until = Column(DateTime(timezone=True))
    accepted_by = Column(String(120))
    acceptance_reason = Column(Text)
    sla_due_at = Column(DateTime(timezone=True))
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





class AdvisoryObservation(Base):
    """Source-specific metadata, never directly treated as asset exposure."""
    __tablename__ = 'advisory_observations'
    id = Column(Integer, primary_key=True)
    source = Column(String(24), nullable=False)
    source_id = Column(String(100), nullable=False)
    vulnerability_id = Column(String(100), ForeignKey('vulnerabilities.id'), nullable=False, index=True)
    aliases = Column(JSON, nullable=False, default=list)
    original_source = Column(String(300))
    cvss = Column(Numeric(4, 1))
    status = Column(String(24), nullable=False, default='published')
    updated_at = Column(DateTime(timezone=True))
    fetched_at = Column(DateTime(timezone=True), nullable=False, default=now)
    raw = Column(JSON)
    __table_args__ = (UniqueConstraint('source', 'source_id', name='uq_advisory_source_identity'),)


class OsvPackageCheck(Base):
    """Durable per unique approved package/version query cache."""
    __tablename__ = 'osv_package_checks'
    id = Column(Integer, primary_key=True)
    ecosystem = Column(String(100), nullable=False)
    package_name = Column(String(500), nullable=False)
    version = Column(String(150), nullable=False)
    checked_at = Column(DateTime(timezone=True), nullable=False, default=now)
    source_ids = Column(JSON, nullable=False, default=list)
    __table_args__ = (UniqueConstraint('ecosystem', 'package_name', 'version',
                                      name='uq_osv_package_query'),)


class FeedCheckpoint(Base):
    """Only advance after successful, completely consumed source pages."""
    __tablename__ = 'feed_checkpoints'
    source = Column(String(24), primary_key=True)
    state = Column(JSON, nullable=False, default=dict)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=now)


class FindingEvent(Base):
    __tablename__ = 'finding_events'
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False, index=True)
    action = Column(String(30), nullable=False)
    actor = Column(String(120), nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now)


class RiskSnapshot(Base):
    __tablename__ = 'risk_snapshots'
    id = Column(Integer, primary_key=True)
    day = Column(String(10), nullable=False, unique=True)
    active_findings = Column(Integer, nullable=False)
    priority_points = Column(Numeric(14, 2), nullable=False)
    p1_findings = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=now)


# Idempotent, additive, PostgreSQL-only in-place upgrade for existing v0.2 databases.
# No dropping/re-writing or production data copies; SQLite unit tests use fresh schema.
V3_ADDITIVE_COLUMNS = {
    'assets': (
        "criticality varchar(12) NOT NULL DEFAULT 'unknown'",
        'internet_facing boolean',
        "business_service varchar(200) NOT NULL DEFAULT ''",
        "owner varchar(200) NOT NULL DEFAULT ''",
    ),
    'vulnerabilities': ('kev_verified boolean NOT NULL DEFAULT false', 'epss_asof timestamptz', 'kev_action text',
                        'intel_checked_at timestamptz', 'cvss_source varchar(24)',
                        'epss_percentile numeric(8,6)', 'epss_date varchar(10)'),
    'affected_packages': ("source varchar(24) NOT NULL DEFAULT 'cve_now'",
                          "source_id varchar(100)", "matched_version varchar(150)", "evidence_status varchar(20) NOT NULL DEFAULT 'current'"),
    'findings': ('risk_score numeric(5,2)', 'priority varchar(3)',
                 'risk_factors json', 'evidence_packet json', 'remediation json',
                 "workflow_state varchar(24) NOT NULL DEFAULT 'open'",
                 'state_updated_at timestamptz', 'accepted_until timestamptz',
                 'accepted_by varchar(120)', 'acceptance_reason text',
                 'sla_due_at timestamptz'),
}


def upgrade_v03(engine):
    if engine.dialect.name != 'postgresql':
        return
    with engine.begin() as conn:
        for table, columns in V3_ADDITIVE_COLUMNS.items():
            for definition in columns:
                # Table names/SQL definitions are static trusted literals above.
                conn.execute(text(f'ALTER TABLE public.{table} ADD COLUMN IF NOT EXISTS {definition}'))


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
,
'risk_overview': '''
 SELECT count(*) FILTER (WHERE f.active AND a.active) AS active_findings,
        count(*) FILTER (WHERE f.active AND a.active AND f.priority='P1') AS p1_findings,
        count(*) FILTER (WHERE f.active AND a.active AND (v.kev_verified OR (v.synthetic AND v.kev))) AS kev_findings,
        coalesce(sum(f.risk_score) FILTER (WHERE f.active AND a.active),0) AS priority_points,
        count(*) FILTER (WHERE f.active AND a.active AND f.workflow_state='accepted'
          AND f.accepted_until > now()) AS accepted_findings,
        count(*) FILTER (WHERE f.active AND a.active AND f.sla_due_at < now()
          AND NOT (f.workflow_state='accepted' AND f.accepted_until > now()))
          AS overdue_findings,
        count(*) FILTER (WHERE f.active AND a.active AND f.risk_score IS NULL)
          AS unscored_findings
 FROM findings f JOIN installations i ON i.id=f.installation_id
 JOIN assets a ON a.id=i.asset_id
 JOIN vulnerabilities v ON v.id=f.vulnerability_id
''',
'risk_queue': '''
 SELECT f.id AS finding_id, a.hostname, a.source_id, a.domain, a.os_name,
        a.business_service, a.owner, a.criticality, a.internet_facing,
        s.vendor, s.name AS software, i.version,
        v.id AS cve_id, v.cvss, v.epss, v.epss_asof, (v.kev_verified OR (v.synthetic AND v.kev)) AS kev, v.intel_checked_at,
        f.priority, f.risk_score, f.workflow_state, f.sla_due_at,
        f.first_detected, f.last_detected,
        (f.sla_due_at < now() AND NOT
          (f.workflow_state='accepted' AND f.accepted_until > now())) AS overdue,
        (f.workflow_state='accepted' AND f.accepted_until > now()) AS risk_accepted
 FROM findings f JOIN installations i ON i.id=f.installation_id
 JOIN assets a ON a.id=i.asset_id
 JOIN software s ON s.id=i.software_id
 JOIN vulnerabilities v ON v.id=f.vulnerability_id
 WHERE f.active AND i.active AND a.active
''',
'finding_evidence': '''
 SELECT f.id AS finding_id, v.id AS cve_id, a.hostname, s.vendor,
        s.name AS software, i.version, f.priority, f.risk_score,
        f.risk_factors, f.evidence_packet, f.remediation,
        f.confidence, f.workflow_state, f.last_detected
 FROM findings f JOIN installations i ON i.id=f.installation_id
 JOIN assets a ON a.id=i.asset_id
 JOIN software s ON s.id=i.software_id
 JOIN vulnerabilities v ON v.id=f.vulnerability_id
 WHERE f.active AND i.active AND a.active
''',
'finding_lifecycle': '''
 SELECT f.id AS finding_id, v.id AS cve_id, a.hostname, a.owner,
        f.active AS observed_in_last_complete_inventory,
        f.workflow_state, f.accepted_by, f.accepted_until,
        f.acceptance_reason, f.first_detected, f.last_detected,
        f.state_updated_at, f.sla_due_at, f.priority
 FROM findings f JOIN installations i ON i.id=f.installation_id
 JOIN assets a ON a.id=i.asset_id
 JOIN vulnerabilities v ON v.id=f.vulnerability_id
''',
'finding_event_history': '''
 SELECT e.id AS event_id, e.finding_id, e.action, e.actor, e.reason,
        e.created_at
 FROM finding_events e
''',
'risk_trend': '''
 SELECT day, active_findings, priority_points, p1_findings, created_at
 FROM risk_snapshots
''',
'risk_by_service': '''
 SELECT coalesce(nullif(btrim(business_service),''),'Unassigned') AS business_service,
        count(*) AS active_findings,
        coalesce(sum(risk_score),0) AS modeled_priority_points
 FROM reporting.risk_queue GROUP BY 1
''',
'risk_by_owner': '''
 SELECT coalesce(nullif(btrim(owner),''),'Unassigned') AS owner,
        count(*) AS active_findings,
        coalesce(sum(risk_score),0) AS modeled_priority_points
 FROM reporting.risk_queue GROUP BY 1
''',
'asset_context_quality': '''
 SELECT count(*) FILTER (WHERE active) AS active_assets,
        count(*) FILTER (WHERE active AND criticality='unknown') AS unknown_criticality,
        count(*) FILTER (WHERE active AND internet_facing IS NULL) AS unknown_exposure,
        count(*) FILTER (WHERE active AND owner='') AS unassigned_owner
 FROM assets
'''

,
'source_coverage': '''
 SELECT source, count(*) AS advisory_count,
        count(*) FILTER (WHERE status='withdrawn') AS withdrawn,
        count(*) FILTER (WHERE cvss IS NOT NULL) AS scored,
        max(fetched_at) AS last_fetched_at
 FROM advisory_observations GROUP BY source
''',
'source_advisories': '''
 SELECT o.source, o.source_id, o.vulnerability_id AS canonical_id,
        o.original_source, o.aliases, o.status, o.cvss AS source_cvss,
        o.updated_at, o.fetched_at, v.cvss AS selected_cvss,
        v.cvss_source AS selected_cvss_source
 FROM advisory_observations o JOIN vulnerabilities v ON v.id=o.vulnerability_id
''',
'source_evidence': '''
 SELECT p.vulnerability_id AS canonical_id, p.source, p.source_id,
        p.ecosystem, p.package_name, p.matched_version, p.evidence_status, p.affected_spec
 FROM affected_packages p
''',
'finding_source_details': '''
 SELECT f.id AS finding_id, f.vulnerability_id AS canonical_id,
        a.hostname, s.name AS software, i.version,
        f.active, f.workflow_state, f.priority, f.risk_score,
        coalesce(f.evidence_packet->'reporting_sources','[]'::json) AS reporting_sources,
        coalesce(json_array_length(f.evidence_packet->'reporting_sources'),0) AS reporting_path_count,
        f.evidence_packet, f.last_detected
 FROM findings f JOIN installations i ON i.id=f.installation_id
 JOIN assets a ON a.id=i.asset_id JOIN software s ON s.id=i.software_id
''',
'source_retractions': '''
 SELECT p.vulnerability_id AS canonical_id, p.source, p.source_id,
        p.ecosystem, p.package_name, p.matched_version,
        count(DISTINCT i.asset_id) AS affected_active_assets
 FROM affected_packages p
 JOIN software s ON lower(s.ecosystem)=p.ecosystem
                AND lower(s.package_name)=p.package_name
 JOIN installations i ON i.software_id=s.id AND i.version=p.matched_version
 JOIN assets a ON a.id=i.asset_id
 WHERE p.evidence_status='retracted' AND p.source='osv'
   AND i.active AND a.active
 GROUP BY p.vulnerability_id, p.source, p.source_id,
          p.ecosystem, p.package_name, p.matched_version
''',
'source_sync_health': '''
 SELECT source, max(finished_at) FILTER (WHERE success) AS last_success,
        max(finished_at) FILTER (WHERE NOT success) AS last_failure,
        count(*) FILTER (WHERE success) AS successes,
        count(*) FILTER (WHERE NOT success) AS failures
 FROM sync_runs
 WHERE source IN ('inventory','cve','osv','nvd','euvd','threat_intel','epss_csv')
 GROUP BY source
''',
'source_cursor_status': '''
 SELECT source, state->>'start' AS pending_window_start,
        state->>'end' AS pending_window_end,
        state->>'offset' AS next_page_or_offset,
        state->>'last_complete' AS last_complete_window_end,
        updated_at,
        (state ? 'start') AS has_pending_pages
 FROM feed_checkpoints
''',
'osv_cache_coverage': '''
 SELECT count(*) AS checked_unique_package_versions,
        count(*) FILTER (WHERE source_ids IS NOT NULL
           AND json_array_length(source_ids)>0) AS with_osv_advisories,
        max(checked_at) AS last_checked_at
 FROM osv_package_checks
'''

}


def initialize(engine):
    Base.metadata.create_all(engine)
    upgrade_v03(engine)
    with engine.begin() as conn:
        # These indexes protect deduplicated lookups on large inventories;
        # no new infrastructure or worker process is needed.
        if engine.dialect.name == 'postgresql':
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_avm_install_active_software_version '
                              'ON installations (software_id, version) WHERE active'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_avm_affected_active_sources '
                              'ON affected_packages (ecosystem, package_name, matched_version, source)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_avm_osv_cache_checked '
                              'ON osv_package_checks (checked_at)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_avm_observation_canonical '
                              'ON advisory_observations (vulnerability_id)'))
        conn.execute(text('CREATE SCHEMA IF NOT EXISTS reporting'))
        for name, query in VIEWS.items():
            conn.execute(text(f'CREATE OR REPLACE VIEW reporting.{name} AS {query}'))
        conn.execute(text('GRANT USAGE ON SCHEMA reporting TO avm_reader'))
        conn.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA reporting TO avm_reader'))
        conn.execute(text('REVOKE ALL ON SCHEMA public FROM avm_reader'))
