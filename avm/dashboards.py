"""Declarative report specification. Every query reads reporting views only."""

# (title, metabase display, SQL, width) per dashboard.
DASHBOARDS = {
    '01 · Security Command Center': [
        ('Managed Assets', 'scalar', 'SELECT total_assets FROM reporting.overview_metrics', 6),
        ('Software Installations', 'scalar', 'SELECT active_installations FROM reporting.overview_metrics', 6),
        ('Affected Assets', 'scalar', 'SELECT potentially_affected_assets FROM reporting.overview_metrics', 6),
        ('Critical Findings', 'scalar', 'SELECT critical_matches FROM reporting.overview_metrics', 6),
        ('Finding Severity', 'pie', 'SELECT severity, finding_count FROM reporting.severity_distribution ORDER BY finding_count DESC', 12),
        ('Potential Exposure by Host', 'bar', 'SELECT hostname, matched_findings FROM reporting.top_risky_assets ORDER BY matched_findings DESC LIMIT 12', 12),
        ('Prioritize Investigations', 'table', 'SELECT hostname, ip_address, os_name, matched_findings, critical_findings, kev_findings FROM reporting.top_risky_assets ORDER BY critical_findings DESC, kev_findings DESC, matched_findings DESC LIMIT 50', 24),
    ],
    '02 · Asset Explorer': [
        ('Total Assets', 'scalar', 'SELECT total_assets FROM reporting.overview_metrics', 6),
        ('Active Agents by Status', 'bar', 'SELECT agent_status, count(*) AS assets FROM reporting.asset_inventory WHERE active GROUP BY 1 ORDER BY 2 DESC', 18),
        ('Operating System Landscape', 'pie', 'SELECT os_name, count(*) AS assets FROM reporting.asset_inventory WHERE active GROUP BY 1 ORDER BY 2 DESC', 12),
        ('Domain Distribution', 'bar', 'SELECT domain, count(*) AS assets FROM reporting.asset_inventory WHERE active GROUP BY 1 ORDER BY 2 DESC', 12),
        ('Asset Inventory · Search and Export', 'table', 'SELECT hostname, ip_address, fqdn, os_name, os_version, domain, agent_status, software_installations, active_findings, last_seen FROM reporting.asset_inventory WHERE active ORDER BY active_findings DESC, hostname LIMIT 10000', 24),
    ],
    '03 · Software Catalog': [
        ('Discovered Products', 'scalar', 'SELECT software_products FROM reporting.overview_metrics', 6),
        ('Unmapped Products', 'scalar', 'SELECT unmapped_products FROM reporting.overview_metrics', 6),
        ('Most Widely Installed Products', 'bar', 'SELECT software, sum(asset_count) AS installations FROM reporting.software_inventory GROUP BY 1 ORDER BY installations DESC LIMIT 15', 12),
        ('Software Versions by Asset Count', 'table', 'SELECT software, vendor, version, ecosystem, package_name, asset_count, matched_findings FROM reporting.software_inventory ORDER BY asset_count DESC, software LIMIT 10000', 24),
        ('All Installed Software · Per Asset', 'table', 'SELECT hostname, ip_address, os_name, software, vendor, version, ecosystem, package_name, last_seen FROM reporting.asset_software WHERE active ORDER BY hostname, software LIMIT 20000', 24),
    ],
    '04 · Vulnerability Intelligence': [
        ('Active Matches', 'scalar', 'SELECT active_matches FROM reporting.overview_metrics', 6),
        ('Known Exploited Matches', 'scalar', 'SELECT count(*) FROM reporting.vulnerability_findings WHERE active AND kev', 6),
        ('CVEs Tracked', 'scalar', 'SELECT count(*) FROM reporting.vulnerability_catalog', 6),
        ('Vulnerability Severity', 'pie', 'SELECT severity, count(*) AS vulnerabilities FROM reporting.vulnerability_catalog GROUP BY 1 ORDER BY 2 DESC', 12),
        ('Latest Advisories', 'table', 'SELECT id, title, severity, cvss, epss, kev, published_at, active_matches, synthetic FROM reporting.vulnerability_catalog ORDER BY published_at DESC NULLS LAST LIMIT 300', 24),
    ],
    '05 · Affected Assets & Evidence': [
        ('Vulnerability to Asset Correlations', 'table', 'SELECT vulnerability_id, severity, cvss, kev, hostname, ip_address, software, vendor, version, confidence, evidence, first_detected FROM reporting.vulnerability_findings WHERE active ORDER BY kev DESC, cvss DESC NULLS LAST, hostname LIMIT 10000', 24),
        ('Detection Trend', 'line', 'SELECT detected_day, findings_created FROM reporting.detection_timeline ORDER BY detected_day DESC LIMIT 180', 12),
        ('Most Exposed Systems', 'bar', 'SELECT hostname, critical_findings, matched_findings FROM reporting.top_risky_assets ORDER BY critical_findings DESC LIMIT 15', 12),
    ],
    '06 · Pipeline Health & Coverage': [
        ('Mapped Packages', 'scalar', 'SELECT mapped_products FROM reporting.coverage', 6),
        ('Unmapped Packages', 'scalar', 'SELECT unmapped_products FROM reporting.coverage', 6),
        ('Recent Collection Runs', 'table', 'SELECT source, started_at, finished_at, success, record_count, message FROM reporting.ingestion_health ORDER BY started_at DESC LIMIT 100', 24),
    ],    '07 · Mapping Quality & Review': [
        ('Active Software Products', 'scalar',
         'SELECT active_products FROM reporting.data_quality_overview', 6),
        ('Verified Mapping Coverage %', 'scalar',
         'SELECT mapping_coverage_pct FROM reporting.data_quality_overview', 6),
        ('Unmapped Active Products', 'scalar',
         'SELECT unmapped_products FROM reporting.data_quality_overview', 6),
        ('Pending Mapping Reviews', 'scalar',
         'SELECT pending_reviews FROM reporting.data_quality_overview', 6),
        ('Approved Active Products', 'scalar',
         'SELECT approved_mapped_products FROM reporting.data_quality_overview', 6),
        ('Unknown Vendor Products', 'scalar',
         'SELECT unknown_vendor_products FROM reporting.data_quality_overview', 6),
        ('Unknown Version Installations', 'scalar',
         'SELECT unknown_version_installations FROM reporting.data_quality_overview', 6),
        ('Active Software Installations', 'scalar',
         'SELECT active_installations FROM reporting.data_quality_overview', 6),
        ('Products With Ingested Advisory Records', 'scalar',
         'SELECT count(*) FROM reporting.data_quality_products '
         'WHERE has_ingested_advisory_records', 6),
        ('Verified vs Unmapped Active Products', 'pie',
         'SELECT mapping_status, count(*) AS product_count '
         'FROM reporting.data_quality_products GROUP BY mapping_status ORDER BY product_count DESC', 12),
        ('Unmapped Products by Vendor', 'bar',
         'SELECT vendor, unmapped_products FROM reporting.data_quality_by_vendor '
         'ORDER BY unmapped_products DESC, vendor LIMIT 20', 12),
        ('Mapping Coverage by Operating System', 'table',
         'SELECT os_name, active_products, mapped_products, unmapped_products '
         'FROM reporting.data_quality_by_os ORDER BY unmapped_products DESC LIMIT 100', 12),
        ('Mapping Coverage by Domain', 'table',
         'SELECT domain, active_products, mapped_products, unmapped_products '
         'FROM reporting.data_quality_by_domain ORDER BY unmapped_products DESC LIMIT 100', 12),
        ('Unmapped Product Inventory & Data Gaps', 'table',
         'SELECT software, vendor, active_asset_count, active_installation_rows, '
         'unknown_version_installations FROM reporting.data_quality_products '
         "WHERE mapping_status='unmapped' ORDER BY active_asset_count DESC, software LIMIT 2000", 24),
        ('Mapped Products vs Ingested Advisories', 'table',
         'SELECT software, vendor, ecosystem, package_name, active_asset_count, '
         'has_ingested_advisory_records FROM reporting.data_quality_products '
         "WHERE mapping_status='approved_mapping' ORDER BY active_asset_count DESC LIMIT 2000", 24),
        ('Mapping Review Queue', 'table',
         'SELECT review_id, vendor, software, ecosystem, package_name, similarity, origin, '
         'proposed_by, created_at FROM reporting.mapping_review_queue '
         "WHERE status='pending' ORDER BY similarity DESC NULLS LAST, created_at DESC LIMIT 500", 24),
        ('Mapping Decision Audit', 'table',
         'SELECT event_id, review_id, action, actor, reason, created_at, vendor, software, '
         'ecosystem, package_name FROM reporting.mapping_review_audit '
         'ORDER BY created_at DESC LIMIT 500', 24),
        ('Source Sync Freshness', 'table',
         'SELECT source, last_success_at, last_failed_at, successful_runs, failed_runs '
         'FROM reporting.data_quality_sync_freshness ORDER BY source', 24),
    ],
    '08 · Risk Intelligence & Remediation': [
        ('Active Potential Findings', 'scalar',
         'SELECT active_findings FROM reporting.risk_overview', 6),
        ('P1 Highest Priority', 'scalar',
         'SELECT p1_findings FROM reporting.risk_overview', 6),
        ('CISA KEV Findings', 'scalar',
         'SELECT kev_findings FROM reporting.risk_overview', 6),
        ('SLA Overdue', 'scalar',
         'SELECT overdue_findings FROM reporting.risk_overview', 6),
        ('Total Modeled Priority Points', 'scalar',
         'SELECT priority_points FROM reporting.risk_overview', 6),
        ('Accepted Risks · Unexpired', 'scalar',
         'SELECT accepted_findings FROM reporting.risk_overview', 6),
        ('Unscored Potential Findings', 'scalar',
         'SELECT unscored_findings FROM reporting.risk_overview', 6),
        ('Assets Without Explicit Criticality', 'scalar',
         'SELECT unknown_criticality FROM reporting.asset_context_quality', 6),
        ('Priority Tiers', 'pie',
         'SELECT priority, count(*) AS findings FROM reporting.risk_queue '
         'GROUP BY priority ORDER BY priority', 12),
        ('Priority by Business Service', 'bar',
         'SELECT business_service, modeled_priority_points FROM reporting.risk_by_service '
         'ORDER BY modeled_priority_points DESC LIMIT 15', 12),
        ('Modeled Priority Points by Owner', 'bar',
         'SELECT owner, modeled_priority_points FROM reporting.risk_by_owner '
         'ORDER BY modeled_priority_points DESC LIMIT 15', 12),
        ('Daily Priority Trend', 'line',
         'SELECT day, priority_points FROM reporting.risk_trend '
         'ORDER BY day ASC LIMIT 365', 12),
        ('Risk-Based Remediation Queue', 'table',
         'SELECT finding_id, priority, risk_score, hostname, cve_id, '
         'software, version, cvss, epss, epss_asof, kev, criticality, internet_facing, '
         'business_service, owner, workflow_state, sla_due_at, overdue '
         'FROM reporting.risk_queue ORDER BY risk_score DESC NULLS LAST LIMIT 2000', 24),
        ('CISA KEV Exposure Queue', 'table',
         'SELECT finding_id, hostname, cve_id, software, risk_score, '
         'business_service, owner, sla_due_at, overdue FROM reporting.risk_queue '
         'WHERE kev ORDER BY risk_score DESC NULLS LAST LIMIT 1000', 24),
        ('Finding Evidence & Candidate Remediation', 'table',
         'SELECT finding_id, cve_id, hostname, software, version, priority, '
         'evidence_packet, remediation FROM reporting.finding_evidence '
         'ORDER BY risk_score DESC NULLS LAST LIMIT 1000', 24),
        ('Risk Acceptance & Lifecycle', 'table',
         'SELECT finding_id, cve_id, hostname, workflow_state, '
         'accepted_by, accepted_until, first_detected, last_detected, '
         'sla_due_at FROM reporting.finding_lifecycle '
         'ORDER BY last_detected DESC LIMIT 1000', 24),
        ('Finding Decision & State Audit', 'table',
         'SELECT event_id, finding_id, action, actor, reason, created_at '
         'FROM reporting.finding_event_history ORDER BY event_id DESC LIMIT 500', 24),
        ('Missing Asset Context', 'table',
         'SELECT active_assets, unknown_criticality, unknown_exposure, unassigned_owner '
         'FROM reporting.asset_context_quality', 24),
    ],
}
