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
    ],
}
