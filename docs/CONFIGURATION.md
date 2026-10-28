# Configuration — V3

The default Demo is **fully configured by ./install.sh --demo**. Change settings only when you need live inventory, verified asset business context or optional mail. Do not manually enter database passwords for the Demo; the installer generates separate random values.

## Local configuration

| File | Default action | Stored privately? |
|---|---|---|
| .env | Automatically generated from example.env; unique passwords | Yes, 0600 and git-ignored |
| config/application.yaml | Automatically generated from the commented example | Yes, git-ignored |
| config/asset-context.yaml | Automatically copied from the empty sample | Yes, git-ignored |
| secrets/manageengine_token | Empty in Demo; verified read-only token needed in Live | Yes, 0600 |
| config/product-mappings.yaml | Synthetic Demo software identities | Tracked sample |
| config/product-mappings.live.yaml | Empty, safe Live mapping source | Tracked empty sample |

Avoid changing environment mode on an existing database. An installation-mode marker prevents reusing Demo data as Live.

## Compose and secrets (.env)

- COMPOSE_PROJECT_NAME: default assetvuln-monitor-v03, **never** V1 or V2.
- BIND_IP: 127.0.0.1, loopback-only by default.
- HTTPS_PORT: 8445 by default.
- PUBLIC_URL: https://localhost:8445 by default.
- HOST_UID, HOST_GID: generated from the installing user for secrets access.
- APP_DB_PASSWORD, POSTGRES_PASSWORD, REPORT_DB_PASSWORD, MB_DB_PASSWORD, METABASE_ADMIN_PASSWORD: generated separately if missing or placeholder.
- METABASE_ADMIN_EMAIL: change the default example address before Live exposure.
- PRODUCT_MAPPINGS_FILE: selected as a synthetic Demo mapping or empty Live mapping according to installation mode; do not mix them.

Do not commit actual .env, certificates, credentials, asset-context configuration, inventory exports or backups. Backup/restore scripts manage the two PostgreSQL application databases for this **one** Compose project.

## Application YAML

| Key | Meaning |
|---|---|
| application.mode | demo or live |
| manageengine.url | Your HTTPS Endpoint Central base URL; no API suffix |
| manageengine.token_file | /run/secrets/manageengine_token |
| manageengine.verify_tls | Must stay true in Live |
| manageengine.ca_bundle | Optional in-container path under /opt/avm/certs |
| manageengine.sync_minutes | Default 360 |
| manageengine.max_assets / max_pages | Safety caps; incomplete collection fails instead of truncating |
| cve.url | Default https://cve.now |
| cve.sync_minutes | Default 30 |
| cve.max_pages_per_poll | Default 5; intentionally bounded, not a CVE historical backfill |
| threat_intelligence.enabled | Default true; only Live uses CISA KEV and FIRST daily EPSS CSV |
| threat_intelligence.sync_hours | Default 24; automatic KEV GET and FIRST daily CSV refresh |
| vulnerability_sources.osv.enabled | Default true in Live: OSV read-only POST QueryBatch and 24-hour per-version cache |
| vulnerability_sources.nvd.enabled | Default true in Live: bounded NVD modified-date GET API delta |
| vulnerability_sources.euvd.enabled | Default true in Live: paginated ENISA EUVD advisory GET |
| NVD_API_KEY (.env) | Optional only; no other source credential is mandatory |
| risk.sla_days | Optional P1/P2/P3/P4 SLA targets in days (defaults 7/30/90/180) |
| matching.mappings_file | Worker path to mounted mapping YAML |
| notifications.email_enabled | Default false; optional SMTP configuration must be independently verified |

No additional API keys are required for CISA KEV, FIRST EPSS, OSV or EUVD. NVD_API_KEY is optional. The Worker uses fixed HTTPS origins:
- CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST EPSS daily bulk CSV: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz (recommended for large-scale ingestion; the public /data/v1/epss API is for limited lookups)

The FIRST **daily CSV** is streamed and validated for bulk updates of known local CVEs; its API is no longer used for mass lookup. Existing EPSS/KEV values are kept if refresh fails. The retrieval timestamp indicates when AVM checked the source, not a guarantee of publication freshness.

## Explicit asset context (optional)

Configure real business/service criticality only after validating it against organizational inventory or CMDB:

~~~yaml
assets:
  - source_id: "301"
    criticality: critical
    internet_facing: true
    business_service: "Payment API"
    owner: "Payments"
~~~

The Worker reads config/asset-context.yaml every inventory synchronization. Unspecified assets get criticality unknown and Internet exposure null (unknown). It does not infer Internet exposure from a hostname, IP range or a DNS name.

The current configuration is deliberately a short explicit file, not an invented full CMDB integration. A future integration should preserve authoritative source and freshness evidence.

## Reviewed mapping sources

Demo uses two deliberately synthetic approved identities; Live starts with no approvals. An exact normalized vendor/name can be approved using a privileged operator action after independent verification, and automatically proposed similarities remain **pending** until that action. See [Mapping Review](MAPPING-REVIEW.md).

## Risk priority semantics

V3 prioritization components (maximum total 100 points):

| Component | Maximum |
|---|---:|
| CVSS v3/v4 value normalized to 0–10 | 40 |
| EPSS 0–1 (square-root transformation) | 20 |
| CISA KEV catalog membership | 25 |
| Explicit asset criticality | 10 |
| Explicit Internet exposure | 5 |

A KEV entry enforces a floor of 75 priority points (P1) for that *potential match*. Missing signals are reported separately rather than silently represented as known zero evidence. The score is not the likelihood of exploitation.

Priorities: P1 ≥75, P2 ≥50, P3 ≥25, P4 below 25. Default remediation SLA targets: P1 7 days, P2 30, P3 90, P4 180, measured from first observation; operators can edit the corresponding risk.sla_days values in the YAML. SLA calculations are **internal model defaults**, not external regulatory requirements or contractual guarantees; tailor operational policy before use.

Risk acceptances last 1–180 days, require a privileged CLI command with evidence-backed explanation and are audited in the app DB. The operator identifier is self-declared; RBAC/SSO is not yet implemented.

## Updating settings

After editing application YAML, restart the v0.3 Worker (this changes only the local Compose project):

~~~bash
docker compose restart worker
~~~

Asset-context values are applied at the next inventory sync. New mapping approvals also take effect on that sync. A restart alone does not force source collection if the Worker is already processing; inspect logs for recorded collection completion.

More details: [Multi-source design](V03-MULTISOURCE.md), [V3 operations](V03-OPERATIONS.md), [installation](INSTALLATION.md), [security](SECURITY.md).
