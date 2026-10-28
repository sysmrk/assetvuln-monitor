# AssetVuln Monitor v0.3 — development scope, design and exit gates

**Branch:** develop/v0.3, created directly from develop/v0.2. Main (v0.1) and develop/v0.2 are not merged or modified.

## V3 product goal

Move from asset inventory and governed identity mapping toward **risk-informed, evidence-backed vulnerability remediation**, without expanding infrastructure complexity. Retain the existing single Python Worker, PostgreSQL, Metabase and NGINX deployment.

Primary design rules:
1. One-command synthetic Demo; private random credentials generated automatically.
2. No automatic remote patching or non-GET calls to Endpoint Central.
3. Unmapped software and unverified guesses cannot produce CVE findings.
4. Composite risk points are a transparent prioritization heuristic, **not** exploit probability.
5. Unknown asset criticality/exposure stays unknown; public-intelligence origin and freshness must be explicit.
6. Missing source data never becomes a silent claim of remediation.
7. Risk acceptance and mapping approval require explicit privileged actions and a recorded reason.

## Implemented in the development branch

### V3.0 — Threat and risk
- [x] Explainable CVSS / FIRST EPSS / CISA KEV / optional business context point-based ranking (P1–P4).
- [x] Require verified CISA/FIRST provenance for Live threat signals, preserve synthetic Demo values separately.
- [x] Same Worker periodically requests the public KEV and EPSS datasets over HTTPS GET; no API key or extra container.
- [x] Configurable asset criticality, internet exposure, business service and owner via git-ignored YAML, auto-created with safe defaults.
- [x] Store priority components, missing signals, data-source provenance and modeled score.

### V3.1 — Evidence, lifecycle and remediation
- [x] Snapshot installed version, normalized approved package and machine-readable affected ranges per potential finding.
- [x] Extract candidate fixed versions only from explicit structured events, with vendor/backport warnings.
- [x] Record detected, reopened, not_observed and expired risk-acceptance events.
- [x] Respect successful inventory boundary; no feed-only closure, no auto claim of fixed/remediated.
- [x] Time-limited acceptance (1–180 days), release, actor and evidence reason via privileged CLI.
- [x] Configurable source sync cadence and internal default P1–P4 SLA targets (7/30/90/180 days).

### V3.2 — Visibility and ergonomics
- [x] Eighth read-only Metabase dashboard for risk queue, evidence, ownership, KEV, SLA, model trend and lifecycle audit.
- [x] Read-only CLI for queue and hypothetical top-N/KEV score-point removal.
- [x] Optional daily point-in-time risk aggregate table and reporting view.
- [x] Safe automatic env creation, private business context, Demo/Live mode lock, unique V3 namespace and HTTPS 8445 defaults.
- [x] Automated CI tests for Python/SQLite, synthetic PostgreSQL, reporting permissions, config syntax, V1/V2 separation, and a full disposable synthetic Docker/Metabase Demo startup (successful workflow run 40599590218).
- [x] Rewrite README, installation, configuration, security and troubleshooting for V3 simplicity and current limitations.

### V3.3 — Multi-source advisory intelligence
- [x] OSV unique approved package/version querybatch with full pagination and SQL-backed expiry cache.
- [x] NVD CVE 2.0 modified-date metadata delta and EUVD recent published-record metadata cursor.
- [x] FIRST full daily CSV instead of bulk lookup API; preserve CISA verified KEV flags.
- [x] Per-provider source identities, aliases, selected CVSS origin, withdrawals and per-Finding matched source evidence.
- [x] Ninth Metabase dashboard with source coverage, evidence, cache and sync freshness.
- [x] Fail-closed source isolation and retention of historical retracted evidence.

## Remaining validation and future features

**Not production validated:** running the actual Docker/Metabase UI on customer hardware, Endpoint Central API compatibility/pagination, KEV/EPSS provider responses from the target network, and vendor backport/patch confirmation. CI tests are not a substitute for these checks.

**Deliberately deferred to keep V3 small:**
- Full CPE/PURL identity resolver (requires ecosystem-specific vendor evidence and governance, not fuzzy guessing).
- Dedicated ticketing/ServiceNow/Jira integration (needs credentials, ownership rules and explicit action consent).
- Authenticated browser-based approval UI, SSO/RBAC and immutable audit forwarding.
- Exploit intelligence beyond verified CISA KEV, external exposure scanning or actively probing production assets.
- Automated patch installation, software upgrade execution and verification of exploitability.
- Real quantitative attack-loss prediction; hypothetical score removal is a planning aid only.
- Performance tuning for very large inventories, external CMDB import and historical CVE backfill.

## Quality gates before promotion

1. GitHub Actions must pass all unit, syntax, temporary PostgreSQL and read-only Compose separation checks for the final commit.
2. [Partially verified] Fresh one-command Docker Demo and Metabase HTTPS/risk SQL/CLI have passed in CI; visually inspect all nine Metabase dashboards and queries in staging.
3. Test Live integration using an approved read-only Endpoint Central token and a secure staging setup; verify actual pagination.
4. Validate official KEV/EPSS feed refresh, failure rollback and freshness timestamps in that environment.
5. Verify reviewer/actor access control and add production-quality audit protections.
6. Back up V3 PostgreSQL and test upgrade and restore in a dedicated staging environment.
7. Merge into main **only after explicit user approval** and review; the V2 and V1 branches remain independently usable.

## Key modules

- avm/risk.py — pure explainable scoring, evidence, candidate remediation, simulation
- avm/threat_intel.py — CISA/FIRST GET-only clients and strict enrichment
- avm/asset_context.py — opt-in verified organizational context
- avm/lifecycle.py — conservative Finding transitions and daily snapshots
- avm/ops.py — minimal privileged CLI for queue/simulate/accept/release
- avm/models.py — additive v3 fields, lifecycle audit/snapshots and reporting views
- avm/dashboards.py — dashboard 08
- scripts/prepare_env.py + scripts/install.sh — safe one-command Demo
- .github/workflows/v03-quality.yml — automated quality gates
