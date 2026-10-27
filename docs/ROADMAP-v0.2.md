# AssetVuln Monitor v0.2 — Development Roadmap

> Development branch: `develop/v0.2`. The `main` branch remains the v0.1 baseline. **Do not merge without explicit review and approval.**

## Scope and guiding principles

v0.2 focuses on **reliable inventory and defensible software-to-vulnerability identity mapping**, not on generating more speculative CVE findings. No write calls to Endpoint Central. All external clients remain GET-only. Demo fixtures and live data must remain isolated.

## Milestone 0 — Development isolation and quality gates

- [x] Support independent Docker Compose project names, networks, volumes and HTTPS ports for simultaneous v0.1/v0.2 testing (configuration implemented; runtime validation pending).
- [x] Document an isolated v0.2 installation, read-only collision checker and rollback; **coexistence still requires Docker runtime validation**.
- [x] Add GitHub Actions checks for Python unit tests, compile/shell syntax and Docker Compose config; **broader linting and secret-scanning policy remain open**.
- [x] Add mocked tests for the standalone GET-only Endpoint Central API smoke test; **real API verification remains open**.
- [x] Document separate deployment and rollback; **no database migration implemented or needed yet for the offline tooling**.

**Exit criteria:** v0.2 can start and stop without affecting a running v0.1 deployment.

## Milestone 1 — Inventory reliability and data quality

- [ ] Validate actual Endpoint Central API response fields and pagination across versions.
- [ ] Record API status, pages read, item counts, schema failures, and collection timestamps without leaking credentials.
- [ ] Avoid marking unseen assets inactive after partial/incomplete collection.
- [x] Add runtime reporting views for active distinct software products, unknown vendors/versions, mapping coverage and review state. **Performance and accuracy at enterprise scale not yet validated**.

**Exit criteria:** ingestion is measurable and fails closed on partial/invalid data.

## Milestone 2 — Software normalization and controlled mapping

- [x] Implement conservative Unicode/whitespace identity normalization and preserve raw inputs; integrate approved-only exact normalized keys into the v0.2 worker.
- [x] Persist review-only proposals in PostgreSQL with explicit status and evidence; **PURL/CPE and authenticated review UI remain open**.
- [x] Add explainable string similarity and source/evidence labels; explicitly **not** a probability/confidence of product identity and never auto-promote.
- [x] Implement privileged CLI for propose/approve/reject/history, separate manual proposer/reviewer identifiers, and application-level audit events. **SSO/RBAC and immutable audit store remain open**.
- [x] Keep demo and live mapping sources separate; offline sample catalog is synthetic and separate from both.

**Exit criteria:** reviewers can explain and reproduce every approved mapping.

## Milestone 3 — Mapping coverage dashboard

- [x] Distinguish active software, approved mapping identity and existence of **ingested** advisory records (limited feed; not comprehensive CVE coverage).
- [x] Display coverage by vendor, OS, domain and latest ingestion success/failure timestamp; **business criticality attributes not available yet**.
- [x] Show pending reviews, audit history and unmapped active products. **Historical trend snapshots remain open**.
- [x] Define active distinct-product denominators and explicitly separate mapping coverage from ingested advisory presence.

**Exit criteria:** dashboards make gaps and uncertainty visible, not just positive matches.

## Deferred to later phases

Asset criticality, EPSS/KEV enrichment, risk prioritization, vulnerability lifecycle, ticketing, and dedicated workflow UI. Their design should follow verified inventory/mapping and a clear ownership model.

## Development workflow

1. All v0.2 code and documentation changes target `develop/v0.2` or short-lived feature branches based on it.
2. Run unit tests and Compose validation for each feature; record what could not be tested.
3. Do not push experimental code to `main`.
4. Merge into `main` only after user approval and a reviewed pull request.

## What has been implemented in the current development branch

- Read-only Compose collision checker: `scripts/check_compose_isolation.py`; unit tests cover project, volume, network, bind and host-port overlaps.
- Offline normalization/suggestion core: `avm/normalization.py`, `scripts/suggest_mappings.py`, synthetic examples and test coverage.
- GitHub Actions quality workflow: `.github/workflows/v02-quality.yml` (CI execution results not yet independently verified).
- Installation and configuration documentation updated for the `develop/v0.2` checkout.
- `avm/mapping_review.py` persists pending proposals, independent reviewer decisions and approved-only identities; `avm/review_cli.py` manages them with a privileged CLI.
- `avm/models.py` provides 3 review tables and 8 new `reporting.*` views; `avm/dashboards.py` provisions the seventh dashboard.
- SQLite unit tests exercise approval and decision history; PostgreSQL/Metabase end-to-end validation is still pending.

## Current constraints

- Real Endpoint Central responses and CVE provider compatibility are not yet verified. Runtime worker mapping changes are covered by code-level tests but not Docker/live validation.
- v0.1 Compose project name is fixed. v0.2 defaults to a distinct project and port; **runtime coexistence is not yet verified**, so check resolved Compose configuration before starting both.
- `config/product-mappings.live.yaml` intentionally begins empty to prevent unsupported correlations.
