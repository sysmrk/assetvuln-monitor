# AssetVuln Monitor v0.2 — Development Roadmap

> Development branch: `develop/v0.2`. The `main` branch remains the v0.1 baseline. **Do not merge without explicit review and approval.**

## Scope and guiding principles

v0.2 focuses on **reliable inventory and defensible software-to-vulnerability identity mapping**, not on generating more speculative CVE findings. No write calls to Endpoint Central. All external clients remain GET-only. Demo fixtures and live data must remain isolated.

## Milestone 0 — Development isolation and quality gates

- [ ] Support independent Docker Compose project names, networks, volumes and HTTPS ports for simultaneous v0.1/v0.2 testing.
- [ ] Document an isolated v0.2 installation; never reuse v0.1 production/demo database volumes.
- [ ] Add CI checks: Python unit tests, syntax/lint checks, Docker Compose config validation, secret scanning where available.
- [ ] Test existing standalone Endpoint Central API smoke test against a controlled mock; real integration tests require an approved Endpoint Central instance.
- [ ] Preserve a clear migration/rollback path.

**Exit criteria:** v0.2 can start and stop without affecting a running v0.1 deployment.

## Milestone 1 — Inventory reliability and data quality

- [ ] Validate actual Endpoint Central API response fields and pagination across versions.
- [ ] Record API status, pages read, item counts, schema failures, and collection timestamps without leaking credentials.
- [ ] Avoid marking unseen assets inactive after partial/incomplete collection.
- [ ] Build data-quality metrics: unmapped products, unknown versions, duplicate software identities, missing vendor values.

**Exit criteria:** ingestion is measurable and fails closed on partial/invalid data.

## Milestone 2 — Software normalization and controlled mapping

- [ ] Normalize vendor, software name and version while retaining raw source values.
- [ ] Model candidate package identities (ecosystem, package name, optional PURL/CPE) separately from approved identities.
- [ ] Add confidence and evidence for each candidate; never auto-promote fuzzy matches into confirmed vulnerability findings.
- [ ] Provide analyst approval/rejection and audit trail; begin with CLI or a simple review interface.
- [ ] Keep demo and live mapping sources separate.

**Exit criteria:** reviewers can explain and reproduce every approved mapping.

## Milestone 3 — Mapping coverage dashboard

- [ ] Distinguish discovered software, verified mapped software, and software with supported advisory coverage.
- [ ] Display coverage by vendor, OS, business segment and last successful sync.
- [ ] Show candidates awaiting review, unmapped inventory and trends.
- [ ] Define explicit denominators to avoid misleading coverage percentages.

**Exit criteria:** dashboards make gaps and uncertainty visible, not just positive matches.

## Deferred to later phases

Asset criticality, EPSS/KEV enrichment, risk prioritization, vulnerability lifecycle, ticketing, and dedicated workflow UI. Their design should follow verified inventory/mapping and a clear ownership model.

## Development workflow

1. All v0.2 code and documentation changes target `develop/v0.2` or short-lived feature branches based on it.
2. Run unit tests and Compose validation for each feature; record what could not be tested.
3. Do not push experimental code to `main`.
4. Merge into `main` only after user approval and a reviewed pull request.

## Current constraints

- Real Endpoint Central responses and CVE provider compatibility are not yet verified.
- Existing v0.1 Compose project name is fixed; **do not start both branches on the same Docker daemon yet**.
- `config/product-mappings.live.yaml` intentionally begins empty to prevent unsupported correlations.
