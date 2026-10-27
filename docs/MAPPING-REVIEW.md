# v0.2 — Mapping Review Workflow and Data Quality

This feature is available **only** in the `develop/v0.2` branch. Nothing is merged to `main`.

## Architecture and trust boundary

```text
Endpoint Central (GET only) ──> Worker ──> Software / Installations
                                      │
                                      ├── Exact approved YAML + approved DB identities
                                      │       └── CVE matching (next inventory sync)
                                      │
                                      └── Name similarity ──> mapping_reviews (PENDING)
                                                              │
                         Privileged operator CLI ────────────┤
                                    │                         │
                               approve/reject                 │
                                    │                         ▼
                               mapping_decisions (audit trail)
                                    │
                             approve only
                                    ▼
                          approved_software_mappings
                                    │
                      included at the next inventory sync
```

**Automatic matching suggestions cannot create CVE findings.** Only identities already in the operator-approved YAML or explicitly approved through the CLI are used by the Worker. An automatic suggestion may include `name_similarity` (a string similarity ratio), which must **not** be interpreted as product-confidence or proof of vulnerability.

The three new PostgreSQL tables are:
- `mapping_reviews`: candidate vendor/name and advisory ecosystem/package, evidence, similarity, state (`pending`, `approved`, `rejected`), proposer and reviewer.
- `mapping_decisions`: append-only *application-level* proposal/decision events (timestamp, action, actor, reason). PostgreSQL owners still have the technical ability to alter audit records; this is **not** cryptographically immutable or WORM storage.
- `approved_software_mappings`: approved, normalized vendor/name to ecosystem/package identities. The database enforces at most one approved identity for a normalized vendor/product pair.

The Metabase reporting account has **SELECT on reporting views**, not write access to these tables. Mapping decisions require privileged application DB access through the Worker container.

## Set up v0.2

Use an isolated v0.2 Compose project and .env as described in [isolation instructions](V02-ISOLATION.md). Run the installation (`./install.sh --demo` for a synthetic evaluation, or `--live` after verifying both ManageEngine APIs). After the worker has initialized the database:

```bash
# Read-only: inspect the review queue
docker compose exec worker python -m avm.review_cli list --status pending

# Read-only: include approved/rejected records
docker compose exec worker python -m avm.review_cli list --status all --limit 100

# Read-only: inspect append-only application audit entries for review 12
docker compose exec worker python -m avm.review_cli history --review-id 12
```

## Create an explicit candidate when automatic matching cannot suggest one

An empty Live mapping catalogue is intentionally safe: `products: []` produces no automatic suggestions. You can **manually propose a product identity** after investigating the real Endpoint Central software name/vendor and the advisory. This creates a **pending** proposal only.

```bash
docker compose exec worker python -m avm.review_cli propose \
  --vendor "Verified Vendor From Inventory" \
  --name "Verified Product From Inventory" \
  --ecosystem "PyPI" \
  --package "verified-package-from-advisory" \
  --actor "analyst_a" \
  --evidence "Verified vendor/product information and advisory package reference."
```

The names above are **placeholders**, not valid product mappings. Never approve them without independent product and advisory verification.

## Approve or reject a pending proposal

A **different person** must approve/reject a manually proposed identity; the CLI checks for distinct actor identifiers (case-insensitive). Automatic proposals may be reviewed by any operator.

```bash
# Approve only after validating vendor, exact product, package ecosystem,
# version applicability and any vendor backports:
docker compose exec worker python -m avm.review_cli approve \
  --id 12 \
  --actor "reviewer_b" \
  --reason "Independently verified the exact package identity in vendor advisory."

# OR reject an incorrect candidate (use an applicable pending ID):
docker compose exec worker python -m avm.review_cli reject \
  --id 13 \
  --actor "reviewer_b" \
  --reason "Advisory applies to a different package and product edition."
```

Each decision moves the proposal from `pending` to `approved` or `rejected` **exactly once**. Automatically discovered duplicate proposals are not appended on later syncs; previously rejected identities remain rejected, not re-opened.

Approved identities are picked up by the Worker **on its next inventory synchronization**. The CLI does not immediately rewrite the YAML, change running inventory rows, recalculate existing CVE findings, or trigger another sync. Verify source data and the resulting findings independently; backported vendor patches can invalidate simplistic version matches.

### Security limitations of this first workflow

- `--actor` is a **self-declared audit identifier**. There is no integrated SSO, signature or RBAC-based verification of that name yet. Limit shell/container/DB access to trusted administrators. The two-person check is a workflow guard, **not a strong security boundary**.
- Changes use SQLAlchemy transactions, locking for individual reviews, uniqueness constraints for approved identities and consistent state transitions; concurrent approvals still require PostgreSQL integration testing.
- Approval is not made available through Metabase or a public HTTP endpoint.
- Changing an approved identity, revoking an approval, and a complete immutable external audit sink are **future features**; do not edit approval tables manually.
- Back up the v0.2 PostgreSQL volume before upgrades. The tables are created by `Base.metadata.create_all`; no destructive migration is included.
- The current approval store is a **separate** set of trusted identities. If an equivalent YAML entry and DB approval conflict, ingestion fails closed instead of silently choosing one.

## Seventh Metabase dashboard

`07 · Mapping Quality & Review` is provisioned during Metabase bootstrap. It reads the following `reporting.*` SQL views:

| View | Purpose |
|---|---|
| `data_quality_overview` | Active product count, mapped/unmapped count, coverage %, unknown versions/vendors, review states |
| `data_quality_products` | Products, installed-host counts, unknown versions, whether any matching advisory records were ingested |
| `data_quality_by_vendor` | Mapped/unmapped products per vendor |
| `data_quality_by_os` | Mapped/unmapped products per operating system |
| `data_quality_by_domain` | Mapped/unmapped products per domain |
| `mapping_review_queue` | Proposed identity and current review status |
| `mapping_review_audit` | Review decisions and reviewer identifiers |
| `data_quality_sync_freshness` | Latest successful/failed ingestion timestamps per source |

**Denominator:** the headline coverage percentage counts distinct software products with at least one **active installation on an active asset**. The numerator is the number of those products with an approved ecosystem/package identity. The same product can appear in multiple OS/domain groups; **do not sum group totals** as if they were distinct global products. The unknown-version figure counts *installation records*, not distinct products.

**Scope limitation:** *approved mapping coverage is not CVE/advisory coverage.* The separate `has_ingested_advisory_records` flag merely indicates at least one advisory record was ingested for that package; the feed is currently bounded to recent pages, and absence of a record is **not proof of safety**.

A fresh bootstrap installs the seventh dashboard. On an existing v0.2 database, rerun the installer/bootstrap to create the new dashboard **after** upgrading the Worker schema. The provisioning logic is designed to avoid duplicating dashboards/cards by name, but an end-to-end Metabase test is pending.

## Developer tests

```bash
python3 -m pytest -q tests/test_mapping_review.py tests/test_review_cli.py \
  tests/test_dashboards.py tests/test_worker_mapping.py
python3 -m compileall -q avm scripts tests
```

The database workflow tests use in-memory/on-disk SQLite to validate state transitions, not to prove PostgreSQL permissions, migrations, locking, or full Docker-stack behavior. GitHub Actions performs unit tests and non-mutating Compose checks; deployment and real Endpoint Central validation are still outstanding.
