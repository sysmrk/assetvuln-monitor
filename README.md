# AssetVuln Monitor — v0.2 development branch

**Read-only asset and vulnerability-intelligence dashboards, packaged entirely in Docker Compose.**

Endpoint Central ➜ PostgreSQL ➜ conservative CVE correlation ➜ automatically provisioned Metabase dashboards, behind NGINX HTTPS.

> **Status: v0.2 experimental development branch**, based on the v0.1 technical preview. New normalization and isolation logic has local unit-test coverage; live Endpoint Central and Docker coexistence have not yet been validated. Do not consider this production-certified.

**v0.2 isolation:** use `COMPOSE_PROJECT_NAME=assetvuln-monitor-v02`, `HTTPS_PORT=8444`, and `PUBLIC_URL=https://localhost:8444` in this branch's `.env`. Never reuse v0.1 database volumes. See [v0.2 isolation guide](docs/V02-ISOLATION.md).

## v0.2 — Offline software normalization and quality checks

Phase-two code is isolated on `develop/v0.2`. An offline **review-only** suggestion engine is available; it does not change approved mappings or generate new vulnerability findings. Start with the synthetic fixtures:

```bash
python3 scripts/suggest_mappings.py --inventory-csv examples/software-inventory.sample.csv --approved-mappings examples/mapping-catalog.sample.yaml --output mapping-review.json
python3 -m pytest -q
```

See [software normalization and mapping review](docs/SOFTWARE-NORMALIZATION.md) and [v0.2 roadmap](docs/ROADMAP-v0.2.md). To validate Compose isolation against a v0.1 checkout, run `python3 scripts/check_compose_isolation.py --baseline-dir /path/to/v0.1` before starting both deployments. GitHub Actions runs unit tests and Compose syntax checks on the development branch.

## v0.2 — Audited mapping review and seventh dashboard

The v0.2 worker persists **review-only mapping candidates** after a successful inventory sync. Trusted administrators can propose, approve or reject software identities using the privileged CLI. Manual proposals require a separate reviewer identifier; decisions and reasons are recorded in the database. Only approved identities can affect the next inventory synchronization. No suggestion is automatically approved.

```bash
# Read-only review queue:
docker compose exec worker python -m avm.review_cli list --status pending
# Read-only decision history:
docker compose exec worker python -m avm.review_cli history --review-id 12
```

The new **07 · Mapping Quality & Review** Metabase dashboard reports active mapped/unmapped software, pending decisions, unknown vendors/versions, per-OS/domain/vendor quality, audit records and ingest freshness. Mapping identity coverage is distinct from ingested-advisory coverage. For privileged approve/reject commands, security limitations and workflow details, see [Mapping Review](docs/MAPPING-REVIEW.md). Feature requires v0.2's isolated database.

## Quick start: choose DEMO or LIVE

> **Important:** v0.1 is a technical preview. The demo can be evaluated locally; the live Endpoint Central/cve.now integration has not yet been validated against real vendor responses and is **not production-certified**. The application is read-only toward managed assets in both modes.

### DEMO — WSL2 / Ubuntu 24.04 (no ManageEngine)

Docker Engine must be running. The project requires **Compose v2** (`docker compose`), not legacy `docker-compose` v1.

```bash
# On Ubuntu 24.04, if Docker is already running but Compose v2 is missing:
sudo apt update
sudo apt install -y docker-compose-v2 git openssl
docker compose version
docker info --format '{{.ServerVersion}}'

# Download and run:
cd /opt/src
git clone --branch develop/v0.2 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v02
cd assetvuln-monitor-v02
cp example.env .env
nano .env  # replace ALL CHANGE_ME_* passwords before installing
./install.sh --demo

# Check status and inspect logs:
docker compose ps
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
```

Open **https://localhost:8444**. The localhost TLS certificate is self-signed for demo use. Set the Metabase password in `.env` before installing; the installer provisions seven dashboards automatically. Demo records are synthetic, clearly labeled `CVE-DEMO-*`, and never fetched from ManageEngine.

### LIVE — real inventory (separate clean deployment)

**Never reuse a demo database for live assets:** demo data is not automatically removed. Use a fresh Docker project/volume, ideally on a separate host. **A separate directory alone is not sufficient:** assign an independent `COMPOSE_PROJECT_NAME` to each v0.2 instance, and use a different HTTPS port. Do not share database volumes.

```bash
# Recommended: execute on a fresh host with no existing AssetVuln Monitor Compose stack.
cd /opt
git clone --branch develop/v0.2 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-live
cd assetvuln-monitor-live
cp example.env .env
nano .env  # choose a UNIQUE COMPOSE_PROJECT_NAME, HTTPS_PORT, PUBLIC_URL and secrets
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
mkdir -p secrets/certs secrets/tls
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token config/application.yaml
nano config/product-mappings.live.yaml  # optional: verified organization-specific identities
# In .env set PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml
python3 scripts/test_manageengine_api.py  # verify APIs before installation
./install.sh --live
docker compose ps
docker compose logs --tail=200 worker
```

**Edit these exact fields in `config/application.yaml`:**

| Field | Real value / example |
|---|---|
| `application.mode` | `live` |
| `application.timezone` | Your timezone, e.g. `Asia/Tehran` |
| `manageengine.url` | `"https://endpoint.example.org:8383"` (HTTPS base URL) |
| `manageengine.token_file` | Keep `/run/secrets/manageengine_token` |
| `manageengine.verify_tls` | Keep `true` |
| `manageengine.ca_bundle` | `""` or `"/opt/avm/certs/org-ca.pem"` |
| `manageengine.sync_minutes` | `360` (6 hours) |
| `manageengine.max_assets` / `max_pages` | Set safe inventory and pagination caps |
| `cve.url` | `"https://cve.now"` |
| `cve.sync_minutes` / `max_pages_per_poll` | `30` / `5` |
| `matching.mappings_file` | Keep `/opt/avm/config/product-mappings.yaml` |
| `notifications.email_enabled` | `false` unless SMTP is configured |

Put **only the least-privilege, read-only inventory API token** in `secrets/manageengine_token` — not in YAML or Git. If using an internal CA, copy its PEM into `secrets/certs/org-ca.pem` and set the container CA path above. The tracked `config/product-mappings.yaml` is **demo-only**; Live must use `config/product-mappings.live.yaml` with verified product identities.

Copy `example.env` to a private `.env` before installation. It contains `METABASE_ADMIN_EMAIL`, `METABASE_ADMIN_PASSWORD`, database passwords, `BIND_IP`, `HTTPS_PORT`, and `PUBLIC_URL`. Set these before the first installation; replace demo TLS certificates with trusted ones. **Never commit `.env`, tokens or private keys.**

For **every command**, all optional fields, HTTPS configuration, backup/restore, and troubleshooting, read the [complete step-by-step installation guide](docs/INSTALLATION.md) and [configuration reference](docs/CONFIGURATION.md).

## Test ManageEngine APIs independently (before LIVE installation)

No Docker or database is required. The GET-only smoke test prints **both API endpoints** and reports PASS/FAIL/SKIP, response timing, and first-page record counts. It reads the HTTPS URL from `config/application.yaml` and the token from `secrets/manageengine_token`.

```bash
cp config/application.example.yaml config/application.yaml
nano config/application.yaml           # set manageengine.url
mkdir -p secrets
nano secrets/manageengine_token        # enter read-only token; never commit
chmod 600 secrets/manageengine_token
python3 scripts/test_manageengine_api.py
# Optional: python3 scripts/test_manageengine_api.py --resource-id 12345
# Optional internal CA: --ca-bundle secrets/certs/org-ca.pem
```

The test checks the first inventory page and one computer's software page; it does **not** certify pagination across all pages, data correctness, or version compatibility. A nonzero exit code indicates failure or incomplete coverage.

## Prebuilt dashboard catalog

| Dashboard | What it shows |
|---|---|
| 01 · Security Command Center | Total inventory, correlated exposure, severity and priority assets |
| 02 · Asset Explorer | Asset/OS/domain breakdown, searchable endpoint table |
| 03 · Software Catalog | Products, versions, host counts and per-asset installations |
| 04 · Vulnerability Intelligence | Advisories, CVSS/EPSS/KEV when present, severity overview |
| 05 · Affected Assets & Evidence | Individual CVE↔asset↔version matches, source evidence, trend |
| 06 · Pipeline Health & Coverage | Source collection status and unmapped-package visibility |
| 07 · Mapping Quality & Review | Coverage, review queue and audit, data-quality gaps and source freshness |

Only `reporting.*` views are exposed to the Metabase reporting user. **Metabase users can browse/report on data but cannot change assets** through this application. Metabase administrators can still edit Metabase's own charts and settings.

## Critical limitations

- **Not an endpoint scanner, not an EDR, not proof of vulnerability.** It correlates observed versions with *explicit*, machine-readable affected-version ranges and verified package identities. Distribution backports, flags and vendor-specific fixes can invalidate simplistic version matches.
- **Coverage is intentionally conservative.** Unmapped software is visible in the dashboard but isn't labeled vulnerable based on fuzzy name similarity. Add independently verified mappings; do not fabricate CPEs.
- **Current CVE ingest is bounded** to `cve.max_pages_per_poll` of the latest entries. It is *not* a complete historical advisory backfill. Older CVEs may be missed until a dedicated historical source/backfill is added.
- **cve.now schema may evolve.** Our parser only accepts recognizable structured `affected` / `affectedPackages` with `package.ecosystem`, `package.name`, OSV-style `versions` or `ranges`; other schemas remain in the advisory record but do not generate a positive match. Live response verification remains outstanding.
- **ManageEngine versions differ.** The connector targets modern On-Premises `/dcapi` endpoints: scanComputers and per-host softwareInfo. Pagination must be exercised against your exact deployment before production use. Cloud auth is not implemented.
- **Full-stack Docker testing was not possible in the generation environment.** Do not treat the preview as production-approved until your WSL end-to-end test passes.

See [installation](docs/INSTALLATION.md), [configuration](docs/CONFIGURATION.md), [security](docs/SECURITY.md) and [troubleshooting](docs/TROUBLESHOOTING.md).

## Source references

- [ManageEngine inventory scan computers](https://www.manageengine.com/products/desktop-central/help/api/onpremise/inventory-get-scan-computers-list.html)
- [ManageEngine per-computer software API](https://www.manageengine.com/products/desktop-central/help/api/onpremise/inventory-get-computer-software-info.html)
- [cve.now public API](https://cve.now/llms.txt)
- [Metabase first-run provisioning API](https://www.metabase.com/articles/set-up-metabase-from-code-with-the-api)

## License and warranty

Apache-2.0 source licensing (see LICENSE). This is independent tooling; it is not affiliated with ManageEngine, Metabase or cve.now. No warranty is provided.
