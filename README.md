# AssetVuln Monitor

**Read-only asset and vulnerability-intelligence dashboards, packaged entirely in Docker Compose.**

Endpoint Central ➜ PostgreSQL ➜ conservative CVE correlation ➜ automatically provisioned Metabase dashboards, behind NGINX HTTPS.

> **Status: v0.1 technical preview.** Demo fixtures and unit tests have been exercised, but a real Endpoint Central instance and Docker runtime were **not available** in the build environment. Production integrations must be validated against your actual build and the current cve.now response format before operational use.

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
git clone https://github.com/sysmrk/assetvuln-monitor.git
cd assetvuln-monitor
./install.sh --demo

# Check status and inspect logs:
docker compose ps
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
```

Open **https://localhost:8443**. The localhost TLS certificate is self-signed for demo use. The installer generates the Metabase password in `.env` and provisions six dashboards automatically. Demo records are synthetic, clearly labeled `CVE-DEMO-*`, and never fetched from ManageEngine.

### LIVE — real inventory (separate clean deployment)

**Never reuse a demo database for live assets:** demo data is not automatically removed. Use a fresh Docker project/volume, ideally on a separate host. **A separate directory alone is not sufficient:** the Compose file sets a fixed project name, so the default named volume would otherwise be shared.

```bash
# Recommended: execute on a fresh host with no existing AssetVuln Monitor Compose stack.
cd /opt
git clone https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-live
cd assetvuln-monitor-live
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
mkdir -p secrets/certs secrets/tls
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token config/application.yaml
nano config/product-mappings.yaml
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

Put **only the least-privilege, read-only inventory API token** in `secrets/manageengine_token` — not in YAML or Git. If using an internal CA, copy its PEM into `secrets/certs/org-ca.pem` and set the container CA path above. Use `config/product-mappings.yaml` only for verified software identities.

The installer generates a private `.env` containing `METABASE_ADMIN_EMAIL`, `METABASE_ADMIN_PASSWORD`, database passwords, `BIND_IP`, `HTTPS_PORT`, and `PUBLIC_URL`. Review these before exposing a live installation; replace demo TLS certificates with trusted ones. **Never commit `.env`, tokens or private keys.**

For **every command**, all optional fields, HTTPS configuration, backup/restore, and troubleshooting, read the [complete step-by-step installation guide](docs/INSTALLATION.md) and [configuration reference](docs/CONFIGURATION.md).

## Prebuilt dashboard catalog

| Dashboard | What it shows |
|---|---|
| 01 · Security Command Center | Total inventory, correlated exposure, severity and priority assets |
| 02 · Asset Explorer | Asset/OS/domain breakdown, searchable endpoint table |
| 03 · Software Catalog | Products, versions, host counts and per-asset installations |
| 04 · Vulnerability Intelligence | Advisories, CVSS/EPSS/KEV when present, severity overview |
| 05 · Affected Assets & Evidence | Individual CVE↔asset↔version matches, source evidence, trend |
| 06 · Pipeline Health & Coverage | Source collection status and unmapped-package visibility |

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
