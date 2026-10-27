# AssetVuln Monitor

**Read-only asset and vulnerability-intelligence dashboards, packaged entirely in Docker Compose.**

Endpoint Central ➜ PostgreSQL ➜ conservative CVE correlation ➜ automatically provisioned Metabase dashboards, behind NGINX HTTPS.

> **Status: v0.1 technical preview.** Demo fixtures and unit tests have been exercised, but a real Endpoint Central instance and Docker runtime were **not available** in the build environment. Production integrations must be validated against your actual build and the current cve.now response format before operational use.

## WSL / Windows quick start (no ManageEngine required)

Prerequisites: WSL2 Ubuntu, Docker Desktop with WSL integration (or Docker Engine with Compose v2), OpenSSL and Git. Allow approximately 4 GB of memory for the stack.

```bash
# Clone or download this repository, then:
cd assetvuln-monitor
./install.sh --demo
```

Open **https://localhost:8443** in your browser. The automatically generated certificate is self-signed; the browser will warn you in local demo mode. Log in with **admin@example.local** and the `METABASE_ADMIN_PASSWORD` in `.env`.

Your six dashboards and their saved questions are created **automatically**. No manual DB or Metabase setup is required. All demo CVEs are named `CVE-DEMO-*` and marked synthetic; they are **not real vulnerabilities**.

```bash
docker compose ps                   # health/status
docker compose logs -f worker       # data collection and matching
docker compose logs -f metabase     # dashboard troubleshooting
./scripts/backup.sh                 # database + dashboard backup
```

## Switch to real Endpoint Central

1. Edit `config/application.yaml`: set `application.mode: live`, and update `manageengine.url` with your **HTTPS** On-Premises URL (often port 8383).
2. Put an **Inventory.READ** token in `secrets/manageengine_token`, never in YAML or Git.
3. Use a trusted CA. For an internal CA, copy a PEM certificate to `secrets/certs/` and set `manageengine.ca_bundle: /opt/avm/certs/<filename>.pem`.
4. Review `config/product-mappings.yaml` to add **verified** package ecosystem identities. Ordinary desktop-software names often have no unambiguous OSV package identity.
5. Run `./install.sh --live` and inspect worker logs and the Pipeline Health dashboard.

**No write capabilities are implemented for Endpoint Central or endpoints.** The collector only issues GET requests; do not give it Admin credentials. The worker writes only to **its own local PostgreSQL database**, and bootstrap writes only **its own Metabase configuration**.

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
