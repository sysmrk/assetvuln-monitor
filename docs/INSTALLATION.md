# Installation and operations — Demo and Live

> **v0.1 technical preview.** Demo is suitable for WSL evaluation. Live mode is a read-only *integration preview*, not production-certified: the exact Endpoint Central on-prem API and cve.now structured affected-version responses have not been verified against a real deployment. Do not use matches as definitive vulnerability findings until integration and backport handling are validated.

## 0. Choose your mode

| | Demo / test | Live / production-data integration |
|---|---|---|
| Install command | `./install.sh --demo` | `./install.sh --live` |
| Inventory | 10 synthetic hosts | Endpoint Central on-prem inventory |
| Vulnerabilities | Synthetic CVE-DEMO records | Live cve.now feed (limited recent pages) |
| Matching | Enabled on synthetic records | Enabled, conservative / verified mappings only |
| ManageEngine token | Not required | Read-only inventory token required |
| Writes to managed assets | **Never** | **Never** |
| Metabase dashboards | Automatically provisioned | Automatically provisioned |
| Production approved | No; testing only | **Not yet; validate before production use** |

**Do not switch an existing demo database to live mode.** Synthetic demo records persist in the database. Use a separate fresh deployment/database for real inventory. **Warning:** this Compose file fixes the project name to `assetvuln-monitor`, so a separate checkout directory on the *same Docker daemon* does NOT isolate the named volume.

## 1. Prerequisites — Ubuntu 24.04 / WSL2

Open an Ubuntu terminal. Install Docker Engine if missing, or use Docker Desktop with WSL integration. If Docker Engine is already installed and `docker info` succeeds, **do not reinstall it**.

Check the environment (read-only):

```bash
cat /etc/os-release
docker --version
docker info --format '{{.ServerVersion}}'
docker compose version
git --version
openssl version
```

The project requires **Docker Compose v2**, invoked as `docker compose` (with a space). Legacy `docker-compose` v1 is not supported. On Ubuntu 24.04 with Docker already installed, add the Ubuntu Compose v2 package if necessary:

```bash
sudo apt update
sudo apt install -y docker-compose-v2 git openssl
docker compose version
docker info --format '{{.ServerVersion}}'
```

If `docker-compose-v2` is not available in your configured repositories, stop and check your Ubuntu/Docker package sources rather than replacing a working Docker Engine blindly. For Docker's official repository, the equivalent plugin package is typically `docker-compose-plugin`. Allow approximately 4 GB of memory for the stack.

## 2. DEMO — complete commands (no ManageEngine needed)

```bash
# Download the standalone repository:
cd /opt/src
git clone https://github.com/sysmrk/assetvuln-monitor.git
cd assetvuln-monitor
cp example.env .env
nano .env  # replace every CHANGE_ME_* with a unique strong secret

# Confirm runtime availability:
docker compose version
docker info --format '{{.ServerVersion}}'

# Build and start Docker services using your configured .env, create local TLS,
# populate synthetic data, and provision the Metabase dashboards:
./install.sh --demo

# Check containers and logs:
docker compose ps
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
docker compose logs --tail=100 nginx

# Show the configured Metabase login (do not paste passwords in tickets):
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
```

Open **https://localhost:8443** on the WSL host browser. The automatically generated localhost certificate is self-signed, so a browser warning is expected in the demo. The six dashboards are automatically provisioned by the bootstrap container. Synthetic advisories are labeled `CVE-DEMO-*` and are not real CVEs.

Useful operational commands:

```bash
docker compose ps                     # container status
docker compose logs -f worker         # follow ingestion/matching
docker compose logs -f metabase       # follow Metabase
docker compose stop                   # stop, keep persistent data
docker compose start                  # restart, keep persistent data
./scripts/backup.sh                   # backup PostgreSQL and Metabase data
./install.sh --demo                   # rerun idempotent setup
```

**Do not run `docker compose down -v` casually:** `-v` removes persistent volumes and destroys local application/Metabase data.

## 3. LIVE — real Endpoint Central integration (separate fresh installation)

Use a **separate Docker host/daemon** for the initial live deployment, or first implement and verify distinct Compose project/volume names. A separate directory on the same daemon is **not** sufficient with the current fixed Compose project name. Example on a fresh dedicated host:

```bash
sudo mkdir -p /opt/assetvuln-live
sudo chown "$(id -u):$(id -g)" /opt/assetvuln-live
cd /opt/assetvuln-live
git clone https://github.com/sysmrk/assetvuln-monitor.git
cd assetvuln-monitor
cp example.env .env
nano .env  # set unique passwords, real admin email, PUBLIC_URL and bind settings

# Create the runtime YAML from the documented template:
cp config/application.example.yaml config/application.yaml

# Edit runtime configuration:
nano config/application.yaml
```

Edit the following fields in `config/application.yaml` (use spaces, not tabs):

| YAML field | Example / required action |
|---|---|
| `application.mode` | `live` |
| `application.timezone` | `Asia/Tehran` or your actual timezone |
| `manageengine.url` | `"https://endpoint.example.org:8383"` — base URL only, **not** an API path |
| `manageengine.token_file` | Leave `/run/secrets/manageengine_token` |
| `manageengine.verify_tls` | Keep `true` |
| `manageengine.ca_bundle` | `""` for publicly trusted TLS, or `"/opt/avm/certs/org-ca.pem"` for internal CA |
| `manageengine.sync_minutes` | `360` (every 6 hours) |
| `manageengine.max_assets` | `10000` (adjust only after assessing inventory size) |
| `manageengine.max_pages` | `500` (pagination safety limit) |
| `cve.url` | `"https://cve.now"` (default) |
| `cve.sync_minutes` | `30` |
| `cve.max_pages_per_poll` | `5` (limited recent-page polling, **not full CVE history**) |
| `cve.request_timeout_seconds` | `30` |
| `matching.mappings_file` | Leave `/opt/avm/config/product-mappings.yaml` |
| `notifications.email_enabled` | `false` until SMTP has been reviewed and tested |

**Do not paste your API token into YAML or Git.** Create its separate local secret file:

```bash
mkdir -p secrets/certs secrets/tls
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token config/application.yaml
```

Paste **only** the read-only Endpoint Central API token into `secrets/manageengine_token`, save and close. Use an account restricted to inventory read access; no patch deployment, remote execution or administrator rights.

If Endpoint Central uses an internal certificate authority, copy the trusted CA PEM into `secrets/certs/org-ca.pem` and set `manageengine.ca_bundle` as shown above. Never set `verify_tls: false` to bypass certificate verification.

### Why product mappings differ between Demo and Live

`config/product-mappings.yaml` contains **two fake demo identities**, corresponding to the synthetic inventory and synthetic CVEs. They are not verified mappings for your organization. For Live, use the separate `config/product-mappings.live.yaml` (initially `products: []`) and set `PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml` in `.env`. The empty default means software is inventoried but no unverified CVE matches are generated.

For real findings, edit the live mapping file and add `vendor` and `name` **exactly as reported by Endpoint Central**, plus `ecosystem` and `package` **verified against the advisory**. Case is ignored for vendor/name, but fuzzy similarity is not used. Example of YAML **structure only** (not a valid preapproved mapping):

```yaml
products:
  - vendor: "Verified Vendor From Inventory"
    name: "Verified Product From Inventory"
    ecosystem: "PyPI"
    package: "verified-package-from-advisory"
```

Do not assume that desktop software shares the identity or affected versions of a similarly named npm/PyPI package. See [configuration reference](CONFIGURATION.md#software-identity-mappings).

### ManageEngine API preflight — run before Live install

After setting `manageengine.url` in `config/application.yaml` and adding the read-only token to `secrets/manageengine_token`, run:

```bash
python3 scripts/test_manageengine_api.py
# If needed, specify a known computer:
python3 scripts/test_manageengine_api.py --resource-id 12345
# For internal CA certificates:
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
```

The test **prints the two GET API paths** before running, then reports PASS/FAIL/SKIP, response time and first-page record counts. It runs without Docker or database, does not modify assets and never prints the token or full JSON. A PASS is a limited smoke test; it does not prove pagination and all field schemas are compatible. Investigate FAIL/SKIP before starting Live.



Start live mode **after the independent API test**:

```bash
./install.sh --live
docker compose ps
docker compose logs --tail=200 worker
docker compose logs --tail=200 metabase
```

For a network-facing deployment, configure `BIND_IP`, `HTTPS_PORT` and `PUBLIC_URL` in `.env` **before running the installer**; install a trusted certificate and matching private key at `secrets/tls/tls.crt` and `secrets/tls/tls.key` before starting. The default bind is loopback only. The default `BIND_IP=127.0.0.1` exposes HTTPS only on the local host. Restrict firewall access and validate Metabase authentication.

### Administrator-configured `.env` — fields and security

Create `.env` yourself with `cp example.env .env`, replace **all** `CHANGE_ME_*` placeholders with independent strong secrets (e.g. `openssl rand -hex 30`), and set `HOST_UID`/`HOST_GID` to the installing user's numeric IDs (`id -u`, `id -g`). The installer validates required credentials and never overwrites `.env`:

| Variable | Purpose |
|---|---|
| `HOST_UID` / `HOST_GID` | Host owner used by non-root worker to read mode-0600 secrets |
| `POSTGRES_PASSWORD` | Internal PostgreSQL administrator credential |
| `APP_DB_PASSWORD` | Application database credential |
| `REPORT_DB_PASSWORD` | Metabase read-only reporting connection credential |
| `MB_DB_PASSWORD` | Metabase application database credential |
| `METABASE_ADMIN_EMAIL` | Initial Metabase administrator email (set a real one before first bootstrap) |
| `METABASE_ADMIN_PASSWORD` | Initial Metabase administrator password |
| `BIND_IP` | Host bind IP; default `127.0.0.1` |
| `HTTPS_PORT` | External HTTPS port; default `8443` |
| `PUBLIC_URL` | User-facing URL; default `https://localhost:8443` |

**Changing database passwords after the first initialization does not automatically rotate PostgreSQL role passwords.** For existing installations, use a tested rotation procedure instead of blindly editing `.env`. Keep `.env`, API tokens, and private keys outside version control.

### Optional email alerts

In `config/application.yaml`, set `notifications.email_enabled: true`, then set `notifications.smtp_host`, `smtp_port`, `smtp_starttls`, `sender`, and `recipients`. Authentication uses `SMTP_USER` and `SMTP_PASSWORD` if supported by your deployment environment. Review SMTP credential injection before enabling in production; do not assume adding variables to `.env` alone wires them into every container.

## ManageEngine API smoke test — command reference

Run this **before** starting containers to verify that the current Endpoint Central deployment accepts the two API calls used by `avm/collectors.py`:

```bash
# Set manageengine.url in config/application.yaml first.
# Put the read-only API token in secrets/manageengine_token.
python3 scripts/test_manageengine_api.py
# Optional: python3 scripts/test_manageengine_api.py --resource-id 12345
# Optional custom CA: python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
```

The script lists the two GET endpoints at startup, validates JSON list shapes, prints PASS/FAIL/SKIP, and never prints the API token or full response. It does not write to ManageEngine, start Docker, or modify the database. Only page one and one selected computer are tested; successful output does not establish full pagination or field compatibility.

## 4. Verification and limitations

```bash
docker compose ps
docker compose logs --tail=150 worker
docker compose logs --tail=150 metabase
```

Demo success criteria: 10 synthetic assets, six dashboards, software installations and labeled `CVE-DEMO-*` records, without duplicate dashboards after a second install. Live success criteria: valid read-only API access, realistic inventory counts, verified pagination and software versions, successful advisory collection, and reviewed correlation evidence. A green container alone does **not** prove source compatibility.

**Current limitations:** on-premises Endpoint Central only (cloud API not implemented), limited cve.now recent polling (no complete historical backfill), conservative package identity matching, and no generic CPE/backport verification. Neither mode modifies any managed asset.

## 5. Backups and restoration

```bash
./scripts/backup.sh
# Review backup directory before recovery:
./scripts/restore.sh /path/to/backup-directory
```

Restore overwrites database contents and requires explicit confirmation. Test in staging first.
