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

**Do not switch an existing demo database to live mode.** Synthetic demo records persist in the database. Use a separate fresh deployment/database for real inventory.

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

# Confirm runtime availability:
docker compose version
docker info --format '{{.ServerVersion}}'

# Build and start Docker services, create local credentials and TLS,
# populate synthetic data, and provision the Metabase dashboards:
./install.sh --demo

# Check containers and logs:
docker compose ps
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
docker compose logs --tail=100 nginx

# Show the generated Metabase login (do not paste passwords in tickets):
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

Use a separate host or deployment directory **without demo volumes**. Example for a dedicated host:

```bash
sudo mkdir -p /opt/assetvuln-live
sudo chown "$(id -u):$(id -g)" /opt/assetvuln-live
cd /opt/assetvuln-live
git clone https://github.com/sysmrk/assetvuln-monitor.git
cd assetvuln-monitor

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

If you need additional **verified** package mappings:

```bash
nano config/product-mappings.yaml
```

Only map software to known ecosystem/package identifiers. A matching name alone is not sufficient evidence of vulnerability.

Start live mode:

```bash
./install.sh --live
docker compose ps
docker compose logs --tail=200 worker
docker compose logs --tail=200 metabase
```

For a network-facing deployment, **before exposing the service** edit `.env` after its first generation, set the correct `BIND_IP`, `HTTPS_PORT` and `PUBLIC_URL`, and install a trusted certificate and matching private key at `secrets/tls/tls.crt` and `secrets/tls/tls.key`. Rerun `./install.sh --live`. The default `BIND_IP=127.0.0.1` exposes HTTPS only on the local host. Restrict firewall access and validate Metabase authentication.

### Generated `.env` — fields and security

`./install.sh` generates `.env` on first run. Do **not** create sample passwords manually. Review/edit only as necessary:

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
