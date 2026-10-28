# V2 installation — clear instructions for Demo and Live

This guide is **only for develop/v0.2**. V2 is a development baseline that added verified mapping review and **seven Metabase dashboards**. The [V3 branch](https://github.com/sysmrk/assetvuln-monitor/tree/develop/v0.3) is the future product track with simpler automatic setup and more intelligence sources. **Do not run these V2 commands inside V1/main or V3 checkout directories.**

**V2 important difference:** unlike V3, the V2 installer **requires you to create .env and generate passwords yourself**. It also does not have V3's strong automatic Demo/Live reuse guard; you must use separate Docker projects/volumes.

## 0. Prerequisites — start here

You need Ubuntu/Linux (or WSL2 Ubuntu), Docker Engine/Desktop running, **Docker Compose v2**, Git, Python 3 and OpenSSL.

Open the Ubuntu/Linux terminal and run:

~~~bash
docker --version
docker compose version
docker info --format '{{.ServerVersion}}'
git --version
python3 --version
openssl version
~~~

**Success:** you see versions, including a **Docker server version**. If Docker is missing, follow its [official Ubuntu setup](https://docs.docker.com/engine/install/ubuntu/) or [Docker Desktop Windows installation](https://docs.docker.com/desktop/setup/install/windows-install/). For a step-by-step Ubuntu setup, see [V3's reusable prerequisite guide](https://github.com/sysmrk/assetvuln-monitor/blob/develop/v0.3/docs/INSTALLATION.md#0-before-installing-what-you-need).

**Do not reinstall an already working Docker Engine.** The supported command is **docker compose**, with a space, not legacy docker-compose.

## Part A — run the Demo

Demo is the safest way to see the platform. It uses **fictional assets and CVE-DEMO identifiers**; no Endpoint Central account or token is required.

### A1. Clone V2 into a dedicated directory

~~~bash
mkdir -p "$HOME/projects"
cd "$HOME/projects"
git clone --branch develop/v0.2 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v02
cd assetvuln-monitor-v02
git branch --show-current
~~~

**Expected:** develop/v0.2.

### A2. Create and fill private .env

~~~bash
cp example.env .env
id -u
id -g
nano .env
~~~

**Look at all five password lines**. V2 requires replacing the **CHANGE_ME_*** values with different random passwords. In another terminal, generate a random value:

~~~bash
openssl rand -hex 30
~~~

Copy the output **privately** into one of the five .env password fields, then repeat **five times**, using a different generated value for each:

- POSTGRES_PASSWORD
- APP_DB_PASSWORD
- REPORT_DB_PASSWORD
- MB_DB_PASSWORD
- METABASE_ADMIN_PASSWORD

If **id -u** or **id -g** from the previous step does not say **1000**, edit **HOST_UID** and **HOST_GID** to match your actual numeric output.

**Keep/verify** these exact Demo settings:

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v02
BIND_IP=127.0.0.1
HTTPS_PORT=8444
PUBLIC_URL=https://localhost:8444
PRODUCT_MAPPINGS_FILE=./config/product-mappings.yaml
~~~

Save in **nano** with **Ctrl+O**, Enter and **Ctrl+X**, then protect the file:

~~~bash
chmod 600 .env
~~~

**Do not share or commit .env.** A configured .env cannot be replaced by the example file after the database has initialized without risking broken authentication.

### A3. Start V2 Demo

~~~bash
./install.sh --demo
~~~

The installer checks Docker/credentials, creates local app YAML and localhost TLS if missing, starts PostgreSQL, Worker, Metabase and NGINX, and runs a temporary Bootstrap job to create the reporting connection and dashboards.

**Success:** you see the installation-finished message. If you get a setup/credential error, check that **every CHANGE_ME_*** was replaced and **.env** is valid. Do not delete the database volume to retry.

### A4. Verify and sign in

~~~bash
docker compose ps
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
~~~

Expected: **postgres**, **worker**, **metabase** and **nginx** running. The one-shot bootstrap container need not keep running.

Open **https://localhost:8444** on the same computer. The self-signed localhost certificate warning is expected for this local test. Find your own login credentials:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

Log in to Metabase and find the **AssetVuln Monitor · Security Workspace** collection. V2 provides **seven dashboards**, numbered 01–07.

### A5. Stop and restart without losing data

~~~bash
docker compose stop
docker compose start
~~~

**Do not run docker compose down -v**. The flag removes the Docker named volume with application and Metabase databases.

---

## Part B — connect real inventory (Live)

**Do not change the existing V2 Demo to Live in place.** Create a new checkout, new **COMPOSE_PROJECT_NAME**, new port and a fresh Docker volume. V2 does **not** automatically prevent mode reuse the way V3 does.

### B1. Create a new isolated checkout

~~~bash
cd "$HOME/projects"
git clone --branch develop/v0.2 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v02-live
cd assetvuln-monitor-v02-live
cp example.env .env
nano .env
~~~

Replace **all five CHANGE_ME_*** placeholders with **five different random passwords** (use **openssl rand -hex 30** as in Demo A2). Set **HOST_UID/HOST_GID** from **id -u** and **id -g**.

**Choose a new project and port, separate from the V2 Demo and V1/V3:**

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v02-live
BIND_IP=127.0.0.1
HTTPS_PORT=8454
PUBLIC_URL=https://localhost:8454
PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml
METABASE_ADMIN_EMAIL=admin@your-company.example
~~~

Change the email to your own, then:

~~~bash
chmod 600 .env
~~~

### B2. Set the real Endpoint Central URL

~~~bash
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
~~~

Change only the existing **application.mode** and **manageengine.url** values:

~~~yaml
application:
  mode: live
  timezone: UTC

manageengine:
  url: "https://endpoint.your-company.example:8383"
  token_file: /run/secrets/manageengine_token
  verify_tls: true
  ca_bundle: ""
  sync_minutes: 360
  max_assets: 10000
  max_pages: 500
~~~

The URL above is a **placeholder**. Insert your actual Endpoint Central on-premises **HTTPS base URL without /dcapi**. Keep the other existing YAML sections.

**Important for larger organizations:** if more than 10,000 assets are approved for inventory, increase **max_assets** first; it is a hard safety cap. Adjust pagination only with verified Endpoint Central API behavior.

### B3. Store the read-only API token

~~~bash
mkdir -p secrets/certs secrets/tls
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token
~~~

Paste only your company's **least-privilege inventory read token** into the file. Never use an Endpoint Central administrator token if read-only access is possible. Never put the token in application.yaml, a screenshot or Git.

If Endpoint Central uses an internal CA, copy the CA certificate to **secrets/certs/org-ca.pem** and set **manageengine.ca_bundle** to **"/opt/avm/certs/org-ca.pem"** inside the YAML. Do not turn TLS verification off.

### B4. Test the real API before installing

For publicly trusted TLS:

~~~bash
python3 scripts/test_manageengine_api.py
~~~

For your own internal CA:

~~~bash
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
~~~

**Expected:** both **scanComputers** and **softwareInfo** report **PASS**. The script sends GET requests only, and does not modify assets. If it fails, fix access/certificate/schema first; the test does not guarantee all pages of a large inventory work.

### B5. Install and open Live

~~~bash
./install.sh --live
docker compose ps
docker compose logs --tail=120 worker
~~~

On the same machine, open **https://localhost:8454**. Use the Metabase credentials from the **Live checkout's** private .env.

**If Live shows assets but zero Findings, that is not automatically an error.** The approved Live mapping catalogue starts empty to avoid guessing package identities. You must verify a product and approve its mapping before a structured CVE/version match can generate a Finding.

Read [Mapping Review](MAPPING-REVIEW.md) for the proposal and approval steps. V2 only uses **cve.now** for advisory ingestion; V3 has additional OSV/NVD/EUVD/FIRST/CISA sources.

---

## 3. What gets installed?

~~~mermaid
flowchart LR
    EC["Endpoint Central<br/>GET-only"] --> W["V2 Worker"]
    C["cve.now"] --> W
    W --> DB[("PostgreSQL<br/>inventory, mapping audit, evidence")]
    DB --> M["Metabase<br/>seven dashboards"]
    M --> N["NGINX HTTPS<br/>localhost"]
~~~

| Container | Purpose |
|---|---|
| postgres | Stores the AVM and Metabase databases |
| worker | Reads inventory + cve.now, correlates approved software identities |
| metabase | Dashboards / read-only report views |
| nginx | HTTPS entry point |
| bootstrap (temporary) | Creates Metabase account/reports and then exits |

## 4. What do the seven dashboards show?

| Dashboard | What to check |
|---|---|
| 01 Security Command Center | Fleet counts and potential matches |
| 02 Asset Explorer | Host, OS, domain and freshness |
| 03 Software Catalog | Product/vendor/version; unmapped identities |
| 04 Vulnerability Intelligence | Received cve.now advisory catalogue |
| 05 Affected Assets & Evidence | Structured potential CVE-to-host matches |
| 06 Pipeline Health & Coverage | Sync failures and missing data |
| 07 Mapping Quality & Review | Coverage, pending proposal and decision audit |

No dashboard is a patching or exploit-execution interface. Metabase queries AVM's **read-only reporting schema**.

## 5. Your daily commands

**Run from the V2 checkout you intend to manage:**

~~~bash
docker compose ps
docker compose logs --tail=100 worker
docker compose exec -T worker python -m avm.review_cli list --status pending
./scripts/backup.sh
docker compose stop
docker compose start
~~~

**Mapping workflow:** find exact product/vendor in dashboard 03, verify the authoritative package identity, manually propose it and have a separate reviewer approve it. Example propose command (all strings are placeholders):

~~~bash
docker compose exec -T worker python -m avm.review_cli propose \
  --vendor "Exact Vendor" --name "Exact Software" \
  --ecosystem "PyPI" --package "verified-package" \
  --actor "analyst-1" \
  --evidence "Verified official package identity"
~~~

Use the returned ID, e.g. **12**:

~~~bash
docker compose exec -T worker python -m avm.review_cli approve \
  --id 12 --actor "reviewer-2" \
  --reason "Independent validation of exact vendor and package identity"
~~~

Approved mappings take effect at the next successful inventory synchronization. The CLI updates **only local AVM DB tables**, never Endpoint Central.

## 6. Backups, isolation and remaining limitations

~~~bash
./scripts/backup.sh
docker compose config --quiet
~~~

**Backup script stores AVM and Metabase PostgreSQL dumps only**. Securely back up local .env, token, private YAML and TLS certs separately. Restore is destructive and requires explicit confirmation; practice in staging before use.

V2 defaults to **assetvuln-monitor-v02** and HTTPS **8444**. V1/main has a different Compose identity and V3 uses its own. [V2 isolation details](V02-ISOLATION.md) describe how to check independent Docker resources before running both versions.

**Current limitations:** only on-premises Endpoint Central API is targeted; cve.now polling covers bounded recent pages, not an entire historical CVE archive; CPE/backport auto-validation is unsupported; software mapping decisions have self-reported actor identifiers without SSO; live corporate integration and a full Docker smoke test for the V2 branch are not verified.

If the goal is to **evaluate the newer, easier product**, use [V3's guided installation](https://github.com/sysmrk/assetvuln-monitor/blob/develop/v0.3/docs/INSTALLATION.md).
