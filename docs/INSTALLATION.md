# Installation guide — from an empty machine to your first dashboard

**This guide assumes you have never installed AssetVuln Monitor.** Follow it top to bottom. Every command runs in a **Linux terminal** (Ubuntu 24.04, another compatible Linux distribution, or Ubuntu in WSL2), unless stated otherwise. Lines beginning with **#** inside code samples are explanations; you do not need to type them.

**Choose exactly one path:**
- **Part A — run the Demo:** try AVM with sample data and **no external credentials**.
- **Part B — connect real inventory (Live):** use your company's **Endpoint Central** server and a read-only API token.

> **Never use one installation for both modes.** The installer deliberately blocks switching Demo ↔ Live in the same project. Running V3 does not install over the original V1 or V2 when you follow the documented checkout/project names.

## 0. Before installing: what you need

| Requirement | Demo | Live |
|---|---|---|
| Linux / Ubuntu or WSL2 Ubuntu terminal | Yes | Yes |
| Docker Engine/Desktop running | Yes | Yes |
| Docker Compose v2 (**docker compose**, with a space) | Yes | Yes |
| Git, Python 3, OpenSSL | Yes | Yes |
| An internet connection for Docker image downloads | First setup | First setup |
| Endpoint Central on-premises HTTPS URL | No | Yes |
| Least-privilege Endpoint Central inventory API token | No | Yes |
| Connection to public vulnerability websites | No | Yes, for full intelligence |
| OSV / FIRST / CISA / EUVD API keys | No | No |
| NVD API key | No | Optional |

**A practical Demo host:** start with **at least 4 GiB of available memory**, sufficient free disk and a running Docker daemon. These are planning recommendations, not benchmarked minimums; Metabase requires Java memory. Allow time for the initial image downloads and build.

### 0.1 Identify your machine

Run:

~~~bash
cat /etc/os-release
uname -m
~~~

You should recognize your Linux distribution. The commands below show the Ubuntu path; for RHEL/Debian/Fedora use the [official Docker instructions for that distribution](https://docs.docker.com/engine/install/).

### 0.2 Check whether Docker is already working

Run these commands **as your normal Linux user**:

~~~bash
docker --version
docker compose version
docker info --format '{{.ServerVersion}}'
~~~

**Success:** the commands print a Docker version, a Compose version and a Docker server version. If they work, **skip Docker installation** and go to **0.4**.

**If Docker is not installed**, choose one of the following.

#### Option A — Windows 10/11 + WSL2 (recommended for a local Demo)

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/) using its official installer.
2. Start **Docker Desktop** on Windows.
3. In Docker Desktop settings, enable the **WSL 2 backend** and **WSL integration** for the Ubuntu distribution you intend to use. The labels can vary slightly by Docker Desktop version.
4. Open the Ubuntu terminal again, then repeat the three check commands above.
5. **Do not also install an independent Docker Engine inside the same WSL distribution** just to make the checks pass; first verify Docker Desktop integration.

#### Option B — new Ubuntu 24.04 host with no Docker installation

**Only use this on a fresh Ubuntu host.** If Docker packages are already installed, do not remove/replace them blindly: follow the official [Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/) procedure for your existing environment.

~~~bash
sudo apt update
sudo apt install -y ca-certificates curl git python3 openssl nano

sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker run --rm hello-world
~~~

The last command should report **Hello from Docker!**. The instructions above match Docker's official Ubuntu repository installation approach; refer to the linked Docker documentation if repository details change.

If you want to run Docker without typing sudo every time:

~~~bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info --format '{{.ServerVersion}}'
~~~

**Security warning:** membership in the **docker** group effectively grants root-level control of the Docker host. Only do this on a machine and user account you trust. If your security policy forbids this, use the Docker access method approved by your administrators.

### 0.3 Install the small command-line requirements

If Git, Python or OpenSSL is missing on Ubuntu:

~~~bash
sudo apt update
sudo apt install -y git python3 openssl nano
~~~

Verify:

~~~bash
git --version
python3 --version
openssl version
docker compose version
docker info --format '{{.ServerVersion}}'
~~~

**Stop here if any check fails.** The AVM installer will not repair a broken Docker installation or a missing Docker daemon.

### 0.4 Where will the files be stored?

Work under your own Linux home directory. This avoids most file-permission surprises.

~~~bash
mkdir -p "$HOME/projects"
cd "$HOME/projects"
pwd
~~~

The output will look like **/home/your-user/projects**. You can use another directory if you understand its permissions; do not copy files into the existing V1 checkout.

---

## Part A — run the Demo

**Goal:** run nine dashboards showing fictional assets and fictional vulnerabilities. No Endpoint Central server, API token or public feed is required.

### A1. Download the V3 branch

From the Linux terminal:

~~~bash
cd "$HOME/projects"
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03
cd assetvuln-monitor-v03
~~~

**Success:** your current directory contains an **install.sh** file. Confirm with:

~~~bash
ls -l install.sh
git branch --show-current
~~~

The branch command should return **develop/v0.3**. If Git says the directory already exists, do not overwrite it: either enter your existing V3 directory or choose a different new clone directory.

### A2. Start the Demo

~~~bash
./install.sh --demo
~~~

**You do not need to create .env, generate passwords, write YAML or install Python dependencies.** The installer handles those for Demo.

It will create a private **.env**, create Demo configuration and localhost TLS files, check that the Docker project cannot collide with V1/V2, start PostgreSQL, Worker, Metabase and NGINX, and run a temporary Metabase setup container.

**Success:** the installer prints **AssetVuln Monitor - installation finished**. Initial downloads and Metabase initialization can take time; do not interrupt a running install.

If it fails, **do not delete volumes or start again from scratch**. Copy the non-secret error text and use the [Troubleshooting guide](TROUBLESHOOTING.md).

### A3. Verify that the services started

~~~bash
docker compose ps
~~~

You should see four running services:

- **postgres** — application and dashboard data.
- **worker** — collection, correlation and scoring.
- **metabase** — the dashboard application.
- **nginx** — HTTPS gateway.

The one-time **bootstrap** container is not expected to remain running.

If something is unhealthy:

~~~bash
docker compose logs --tail=100 worker
docker compose logs --tail=100 metabase
docker compose logs --tail=100 postgres
~~~

These commands **read logs only** and do not change anything.

### A4. Open the web page and sign in

Open **https://localhost:8445** in a browser on the same computer. With Docker Desktop + WSL2, use the **Windows browser**. The default certificate is self-signed, so a browser warning is normal for this **local Demo only**.

Find the administrator credentials in the Linux terminal:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

Copy the values after the equals sign into Metabase's login page. **Never share the password output.**

You should find a collection named **AssetVuln Monitor · Security Workspace** with nine dashboards. If Metabase opens but the dashboards are missing, see [Troubleshooting](TROUBLESHOOTING.md#dashboard-or-metabase-problems).

### A5. Your first five checks

1. Open **01 · Security Command Center**: look at the fictional fleet summary.
2. Open **03 · Software Catalog**: see installed products and versions.
3. Open **05 · Affected Assets & Evidence**: inspect a synthetic host–version match.
4. Open **08 · Risk Intelligence & Remediation**: see priority, evidence and remediation candidates.
5. Open **09 · Source Intelligence & Coverage**: see which synthetic source reports each issue.

Demo advisories use **CVE-DEMO-*** identifiers. They are **not real-world CVEs**. There is no live scan, public-feed download or email notification in Demo.

Follow the illustrated architecture and field-by-field explanations in the [First-use and dashboard tour](USER-GUIDE.md).

### A6. Stop or return later, keeping all data

~~~bash
docker compose stop
~~~

To start again:

~~~bash
docker compose start
~~~

To read new logs:

~~~bash
docker compose logs --tail=100 worker
~~~

**Do not run docker compose down -v:** the **-v** flag removes the PostgreSQL volume and therefore destroys your local data.

---

## Part B — connect real inventory (Live)

**Goal:** deploy a *separate*, initially local-only V3 stack connected to real on-premises Endpoint Central inventory.

**You must have:** the Endpoint Central base HTTPS URL (for example **https://endpoint.example.org:8383**) and a token for an account restricted to **inventory read access**. Do not use a full administrator token. You also need network reachability from the Worker host to Endpoint Central, plus public HTTPS access for live intelligence.

### B1. Download a second copy, separate from Demo

~~~bash
cd "$HOME/projects"
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03-live
cd assetvuln-monitor-v03-live
~~~

**Important:** different directories alone are not enough. We will also give Live a **different Compose project name and HTTPS port**. Never point this checkout at V1, V2 or an existing Demo database volume.

### B2. Generate private credentials automatically

~~~bash
python3 scripts/prepare_env.py --mode live
~~~

**Success:** it prints **Private .env ready**. This creates secure, random *local* passwords and sets the Live-only mapping file. You will **not** need to make up five database passwords.

Open the file:

~~~bash
nano .env
~~~

Find/change these lines (keep other generated secrets unchanged):

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v03-live
BIND_IP=127.0.0.1
HTTPS_PORT=8446
PUBLIC_URL=https://localhost:8446
METABASE_ADMIN_EMAIL=your-admin-email@example.org
PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml
~~~

Replace the email with an account you control. These are **examples for an isolated installation**, not instructions to expose the service on the Internet. If port **8446** is already occupied, select another unused port and keep **HTTPS_PORT** and the port in **PUBLIC_URL** aligned.

**How to save in nano:** press **Ctrl+O**, press **Enter**, then **Ctrl+X**. Do not put passwords in Git commits or chat messages.

### B3. Create the application's configuration

~~~bash
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
~~~

Under the **application** section, set:

~~~yaml
application:
  mode: live
  timezone: UTC
~~~

Under **manageengine**, set your **actual HTTPS base URL**, without adding a path like /dcapi:

~~~yaml
manageengine:
  url: "https://endpoint.example.org:8383"
  token_file: /run/secrets/manageengine_token
  verify_tls: true
  ca_bundle: ""
  sync_minutes: 360
  max_assets: 10000
  max_pages: 500
~~~

You are editing only the values, not deleting the other sections (cve, vulnerability_sources, threat_intelligence, risk, matching or notifications).

**Crucial for large organizations:** **max_assets: 10000** is the initial **safety limit**, not a measured scalability limit. If Endpoint Central contains more than 10,000 computers, change this value **before installation** to a number that safely exceeds your approved fleet count, for example **max_assets: 120000** for a roughly 100,000-host deployment. Collection rejects data exceeding the limit rather than silently importing a truncated subset. Also review **max_pages** and API capacity with the Endpoint Central administrator; the collector currently retrieves software information per computer.

### B4. Store the Endpoint Central token securely

~~~bash
mkdir -p secrets/certs secrets/tls
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token
~~~

Paste **only the inventory-read token** into that file and save. The token must not be added to **.env**, application YAML, screenshots or public tickets.

### B5. If Endpoint Central uses your organization's private CA

**Skip this step if its TLS certificate already chains to a trusted CA.**

Copy the CA certificate from a *trusted administrative source* to:

~~~bash
cp /path/to/your-trusted-ca.pem secrets/certs/org-ca.pem
~~~

The command above contains a **placeholder path**. Replace it with the real location of your PEM file.

Then edit **config/application.yaml**:

~~~yaml
ca_bundle: "/opt/avm/certs/org-ca.pem"
~~~

For the independent host-side API test in the next step, use **--ca-bundle secrets/certs/org-ca.pem**. The two paths differ because one is **inside the container** and the other is **on the Linux host**.

Never set **verify_tls: false**.

### B6. Test Endpoint Central BEFORE deploying containers

With a publicly trusted certificate:

~~~bash
python3 scripts/test_manageengine_api.py
~~~

With the trusted organization CA from step B5:

~~~bash
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
~~~

Use **one** of those two commands.

**Success:** the script reports **[PASS] 1/2 scanComputers** and **[PASS] 2/2 softwareInfo**, plus a zero-failure summary. It makes **GET requests only** to the two Endpoint Central endpoints. It does not install anything, query vulnerability feeds or change managed systems.

**If it reports FAIL or SKIP:** stop and fix the URL, token, certificate, API permissions or resource ID **before installation**. For an empty inventory page, a known numeric Endpoint Central resource ID can be supplied:

~~~bash
python3 scripts/test_manageengine_api.py --resource-id 12345
~~~

Replace **12345** with an actual resource ID. A successful first-page test does **not** guarantee that the full fleet's pagination is compatible; verify it during staging.

### B7. Install the Live stack

~~~bash
./install.sh --live
~~~

The installer checks credentials, refuses a project/volume collision, checks the Live mapping file, starts the four containers and provisions Metabase. **You do not need to create the database, manually install pip packages or run SQL migrations.**

Verify:

~~~bash
docker compose ps
docker compose logs --tail=120 worker
~~~

**Success:** the Worker reports successful inventory synchronization and the four services are healthy. A container can be healthy even if a public feed is failing; check the Worker logs and source-health dashboard to assess data freshness.

### B8. Open the Live dashboard securely

If the browser is **on the same machine**, open **https://localhost:8446**.

If Docker is running on a **remote Linux server**, leave the default loopback-only binding in place and use an SSH tunnel **from your own workstation**:

~~~bash
ssh -L 8446:127.0.0.1:8446 your-user@your-server
~~~

Replace the user/server with your SSH details. Keep that terminal open and browse to **https://localhost:8446** on your workstation. Do not expose **BIND_IP=0.0.0.0** merely to make the browser connect.

Get the Live admin credentials from the **Live checkout** (not the Demo checkout):

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

The generated TLS certificate is still self-signed. **For a network-facing deployment**, install an organization-trusted certificate and configure access controls/reverse-proxy exposure with the security team first; the provided localhost certificate is not a production TLS solution.

### B9. Understand why Live can show zero Findings initially

This is intentional and important:

1. Endpoint Central assets and installed software appear in **02 / 03**.
2. The Live package identity mapping starts at **products: []**.
3. AVM will **not** invent a PyPI/npm/CPE identity from a similar-looking application name.
4. Until a trusted operator approves at least one matching package identity, the conservative engine may show **zero correlated Findings**.
5. Zero Findings is therefore **not evidence that the fleet is safe**.

**Here is the exact first-review flow.** Look at the product's **vendor** and **name** in dashboard **03 · Software Catalog**. Independently confirm its matching package **ecosystem** and **package name** from the provider's official advisory/package documentation.

Create a pending proposal (all quoted values below must be replaced with real verified values):

~~~bash
docker compose exec -T worker python -m avm.review_cli propose \
  --vendor "EXACT Vendor From Dashboard 03" \
  --name "EXACT Software From Dashboard 03" \
  --ecosystem "PyPI" \
  --package "verified-package-name" \
  --actor "analyst-1" \
  --evidence "Reviewed official package identity and upstream advisory"
~~~

**Success:** the command prints a numeric **review ID**. Inspect it:

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status pending
~~~

After independent verification, **a different reviewer** runs (replace **12** with the actual ID):

~~~bash
docker compose exec -T worker python -m avm.review_cli approve \
  --id 12 \
  --actor "reviewer-2" \
  --reason "Verified product, vendor and package identity independently"
~~~

**This writes only to AVM's local mapping-review tables**, not Endpoint Central. The approved mapping is applied at the **next successful inventory sync** (default every 360 minutes). For a small staging environment, an administrator can restart the Worker to trigger collection sooner:

~~~bash
docker compose restart worker
~~~

Restarting triggers a **new inventory collection**, which may generate many API requests on a large fleet. **Do not force it during a production peak.** Prefer the normal schedule and inspect:

~~~bash
docker compose logs --tail=120 worker
docker compose exec -T worker python -m avm.ops queue --limit 10
~~~

Actual findings depend on available, valid version evidence; mapping approval alone does not guarantee a CVE. For the full workflow including rejection and auditing, follow [Mapping Review](MAPPING-REVIEW.md).

### B10. Your first operational checklist

- [ ] **01 / 02 / 03** show plausible inventory counts and software versions.
- [ ] **06 / 07** show source health, unmapped software and the review queue.
- [ ] **09** shows which public providers were queried and their last successful sync.
- [ ] **08** ranks only potential findings supported by evidence; no automatic patching.
- [ ] Read-only Endpoint Central access, TLS trust and outgoing data sharing have been approved.
- [ ] Backups, admin access and retention requirements have been reviewed.

You can use the bundled backup command:

~~~bash
./scripts/backup.sh
~~~

This backs up the **AVM and Metabase PostgreSQL databases only**. Securely preserve your **.env**, **config/application.yaml**, approved mappings, token and certificates separately according to your organization's secrets policy. Do not put these files in Git.

---

## What did the installer create?

~~~mermaid
flowchart TD
    I["./install.sh --demo OR --live"] --> A["Private .env + application.yaml<br/>Generated passwords + mode isolation"]
    A --> T["Local TLS certificate<br/>only if missing"]
    T --> C["Docker Compose<br/>PostgreSQL + Worker + Metabase + NGINX"]
    C --> S["Worker initializes schema<br/>and reporting-only SQL views"]
    S --> B["One-time bootstrap<br/>Metabase login + nine dashboards"]
    B --> O["Open local HTTPS URL<br/>and verify data"]
~~~

| Path | Meaning | Should you edit it? |
|---|---|---|
| **.env** | passwords, Docker project, HTTPS port, admin login | Only for intentional configuration; never publish |
| **config/application.yaml** | Live inventory URL, source schedules, risk options | Yes, when necessary |
| **config/asset-context.yaml** | optional verified owner/criticality/exposure | Optional |
| **config/product-mappings.live.yaml** | initially empty reviewed Live catalogue | Prefer the review CLI; don't approve guesses |
| **secrets/manageengine_token** | least-privilege Endpoint Central token | Live only; secret |
| **secrets/tls/** | NGINX HTTPS cert/key | Replace for trusted network access |
| **secrets/certs/** | trusted CA files for Endpoint Central | Only for internal CA |
| **PostgreSQL Docker volume** | application records and Metabase metadata | **Never delete casually** |

## What to read next

- [Dashboard tour: your first 15 minutes](USER-GUIDE.md)
- [All operator commands and bundled scripts](COMMANDS.md)
- [Configuration reference](CONFIGURATION.md)
- [Troubleshooting, with exact commands](TROUBLESHOOTING.md)
- [Security checklist and known limitations](SECURITY.md)

**Release status:** V3 is still under development. Automated tests include an actual Docker **synthetic Demo**, but they do **not** certify real Endpoint Central APIs, every changing public feed, complete historic CVE coverage, or enterprise-scale performance. Validate Live in staging first.
