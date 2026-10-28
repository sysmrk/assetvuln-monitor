# Configuration guide — what to edit, where, and why

**Good news:** a new **Demo requires no configuration at all**. The installer creates everything it needs. Only start editing configuration when you move to **Live**, need a different HTTPS port, or want to supply verified business context.

[Beginner installation guide](INSTALLATION.md) · [All operator commands](COMMANDS.md) · [Troubleshooting](TROUBLESHOOTING.md)

## 1. There are only three files most operators need to know

| File | In plain English | Typical change |
|---|---|---|
| **.env** | Settings Docker needs: project name, web port, passwords, admin email | Live's unique name/port or admin email |
| **config/application.yaml** | What the Worker does: Endpoint Central URL, scheduling, source and risk settings | Set Live URL and fleet-size safety cap |
| **secrets/manageengine_token** | The inventory-only Endpoint Central token | Put token inside **only for Live** |

Two optional files are explained later: **config/asset-context.yaml** (verified asset importance) and **config/product-mappings.live.yaml** (trusted package identities; prefer the review CLI).

**Important:** .env is **not** a script you should execute or source. Never use **source .env**. The installer/Compose read it as data.

### Where to run commands

First open a terminal and enter your checkout:

~~~bash
cd "$HOME/projects/assetvuln-monitor-v03"
~~~

For Live, use your separate **assetvuln-monitor-v03-live** directory. If your clone is elsewhere, enter that directory instead. Confirm:

~~~bash
pwd
git branch --show-current
~~~

Expected branch: **develop/v0.3**.

## 2. The private .env file

### Demo: let the installer create it

~~~bash
./install.sh --demo
~~~

### Live: generate it before editing

~~~bash
python3 scripts/prepare_env.py --mode live
nano .env
~~~

The generator keeps values that already exist. If a password is missing or still a **CHANGE_ME_*** placeholder, it creates a different random password for that field. **It does not rotate passwords on an already initialized database.**

Main settings:

| Key | Default / example | Meaning |
|---|---|---|
| **COMPOSE_PROJECT_NAME** | assetvuln-monitor-v03 | Names Docker resources; keep each installation separate |
| **BIND_IP** | 127.0.0.1 | Only this host can access the published HTTPS port by default |
| **HTTPS_PORT** | 8445 | Port of NGINX on the Docker host |
| **PUBLIC_URL** | https://localhost:8445 | Browser-facing URL Metabase uses |
| **METABASE_ADMIN_EMAIL** | admin@example.local | Initial Metabase admin identity; replace for Live |
| **METABASE_ADMIN_PASSWORD** | generated | Initial Metabase admin password |
| **POSTGRES_PASSWORD** | generated | PostgreSQL administrator password |
| **APP_DB_PASSWORD** | generated | AVM Writer database account password |
| **REPORT_DB_PASSWORD** | generated | Read-only Metabase reporting account password |
| **MB_DB_PASSWORD** | generated | Metabase's own application database password |
| **HOST_UID / HOST_GID** | resolved from installer user | Allow the non-root Worker to read its mounted config/token |
| **PRODUCT_MAPPINGS_FILE** | Demo YAML; Live YAML selected by generator | Keeps synthetic identities out of Live |
| **NVD_API_KEY** | empty | Optional NVD API capacity increase; no mandatory API keys |
| **PIP_INDEX_URL** | https://pypi.org/simple | Optional trusted Python package index used only during image build |

### Running Demo and Live on one host

The following are **examples**, not required if you only use one installation:

| | Demo | Live |
|---|---|---|
| Working directory | assetvuln-monitor-v03 | assetvuln-monitor-v03-live |
| COMPOSE_PROJECT_NAME | assetvuln-monitor-v03 | assetvuln-monitor-v03-live |
| HTTPS_PORT | 8445 | 8446 |
| PUBLIC_URL | https://localhost:8445 | https://localhost:8446 |
| PRODUCT_MAPPINGS_FILE | ./config/product-mappings.yaml | ./config/product-mappings.live.yaml |

**Never point two deployments at the same Compose project/volume.** Changing COMPOSE_PROJECT_NAME on an existing populated instance may make its original data appear missing. The installer also refuses V1/V2 default project names.

### Changing the web port

For example, if **8445** is occupied, open the private file:

~~~bash
nano .env
~~~

Change both port settings consistently:

~~~dotenv
HTTPS_PORT=8455
PUBLIC_URL=https://localhost:8455
~~~

Save (**Ctrl+O**, Enter, **Ctrl+X**), then apply the configuration **in that project's checkout**:

~~~bash
docker compose up -d nginx
~~~

Reopening the same localhost URL with the new port may require waiting for the NGINX container to restart. Keep **BIND_IP=127.0.0.1** for evaluation.

**Do not edit .env to change the existing PostgreSQL passwords**: Docker's initialization script only runs on the first creation of a fresh database volume. Changing .env alone does not rotate stored database passwords and can break startup.

## 3. The Worker configuration: config/application.yaml

Create this file only if it does not exist:

~~~bash
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
~~~

The installer also creates it automatically if missing. Edit values **after the colon** and keep YAML indentation as **spaces**, not tabs. Do not delete unrelated sections.

### Application

~~~yaml
application:
  mode: demo
  timezone: UTC
~~~

- **demo** = fabricated inventory/advisories without external connections.
- **live** = actual Endpoint Central and public data sources.
- **timezone** is a configuration field; the current event timestamps are stored in UTC. Do not assume changing this setting converts all database timestamps.

**Never switch an existing Demo database to Live.** Use a new checkout and a new Compose project/volume.

### Endpoint Central / ManageEngine

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

| Key | Meaning and safe behavior |
|---|---|
| **url** | Your actual on-premises Endpoint Central **base URL**, HTTPS required; do not append /dcapi |
| **token_file** | Path **inside Worker container**, normally unchanged |
| **verify_tls** | Must remain true in Live |
| **ca_bundle** | Optional *container* path such as /opt/avm/certs/org-ca.pem |
| **sync_minutes** | Inventory scheduling: default **360 minutes** (6 hours) |
| **max_assets** | Hard safety cap: **10,000** by default; increase before a larger fleet |
| **max_pages** | Hard pagination safety cap: **500** by default |

**Example for an organization with roughly 100,000 assets:** set **max_assets: 120000** after confirming permitted load and performance. A higher cap does **not** automatically improve Endpoint Central API throughput: the current collector reads per-computer software information, so very large fleets need a staged load test.

When setting an internal CA:
1. Obtain its PEM from a trusted internal source.
2. Place it at **secrets/certs/org-ca.pem** on the host.
3. Set **ca_bundle: "/opt/avm/certs/org-ca.pem"** in YAML.
4. Test on the **host** with **python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem**.

Host and container certificate paths are intentionally different. Never disable TLS checks.

### Public intelligence source schedules

The default source settings are already in **config/application.example.yaml** and are copied to your private application YAML on first install:

| Source | Setting | Default | Behavior |
|---|---|---|---|
| **cve.now** | cve.sync_minutes | 30 | Receives a bounded number of recent advisory pages |
| **OSV.dev** | vulnerability_sources.osv.sync_minutes | 20 | Checks approved unique package/version tuples |
| **OSV.dev** | vulnerability_sources.osv.cache_hours | 24 | Re-checks both positive and negative cache entries after expiry |
| **OSV.dev** | vulnerability_sources.osv.batch_size | 50 | Requested unique package/version combinations per batch |
| **OSV.dev** | vulnerability_sources.osv.max_batches_per_cycle | 4 | Bounded work per Worker cycle |
| **NVD 2.0** | vulnerability_sources.nvd.sync_minutes | 120 | Recent modified CVE metadata |
| **NVD 2.0** | vulnerability_sources.nvd.max_pages_per_cycle | 2 | Bounded page budget |
| **EUVD** | vulnerability_sources.euvd.sync_minutes | 240 | Recent dated ENISA metadata |
| **EUVD** | vulnerability_sources.euvd.max_pages_per_cycle | 3 | Bounded page budget |
| **NVD/EUVD** | *.pending_sync_minutes | 10 | Resume a large paginated window sooner |
| **CISA KEV** | threat_intelligence.sync_hours | 24 | Official list of known exploited vulnerabilities |
| **FIRST EPSS** | threat_intelligence.sync_hours | 24 | Official compressed daily CSV; only known CVEs updated |

By default **OSV, NVD and EUVD are enabled in Live** and disabled as network operations in Demo. These schedules are **local polling intervals**, not guarantees of publisher freshness.

**To disable an external source** in a restricted network, for example EUVD:

~~~yaml
vulnerability_sources:
  euvd:
    enabled: false
    sync_minutes: 240
    max_pages_per_cycle: 3
    page_size: 100
    pending_sync_minutes: 10
~~~

Do **not** replace the whole **vulnerability_sources** section with only this fragment: keep the existing OSV and NVD settings too.

**Source roles matter:**
- **OSV + cve.now** can generate potential findings when version evidence matches an approved identity.
- **NVD + EUVD** add metadata, CVSS and aliases; no unsupported CPE/free-text exposure claim.
- **FIRST EPSS + CISA KEV** adjust priority, not whether an installed version is affected.

For exact provenance and source conflicts, read [Multi-source intelligence](V03-MULTISOURCE.md).

### Risk score and local SLA defaults

~~~yaml
risk:
  sla_days:
    P1: 7
    P2: 30
    P3: 90
    P4: 180
~~~

These are *internal configurable targets*, not guarantees or legal compliance requirements.

The score adds up to 100 modeled points:

| Factor | Maximum points |
|---|---:|
| CVSS 0–10 (normalized) | 40 |
| FIRST EPSS (square-root weighting) | 20 |
| Verified CISA KEV signal | 25 |
| Explicit asset criticality | 10 |
| Explicit Internet exposure | 5 |

When a confirmed CISA KEV advisory is linked to a *potential affected-version finding*, the modeled priority is at least **75 (P1)**. Missing signals remain **unknown**. The score is **not** a percentage chance of compromise.

### Notifications

~~~yaml
notifications:
  email_enabled: false
~~~

This is **off by default**. SMTP STARTTLS is required by the code if sending is enabled, and a production notification path requires independently validated SMTP routing, credentials and recipient handling. Do not assume putting SMTP_USER/SMTP_PASSWORD into .env alone configures authenticated SMTP: the Compose Worker environment must also supply them. Leave this disabled until configured and tested by your operations team. Demo never sends emails.

## 4. Asset business context — optional

The installer creates **config/asset-context.yaml** with an empty list. You can leave it empty; the platform still works.

If you have **verified** asset source IDs and ownership:

~~~bash
nano config/asset-context.yaml
~~~

Example (all values are illustrative):

~~~yaml
assets:
  - source_id: "12345"
    criticality: critical
    internet_facing: true
    business_service: "Payment API"
    owner: "Platform Team"
~~~

- **source_id** is the stable resource ID from Endpoint Central, **not** a guessed host number.
- **criticality** accepts: unknown, low, medium, high, critical.
- **internet_facing** accepts: true, false or null (unknown).
- **owner** and **business_service** are optional labels.

**Never infer Internet exposure from a private IP, hostname or DNS suffix alone.** Unspecified assets stay unknown. This file is read at the next successful inventory synchronization.

## 5. Software package mappings — how to avoid wrong Findings

Demo includes fictional mappings. Live starts with:

~~~yaml
products: []
~~~

That means **all discovered software is still visible** in inventory, but no unsupported CVE-to-package correlation is created.

For most operators, prefer [Mapping Review CLI](MAPPING-REVIEW.md) over manually editing YAML. A manual approval is audited and applied at the next inventory sync. This is not automatic fuzzy matching.

**Do not edit the synthetic config/product-mappings.yaml for Live.** The installer specifically requires **PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml** for Live and rejects the Demo file.

## 6. Apply changes and confirm

| What changed? | How to apply | Important side effect |
|---|---|---|
| application.yaml (Worker options) | **docker compose restart worker** | Starts a fresh collection cycle |
| asset-context.yaml | Wait for next inventory sync or restart Worker in staging | Applies only to verified source IDs |
| mapping approval in local DB | Wait for next inventory sync | Fuzzy candidates remain unapproved |
| HTTPS port/BIND_IP (.env) | **docker compose up -d nginx** | Recreates/restarts gateway as needed |
| NVD_API_KEY (.env) | **docker compose up -d worker** | Recreates Worker with new environment |
| First Metabase setup/dashboards | Installer handles it; otherwise **docker compose --profile setup run --rm bootstrap** | Creates missing Metabase artifacts |
| Existing database credentials | **Not supported by editing .env alone** | Requires planned credential rotation procedure |

After any change:

~~~bash
docker compose ps
docker compose logs --tail=100 worker
~~~

For changes that trigger a new large inventory collection, schedule them according to your Endpoint Central API capacity rather than restarting the Worker during peak hours.

## 7. Keep the private files private

The project ignores **.env**, private application YAML, token/cert directories, asset-context YAML and backups in Git. **config/product-mappings.live.yaml is a tracked template**; real custom mappings should be handled carefully and never accidentally committed if they reveal internal software inventory.

Before sharing any logs, CSV or screenshots, remove company hostnames/IPs, tokens, credentials and software inventory details.

For deployment decisions beyond localhost, read [Security model](SECURITY.md) and [Troubleshooting](TROUBLESHOOTING.md).
