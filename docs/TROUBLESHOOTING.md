# Troubleshooting — symptom → command → what to do

**Do not wipe your data to fix a dashboard.** Almost every first-install problem can be investigated using read-only status and log commands.

This guide is for **V3**. Start in **the checkout you actually installed** (Demo or Live), not in the V1/V2 directories.

~~~bash
pwd
git branch --show-current
docker compose ps
~~~

Expected branch: **develop/v0.3**.

## The three safe diagnostic commands

Run these first:

~~~bash
docker compose ps
docker compose logs --tail=120 worker
docker compose logs --tail=120 metabase
~~~

- **docker compose ps**: shows which services started or stopped.
- **Worker logs**: show inventory, mapping, public feed and correlation results.
- **Metabase logs**: show dashboard/UI startup.

**All three are read-only.** Logs can expose organizational hostnames or software names; redact them before sharing.

## 1. Installation and Docker problems

### "docker: command not found" / "docker compose: not found"

**Meaning:** Docker Engine/Desktop or Compose v2 is missing, or the Ubuntu terminal is not integrated with Docker Desktop.

**Do this:** follow [Prerequisites — Docker installation](INSTALLATION.md#0-before-installing-what-you-need). Do not delete an existing Docker Engine installation just to install the Compose plugin.

~~~bash
docker --version
docker compose version
~~~

**Expected:** both print a version number. V3 requires **docker compose** (space), not legacy **docker-compose**.

### "Cannot connect to the Docker daemon" or permission denied

~~~bash
docker info --format '{{.ServerVersion}}'
~~~

**Expected:** the Docker server version. If Docker Desktop is used, make sure it is running and WSL integration is enabled. On native Ubuntu, check the Docker service:

~~~bash
sudo systemctl status docker
~~~

If you are explicitly authorized to manage the service:

~~~bash
sudo systemctl start docker
~~~

If you need group-based Docker access, read [the security warning](INSTALLATION.md#0-before-installing-what-you-need): the **docker** group has root-equivalent power.

### "port is already allocated" / cannot bind HTTPS 8445

**Meaning:** another process already uses the port. V1/V2/V3 must not share a published port.

Open your own project's private file:

~~~bash
nano .env
~~~

Change **both** lines (example):

~~~dotenv
HTTPS_PORT=8455
PUBLIC_URL=https://localhost:8455
~~~

Save with **Ctrl+O**, Enter, **Ctrl+X**. If installation has not completed, rerun the original install command **in the same mode**. For an already running stack:

~~~bash
docker compose up -d nginx
docker compose ps
~~~

Then browse to the new URL. Do **not** change COMPOSE_PROJECT_NAME on a populated installation just to fix a port.

### Installer says "existing PostgreSQL volume" / "cannot switch Demo and Live"

**This is a safety feature.** V3 refuses to join an existing unidentified Docker volume or use a Demo database as Live.

**Correct fix:** use a **new checkout**, **unique COMPOSE_PROJECT_NAME**, **different HTTPS port** and **new database volume**, as in [Live Step B1/B2](INSTALLATION.md#part-b--connect-real-inventory-live).

**Do not** delete, rename, attach or manually replace an existing volume to silence the error.

### A container reports "unhealthy" or restarts

~~~bash
docker compose ps
docker compose logs --tail=120 postgres
docker compose logs --tail=120 worker
docker compose logs --tail=120 metabase
docker compose logs --tail=120 nginx
~~~

Read the first clear error:
- **PostgreSQL unhealthy** → database initialization/volume issue; preserve the volume.
- **Worker unhealthy** → database credentials/schema/config; check its logs.
- **Metabase unhealthy** → dashboard app initialization, resource shortage or its DB.
- **NGINX unhealthy/not running** → TLS cert or Metabase dependency/startup.

**Do not run docker compose down -v** to make a health check green. Back up first and investigate.

## 2. Dashboard or Metabase problems

### Browser does not load

1. Read the port from your own private **.env**:

~~~bash
grep -E '^(BIND_IP|HTTPS_PORT|PUBLIC_URL)=' .env
docker compose ps
~~~

2. Open the **PUBLIC_URL** on the correct host. By default, Docker binds HTTPS to **127.0.0.1**, so a **remote workstation cannot open it directly**. Use SSH tunneling as shown in the [Live guide](INSTALLATION.md#b8-open-the-live-dashboard-securely).
3. On the local Demo host only, check gateway health with its default port:

~~~bash
curl --insecure --fail --silent --show-error https://127.0.0.1:8445/api/health
~~~

For Live, change the example port to your configured HTTPS_PORT. **--insecure** is acceptable only to diagnose the default, deliberately self-signed local certificate; do not bypass TLS verification for real remote services.

### Browser displays a certificate warning

The installer creates a **localhost self-signed certificate** if none exists. It is expected in the **local Demo**. For corporate or shared-network use, install a valid certificate issued by a trusted internal/public CA and restrict access appropriately. Do not teach users to ignore remote TLS warnings.

### I do not know the login password

From the **correct project directory**, on a private terminal:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

These are the values initially provisioned on the first Metabase setup. **If the administrator password was later changed in Metabase**, the old .env value may no longer work; do **not** reset the database just to regain access. Follow your approved Metabase account-recovery procedure.

### Metabase loads but dashboards/collection are missing

First inspect:

~~~bash
docker compose logs --tail=150 worker
docker compose logs --tail=150 metabase
~~~

If Worker/database initialization has completed, re-run the **one-time provisioning job**:

~~~bash
docker compose --profile setup run --rm bootstrap
~~~

**Expected:** logs reporting dashboard IDs and a bootstrap-complete message. This **writes Metabase metadata**, not endpoint data.

**Important:** the bootstrap creates missing cards/dashboards, but existing customized saved questions may not automatically get their SQL replaced. Review existing dashboards after upgrades.

### A newly installed dashboard shows blank cards

- Check **02 / 03** for inventory, **06** for ingestion health, and **07** for mapping coverage.
- In **Demo**, there should be fictional sample data.
- In **Live**, mappings start empty; zero matching Findings can be normal.
- Check for SQL view/migration failures in **worker** logs before treating the data as empty.

A blank chart is not proof that no vulnerabilities exist.

## 3. No inventory or no Findings

### Endpoint Central not collecting Live assets

First run the **independent host-side GET-only preflight**:

~~~bash
python3 scripts/test_manageengine_api.py
~~~

For an internal company CA:

~~~bash
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
~~~

**Expected:** both **scanComputers** and **softwareInfo** print **PASS**. If not, verify the HTTPS base URL, inventory token, account scope, CA certificate and actual on-premises API version.

Then inspect the collection log:

~~~bash
docker compose logs --tail=200 worker
~~~

This source's pagination and response keys can differ across Endpoint Central versions; a first-page smoke test alone does not validate every asset.

### "Asset cap exceeded" or "Inventory page cap reached"

The default **manageengine.max_assets: 10000** and **max_pages: 500** are *protective limits*. An unusually large fleet or unexpected pagination can hit them.

Open:

~~~bash
nano config/application.yaml
~~~

Adjust **max_assets** to safely exceed your verified asset count and **max_pages** only after reviewing API behavior and load. Then apply at an approved time:

~~~bash
docker compose restart worker
docker compose logs --tail=200 worker
~~~

**Do not simply set unlimited values.** A failed/truncated full scan must not be silently accepted as a complete inventory.

### Assets appear, but there are no Findings

This is **the most common Live question**.

1. Open dashboard **03**. Does the affected software have a populated **ecosystem** and **package_name**?
2. Open dashboard **07**. Are many products **unmapped**? If so, use [Mapping Review](MAPPING-REVIEW.md) to propose/approve a verified package identity.
3. Wait for the next successful inventory sync.
4. Open dashboard **09**. Does OSV have completed package/version checks? Are source synchronizations healthy?
5. Only then examine **05 / 08** for version-specific evidence.

A fresh Live installation has an **empty approved mapping list by design**. No mapping → no unsupported software-level findings. Even with mappings, a given product/version might not appear in the currently available advisory coverage.

### "Approved mapping not applied"

The mapping review CLI changes the AVM approval tables. **The Worker incorporates approved mappings on the next inventory sync**, not immediately after the approval.

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status approved
docker compose logs --tail=120 worker
~~~

For a small authorized staging environment only, restart the Worker to trigger a new inventory read:

~~~bash
docker compose restart worker
~~~

Do not repeatedly restart a Worker serving a very large fleet.

## 4. Public vulnerability-source problems

### OSV does not report any package matches

First check **09 · Source Intelligence & Coverage** for **OSV Cache Coverage** and **Feed Health**. OSV only checks **approved unique package/version combinations**; it does not query each asset separately.

~~~bash
docker compose logs --tail=160 worker
~~~

Check outbound HTTPS/DNS to **api.osv.dev**, any proxy policy and your approved mappings. The OSV QueryBatch API uses HTTPS **POST for read-only lookup**, which some corporate proxies may block even when GET works. No OSV API key is required.

**A cached empty result is not evidence of safety.** The default negative-cache refresh is 24 hours.

### NVD or EUVD data seems sparse/stale

- **NVD** begins with a **48-hour modified-date lookback** and continues from saved pagination checkpoints.
- **EUVD** begins with a **7-day recent publication window** and uses resumable paging with overlap.
- Neither importer is a **complete historical mirror**, so do not expect every older CVE on a fresh installation.
- See dashboard 09 **Source Cursor and Backlog** and **Feed Health**; source failures should not erase valid older data.

~~~bash
docker compose logs --tail=200 worker
~~~

An optional NVD API key can improve authorized rate limits; it is not required for the default setup. Only change feed budgets when you understand source policies and local resource capacity.

### FIRST EPSS / CISA KEV appears missing

These enrich **already-known vulnerabilities** in **Live**. They do **not** create new asset Findings.

- FIRST: daily, compressed bulk CSV download over HTTPS.
- CISA: daily official KEV JSON catalogue.
- Demo: synthetic data only, no public feed calls.

Read dashboard 09 / worker logs. Check your egress policy, DNS and whether the local CVE was known when the daily update ran. On a failed/partial download, the last valid values are kept rather than silently overwritten.

### Why does one source say "affected" and another disagree?

Read dashboard 09 **Source Range Disagreements Requiring Review** and the Finding evidence details. AVM distinguishes **explicitly comparable, contradictory version ranges** from **silence**.

- Silence from one source is **not** a vote against another.
- A retracted OSV match is preserved as history and may flag a Finding for review.
- CVSS selection has an attributed provider; this is not a majority-vote CVSS.
- Validate the official vendor advisory and any backport before closing a Finding.

## 5. Risk and workflow problems

### Risk score seems too low or too high

Open **08 · Risk Intelligence & Remediation**, inspect **risk_factors** and the reported CVSS, EPSS, CISA KEV, criticality and Internet exposure. Missing values remain unknown; the application does **not** invent business importance. A verified KEV signal may enforce a modeled P1 floor.

### "Risk acceptance rejected"

~~~bash
docker compose exec -T worker python -m avm.ops queue --limit 20
~~~

Confirm the Finding exists and is active. The **--until** date must be in the future but no more than **180 days** away. Actor identifiers and reasons have validation requirements. The operation requires privileged Worker/DB access; **Metabase cannot accept a risk**.

### A Finding is "not_observed"; was it patched?

**Not necessarily.** This means the relevant installation was no longer observed after a successful inventory synchronization; it is **not** confirmation of patch deployment, secure build or vendor remediation. Verify the endpoint and patch state separately.

### My configured owner/criticality remains unknown

Check **config/asset-context.yaml**. The **source_id** must exactly equal Endpoint Central's resource ID. Values only apply after the next complete inventory sync. Unknown exposure is intentionally **not guessed** from the IP address.

## 6. Backups and what not to do

~~~bash
./scripts/backup.sh
~~~

The script creates local **database** dumps for both AVM and Metabase. It does not include private .env, API tokens, runtime application YAML or certificates: save those separately in an approved secure backup system.

**Never treat these as harmless troubleshooting commands:**

- **docker compose down -v** — can delete named PostgreSQL volumes.
- **./scripts/restore.sh ...** — replaces current database contents.
- Changing **COMPOSE_PROJECT_NAME** on an existing populated checkout — points at different Docker resources.
- Changing DB password values in **.env** alone — can break existing DB authentication.
- Pasting **.env**, tokens, raw inventory dumps or private certificates into a public issue.

For safe operation and recovery commands, read [Operator command book](COMMANDS.md). If the cause is still unclear, capture the **non-secret** error message, source run timestamps and the relevant Worker/Metabase logs rather than deleting data.
