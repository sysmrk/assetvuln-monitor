# V2 configuration — every file explained

**This is the historical V2 implementation.** It has **seven** Metabase dashboards, uses Endpoint Central + cve.now and requires **manual .env password setup**. For the simpler future product, read [V3 configuration](https://github.com/sysmrk/assetvuln-monitor/blob/develop/v0.3/docs/CONFIGURATION.md).

[Install V2 step by step](INSTALLATION.md) · [V1/V2 isolation](V02-ISOLATION.md) · [Mapping approvals](MAPPING-REVIEW.md)

## Which files must I change?

| File | Used for | Demo | Live |
|---|---|---|---|
| **.env** | Passwords, Docker project and HTTPS | **Create and fill** | **Create and fill** |
| **config/application.yaml** | Worker mode, Endpoint Central URL, source settings | Installer creates it | Set Live URL and mode |
| **secrets/manageengine_token** | Inventory-only Endpoint Central token | Empty | Add read-only token |
| **config/product-mappings.yaml** | Fictional Demo mappings | Use only for Demo | **Never use for Live** |
| **config/product-mappings.live.yaml** | Verified real package mappings | Not used | Starts empty; approve identities |
| **secrets/certs/** | Organization CA PEM | Usually not needed | If Endpoint Central uses private CA |
| **secrets/tls/** | NGINX TLS certificate and key | Local self-signed generated | Replace for trusted network access |

All commands assume you are in the root of the **correct V2 checkout**:

~~~bash
git branch --show-current
~~~

Expected: **develop/v0.2**.

## 1. Create and protect .env

~~~bash
cp example.env .env
nano .env
~~~

V2 **does not generate passwords for you**. Replace each **CHANGE_ME_*** value with a separate random value:

~~~bash
openssl rand -hex 30
~~~

Run that five times, once for each password: **POSTGRES_PASSWORD**, **APP_DB_PASSWORD**, **REPORT_DB_PASSWORD**, **MB_DB_PASSWORD**, **METABASE_ADMIN_PASSWORD**.

Set **HOST_UID** and **HOST_GID** to the numeric values printed by:

~~~bash
id -u
id -g
~~~

**Demo** example values:

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v02
BIND_IP=127.0.0.1
HTTPS_PORT=8444
PUBLIC_URL=https://localhost:8444
PRODUCT_MAPPINGS_FILE=./config/product-mappings.yaml
~~~

**Live** must use a different project/port and the empty Live mapping file:

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v02-live
BIND_IP=127.0.0.1
HTTPS_PORT=8454
PUBLIC_URL=https://localhost:8454
PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml
~~~

Save with **Ctrl+O**, Enter, **Ctrl+X**, then:

~~~bash
chmod 600 .env
~~~

**Do not edit existing PostgreSQL passwords after DB initialization** expecting a rotation: the PostgreSQL init script does not rerun on a populated volume. Never commit .env.

## 2. Configure the Worker

If the file is absent:

~~~bash
cp config/application.example.yaml config/application.yaml
nano config/application.yaml
~~~

**Demo:**

~~~yaml
application:
  mode: demo
~~~

**Live:** set **mode: live**, then the actual HTTPS base URL under **manageengine**:

~~~yaml
application:
  mode: live

manageengine:
  url: "https://endpoint.your-company.example:8383"
  token_file: /run/secrets/manageengine_token
  verify_tls: true
  ca_bundle: ""
  sync_minutes: 360
  max_assets: 10000
  max_pages: 500
~~~

Do **not** delete other sections of the example YAML while editing. The Endpoint Central URL should be the **base URL** only, with no /dcapi suffix.

| Setting | Meaning |
|---|---|
| **application.mode** | demo = synthetic; live = actual Endpoint Central + cve.now |
| **manageengine.url** | Real HTTPS base URL (on-premises API) |
| **manageengine.token_file** | In-container token path; keep default |
| **manageengine.verify_tls** | Must remain true |
| **manageengine.ca_bundle** | In-container CA path if internal PKI |
| **manageengine.sync_minutes** | Default 360 (six hours) |
| **manageengine.max_assets** | Hard default cap 10,000; increase before larger authorized inventories |
| **manageengine.max_pages** | Pagination cap; rejects incomplete scans |
| **cve.url** | https://cve.now |
| **cve.sync_minutes** | Default 30 |
| **cve.max_pages_per_poll** | Default 5 most recent pages; **not a full CVE archive** |
| **matching.mappings_file** | Internal path for mounted approved mapping YAML; usually leave default |
| **notifications.email_enabled** | Off by default; separately validate SMTP if enabling |

YAML indentation uses **spaces**, not tabs. The timezone field exists but is not a substitute for confirming timestamps and freshness in dashboards.

## 3. Add the Live inventory token

~~~bash
mkdir -p secrets/certs
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token
~~~

Use an account with **inventory-read permission only**. Never paste the token into a GitHub issue, commit or configuration example.

If you have a private company CA, copy the trusted PEM into **secrets/certs/org-ca.pem** and set:

~~~yaml
ca_bundle: "/opt/avm/certs/org-ca.pem"
~~~

Then test using its **host path**:

~~~bash
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
~~~

Otherwise:

~~~bash
python3 scripts/test_manageengine_api.py
~~~

**Expected:** both inventory and software API tests return PASS. Both test calls are **GET-only**.

## 4. Approved software identities: why Live starts empty

**config/product-mappings.yaml** is a tracked, fictional Demo file. **Do not use it for company data.**

**config/product-mappings.live.yaml** starts at:

~~~yaml
products: []
~~~

This means observed software still appears, but the Worker **does not guess** matching advisory package IDs. To create real version-based correlations:

1. Find exact vendor and product in **03 · Software Catalog**.
2. Verify its **ecosystem** (PyPI/npm/etc.) and **package name** in an official source.
3. Create a pending mapping proposal using **avm.review_cli propose**.
4. Have a different reviewer approve it with evidence.
5. Wait for the next full inventory sync and verify the result.

See [the complete commands](MAPPING-REVIEW.md). Fuzzy similarity suggestions are never automatically promoted.

V2's optional **scripts/suggest_mappings.py** reads local CSV data and reports **review-only candidates**; it does not modify approvals or change Endpoint Central.

## 5. How to apply settings safely

~~~bash
docker compose config --quiet
docker compose ps
~~~

After editing application YAML, on an appropriately sized staging deployment:

~~~bash
docker compose restart worker
docker compose logs --tail=100 worker
~~~

Restarting triggers another read-only Endpoint Central inventory collection; for large fleets, prefer the normal six-hour schedule. Do not change project identity or database credentials on a populated installation without a tested migration/rotation plan.

To change only NGINX port, update both **HTTPS_PORT** and **PUBLIC_URL** in .env, then run:

~~~bash
docker compose up -d nginx
~~~

**Keep BIND_IP=127.0.0.1 for initial tests.** The installer-generated localhost TLS certificate is not a production shared-network certificate.

## 6. What V2 does not configure

V2 does **not** include OSV QueryBatch, NVD/EUVD collectors, official FIRST EPSS CSV, CISA daily verified enrichment, the ninth source dashboard or the V3 risk engine. Do not copy V3-only YAML sections or CLI commands into this checkout.

For those capabilities, use [V3](https://github.com/sysmrk/assetvuln-monitor/tree/develop/v0.3), always as a separate project. Both branches are development previews; neither validates your production Endpoint Central infrastructure automatically.
