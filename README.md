# AssetVuln Monitor v0.2 — Software Mapping & Data Quality

![Version](https://img.shields.io/badge/branch-develop%2Fv0.2-blue)
![Status](https://img.shields.io/badge/status-development_baseline-yellow)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

**V2 is the development milestone that introduced safer software identity matching, human-reviewed mapping approvals, quality reporting and isolated Docker deployment.** It reads Endpoint Central inventory without changing managed devices and correlates approved package identities with supported cve.now version evidence.

> **Which version should I use?** If you are evaluating the future product, use **[V3 — develop/v0.3](https://github.com/sysmrk/assetvuln-monitor/tree/develop/v0.3)**. V3 adds automated credentials, multi-source intelligence, risk scoring and nine dashboards. This **V2** branch is kept as a clear technical milestone and comparison baseline. **V1/main is a separate, unchanged baseline.**

## What this version does

~~~mermaid
flowchart LR
    EC["Endpoint Central<br/>GET-only inventory"] --> W["Python Worker"]
    C["cve.now advisories"] --> W
    W --> DB[("PostgreSQL<br/>assets + approved mappings + potential findings")]
    DB --> MB["Metabase<br/>7 dashboards"]
    MB --> N["NGINX<br/>HTTPS localhost:8444"]
~~~

| Capability | V2 behavior |
|---|---|
| Asset & software inventory | GET-only Endpoint Central on-premises connector |
| Demo | Fictional devices, software and CVE-DEMO records |
| Package identity matching | Exact normalized vendor+product mapped to a reviewed ecosystem/package |
| Mapping workflow | Pending proposals, independent operator review, approval/rejection audit |
| Vulnerability matching | Requires supported structured affected-version evidence from cve.now |
| User interface | **7** automatically provisioned Metabase dashboards |
| Deployment | **4** Docker containers, dedicated Compose project and HTTPS port |
| Risk scoring / FIRST / OSV / NVD / EUVD | **Not part of V2**; developed in V3 |

**Not an exploit scanner, EDR, patching system or evidence of confirmed exploitability.** Live Endpoint Central API compatibility and actual organization-specific affectedness require staging validation.

## Getting started — Demo

**Before starting:** install/run Docker Engine/Desktop with **Docker Compose v2**, plus Git, Python 3 and OpenSSL. On Windows, Docker Desktop with WSL2 Ubuntu integration is a straightforward evaluation environment. See the [complete V2 installation guide](docs/INSTALLATION.md) if you have never installed Docker.

~~~bash
mkdir -p "$HOME/projects"
cd "$HOME/projects"
git clone --branch develop/v0.2 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v02
cd assetvuln-monitor-v02
cp example.env .env
nano .env
~~~

**V2 differs from V3:** V2's installer **does not automatically generate passwords**. Before running it, replace **every CHANGE_ME_*** password in **.env** with a **different strong value**. To generate one random value at a time:

~~~bash
openssl rand -hex 30
~~~

Run that command **five times** and paste each unique output into the corresponding .env password field (PostgreSQL, app, reports, Metabase DB, Metabase admin). Set **HOST_UID/HOST_GID** using the values shown by **id -u** and **id -g** if they differ from the example values.

Check that your private .env includes:

~~~dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v02
BIND_IP=127.0.0.1
HTTPS_PORT=8444
PUBLIC_URL=https://localhost:8444
PRODUCT_MAPPINGS_FILE=./config/product-mappings.yaml
~~~

Save in nano (**Ctrl+O**, Enter, **Ctrl+X**), then:

~~~bash
chmod 600 .env
./install.sh --demo
docker compose ps
~~~

Open **https://localhost:8444** on the same computer. The generated localhost certificate is self-signed (expected for local Demo only). Find the Metabase login values locally:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

**Do not share** .env, passwords, tokens, screenshots showing credentials, or raw inventory.

## Connecting Live Endpoint Central

**Use a fresh checkout and a different Compose project/port from Demo, V1 and V3.** This V2 branch only uses cve.now for public advisory collection; it does not fetch OSV/NVD/EUVD or official FIRST CSV as V3 does.

The [Live tutorial](docs/INSTALLATION.md#part-b--connect-real-inventory-live) provides each exact command: copy/edit .env, create config/application.yaml, store a read-only Endpoint Central token, run the included **GET-only API preflight**, select the empty Live mapping file, install and verify.

**A fresh Live deployment starts with empty approved mappings.** Assets can appear before Findings. The operator must verify the exact software-to-package identity; no fuzzy suggestion is silently trusted.

## Seven dashboards

| Dashboard | What it answers |
|---|---|
| **01 · Security Command Center** | What inventory and potential exposure do we know? |
| **02 · Asset Explorer** | Which managed computers, OS and domains do we see? |
| **03 · Software Catalog** | Which installed products/versions exist? |
| **04 · Vulnerability Intelligence** | What cve.now advisories have been collected? |
| **05 · Affected Assets & Evidence** | Which approved package/version combinations have potential matches? |
| **06 · Pipeline Health & Coverage** | Are ingestion and coverage measurable? |
| **07 · Mapping Quality & Review** | Which software identities need verified approval? |

All report questions read from dedicated PostgreSQL **reporting** views. Metabase cannot use this reporting connection to mutate AVM application data.

## Daily commands

~~~bash
docker compose ps
docker compose logs --tail=100 worker
docker compose exec -T worker python -m avm.review_cli list --status pending
./scripts/backup.sh
docker compose stop
docker compose start
~~~

**Do not run docker compose down -v** unless you intend to delete this installation's PostgreSQL data.

## Documentation

- **[Complete Demo and Live installation, step by step](docs/INSTALLATION.md)**
- [V2 configuration file reference](docs/CONFIGURATION.md)
- [Mapping review, approval, rejection and audit](docs/MAPPING-REVIEW.md)
- [Software normalization and offline candidate research](docs/SOFTWARE-NORMALIZATION.md)
- [V1/V2 Docker isolation](docs/V02-ISOLATION.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [V2 roadmap and limitations](docs/ROADMAP-v0.2.md)
- **[Future product track: V3](https://github.com/sysmrk/assetvuln-monitor/tree/develop/v0.3)**

**Readiness:** GitHub Actions tests Python logic, Compose config/isolation and a disposable PostgreSQL instance. The V2 branch does **not** have a full Docker Demo smoke job and has **not** been certified for Live use.

**License:** Apache-2.0. Independent project, not affiliated with ManageEngine, cve.now or Metabase.
