# AssetVuln Monitor
### See your assets. Understand the evidence. Prioritize what matters.

[![V3 quality gates](https://github.com/sysmrk/assetvuln-monitor/actions/workflows/v03-quality.yml/badge.svg?branch=develop%2Fv0.3)](https://github.com/sysmrk/assetvuln-monitor/actions/workflows/v03-quality.yml)
![Version](https://img.shields.io/badge/version-v0.3_development-blue)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![Deployment](https://img.shields.io/badge/deployment-Docker_Compose-informational)

**AssetVuln Monitor** is a self-hosted security visibility platform that turns software inventory into **explainable, prioritized potential vulnerability findings**. It reads device and software data from **ManageEngine Endpoint Central**, correlates approved software identities with public vulnerability information, adds CVSS / FIRST EPSS / CISA KEV context, and presents the result in **nine ready-to-use Metabase dashboards**.

**No agent to install. No changes to managed endpoints. No Redis, Kafka or extra database.** One Docker Compose stack handles collection, correlation, evidence, ranking and reporting.

> **Release status:** V3 is the future product track, currently **a development/technical-preview release**. Automated synthetic Docker, database and unit tests pass; live Endpoint Central compatibility, public-provider responses, enterprise-scale load and production recovery still require staging validation. Do not interpret a potential match as a confirmed exploit.

**Choose your starting point**

| I want to… | Start here |
|---|---|
| See the product using sample data, without any credentials | [Demo: from zero to dashboards](docs/INSTALLATION.md#part-a--run-the-demo) |
| Connect my real Endpoint Central inventory | [Live: complete guided installation](docs/INSTALLATION.md#part-b--connect-real-inventory-live) |
| Understand each chart and what it means | [Dashboard & first-use tour](docs/USER-GUIDE.md) |
| Find every command for day-to-day work | [Operator command book](docs/COMMANDS.md) |
| Read the guide in Persian | [راهنمای شروع فارسی](docs/fa/START-HERE.md) |

---

## What does the product actually do?

Imagine Endpoint Central reports an application installed on 400 servers. AVM identifies **the approved software/package mapping once**, asks the vulnerability sources about the relevant package and version, and links the returned evidence back to all relevant installations. Analysts see **which hosts**, **which versions**, **which vulnerability IDs**, **which source(s)** and **why** the item is prioritized.

~~~mermaid
flowchart LR
    EC["Endpoint Central<br/>Read-only inventory"] --> W["AVM Worker<br/>Inventory + approved mapping"]
    SRC["cve.now · OSV.dev<br/>NVD · EUVD"] --> W
    W --> DB[("PostgreSQL<br/>Assets · Evidence · Findings")]
    PRI["FIRST EPSS<br/>CISA KEV"] --> W
    DB --> MB["Metabase<br/>9 prebuilt dashboards"]
    MB --> N["NGINX HTTPS<br/>Your browser"]
    style W fill:#e4f1ff,stroke:#2761a6,color:#122a4a
    style DB fill:#e3f6ed,stroke:#22835c,color:#123c2a
    style MB fill:#f3eafe,stroke:#8251aa,color:#3a205c
~~~

**A key safety choice:** the platform does *not* assume a similar-looking desktop product is the same package as an npm or PyPI library. It displays unmapped software and lets a trusted reviewer approve the exact identity first. This reduces unsupported matches, but means **a fresh Live installation can show assets before it shows findings**. [Learn the two-minute review workflow](docs/MAPPING-REVIEW.md).

### What is automated — and what is not?

| Automatic after setup | Requires a human decision |
|---|---|
| Collect asset/software inventory on a schedule | Supply one read-only Endpoint Central token for Live |
| Create the PostgreSQL schema and Metabase dashboards | Verify software-to-package identity before approval |
| Generate different local passwords during first V3 setup | Decide whether an alert is real, patched/backported or a false positive |
| Refresh public vulnerability feeds and use a local cache | Confirm remediation and document risk acceptance |
| Prioritize findings and record source provenance | Approve exposure of the Metabase site beyond localhost |

The Worker does **not** run exploits, deploy patches, run commands on endpoints, prove exploitability, or silently approve software mappings.

## Try it — three commands

You need Docker Engine/Desktop with **Docker Compose v2**, Git, Python 3 and OpenSSL. Docker must already be running. Full prerequisite installation is documented [step by step](docs/INSTALLATION.md).

~~~bash
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03
cd assetvuln-monitor-v03
./install.sh --demo
~~~

**Open:** **https://localhost:8445** in your browser. A browser certificate warning is expected for the installer-generated **localhost-only self-signed certificate**.

The installer creates a private local configuration and random passwords, launches **four containers**, loads fictional devices and advisories, and provisions all nine dashboards. **Demo contacts neither Endpoint Central nor the public vulnerability providers.**

See the generated Metabase login on **your own terminal**:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
docker compose ps
~~~

Do not paste the password output into issues, chat, screenshots or shell logs. On a remote server, the default web port is only bound to **127.0.0.1**, not publicly exposed. [Follow the detailed Demo walkthrough](docs/INSTALLATION.md#part-a--run-the-demo).

## Move to real inventory (Live)

Live requires a **separate checkout and Docker project**; do **not** reuse Demo data. You provide a **read-only Endpoint Central base URL and inventory token**, run the included **GET-only preflight test**, and then install the same four-service stack. No other source requires an API key (an NVD key is optional).

The installer deliberately begins with **zero verified Live software mappings**. This means collection and visibility work immediately, while CVE findings need approved package identities. The [Live tutorial](docs/INSTALLATION.md#part-b--connect-real-inventory-live) gives **every command**, the exact file and field to edit, a first mapping-review example, and verification checks.

## One platform, nine dashboards

| Dashboard | Answer it gives you |
|---|---|
| **01 · Security Command Center** | What is in scope and where are the potential exposures? |
| **02 · Asset Explorer** | Which hosts, domains and operating systems are observed? |
| **03 · Software Catalog** | Which products and versions are installed, and how widely? |
| **04 · Vulnerability Intelligence** | What advisories, severity and exploit signals do we know about? |
| **05 · Affected Assets & Evidence** | Why does this CVE appear on this host and installed version? |
| **06 · Pipeline Health & Coverage** | Are collection and matching healthy? What data is missing? |
| **07 · Mapping Quality & Review** | Which identities need review, and what was approved? |
| **08 · Risk Intelligence & Remediation** | Which *potential* findings should be reviewed first? |
| **09 · Source Intelligence & Coverage** | Did cve.now, OSV, NVD or EUVD report it? What disagrees? |

[Explore every dashboard with examples and explanations](docs/USER-GUIDE.md).

## How the intelligence works

~~~mermaid
flowchart TD
    A["Installed product + version"] --> B{"Exact approved package mapping?"}
    B -- No --> U["Unmapped inventory<br/>Visible; no invented findings"]
    B -- Yes --> C["Correlate source-specific evidence"]
    C --> D{"Supported affected version<br/>or exact OSV query match?"}
    D -- No --> E["Advisory intelligence only"]
    D -- Yes --> F["Potential Finding + evidence"]
    F --> G["CVSS + EPSS + CISA KEV<br/>+ verified asset context"]
    G --> H["P1–P4 priority / reporting"]
~~~

- **cve.now and OSV.dev** can provide the version evidence needed for a potential finding.
- **NVD and ENISA EUVD** supplement advisory records, CVSS and identity aliases; they do not independently assert a host match from unverified CPE/product text.
- **FIRST EPSS and CISA KEV** enrich *priority*, not installed-version applicability.
- One source's silence is not a negative vote. A duplicate CVE does not create duplicate findings for the same installation/canonical ID. Explicit contradictory ranges and retracted evidence are shown for analyst review.
- The correlation result is **potential exposure**, not proof that a vendor fix, backport or mitigation is absent.

[Read the source-by-source design and limitations](docs/V03-MULTISOURCE.md).

## Technology & deployment

**Exactly four long-running services:**

| Service | Job |
|---|---|
| **Worker** (Python) | Collects read-only inventory, refreshes feeds, correlates and ranks |
| **PostgreSQL** | Stores observed inventory, history, mapping reviews, evidence and Metabase metadata |
| **Metabase** | Dashboard UI and read-only reporting access |
| **NGINX** | HTTPS entry point; default loopback only |

The one-shot **bootstrap** job configures Metabase and exits. It is *not* a fifth continuously running service.

By default V3 uses Docker project **assetvuln-monitor-v03** and HTTPS port **8445**; V1 and V2 are distinct. Never switch an existing project between Demo and Live.

## Documentation library

**Getting started**
- [Installation: prerequisites, Demo, Live and verification](docs/INSTALLATION.md)
- [A guided first tour of the dashboards](docs/USER-GUIDE.md)
- [راهنمای شروع فارسی](docs/fa/START-HERE.md)

**Daily work**
- [Copy-ready commands, scripts and safe operations](docs/COMMANDS.md)
- [Mapping approval, with examples](docs/MAPPING-REVIEW.md)
- [Risk score, evidence, acceptance and lifecycle](docs/V03-OPERATIONS.md)
- [Problem → command → expected result](docs/TROUBLESHOOTING.md)

**Reference & design**
- [Configuration: every file and relevant option](docs/CONFIGURATION.md)
- [Source architecture and reliability limits](docs/V03-MULTISOURCE.md)
- [Security boundaries and production checklist](docs/SECURITY.md)
- [Software normalization internals](docs/SOFTWARE-NORMALIZATION.md)
- [V3 roadmap and remaining validation](docs/ROADMAP-v0.3.md)
- [Historical V2 isolation guide](docs/V02-ISOLATION.md)

### Honest readiness statement

The GitHub Actions workflow exercises Python tests, an isolated PostgreSQL instance, reporting permissions, Compose isolation against V1/V2 and a **real Docker synthetic Demo start**. These tests **do not establish** production-safe Live behavior or complete coverage of all CVEs: cve.now pages are bounded, initial NVD/EUVD windows are recent, vendor backports are not automatically verified, and the Live approval workflow is not SSO/RBAC-backed.

**License:** Apache-2.0. Independent community project; not affiliated with ManageEngine, NIST, ENISA, OSV, FIRST, CISA, cve.now or Metabase.
