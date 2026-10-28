# First-use tour — understand what you are seeing

Welcome to **AssetVuln Monitor**. This guide is for someone who has **already run the installer** and wants to understand the dashboards without learning SQL, Docker internals or vulnerability database schemas.

If you have not installed it yet: [follow the beginner installation guide](INSTALLATION.md).

## 1. Open the dashboard

**Demo:** go to **https://localhost:8445**.  
**Live:** go to the exact **PUBLIC_URL** in your installation's private **.env** (the step-by-step Live example uses **https://localhost:8446**).

To find your local Metabase username and password from inside **the correct V3 checkout**:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

Use these values on the login page. The local self-signed certificate can cause a browser warning; **do not accept such a warning on an untrusted or public remote deployment**.

Inside Metabase, open **Collections**, then **AssetVuln Monitor · Security Workspace**. The installer creates **nine** dashboards. If the collection or dashboards are missing, follow [this repair path](TROUBLESHOOTING.md#2-dashboard-or-metabase-problems).

## 2. The big picture — what a Finding means

~~~mermaid
flowchart TD
    I["Computer and installed software"] --> M["Verified package identity"]
    M --> V["CVE advisory + affected version evidence"]
    V --> F["Potential Finding<br/>host + installed version + advisory"]
    F --> P["CVSS / EPSS / CISA KEV<br/>+ explicit business context"]
    P --> R["Priority + review queue"]
    R --> D["Human validation<br/>vendor fix / patch / backport / exception"]
    style F fill:#fff1d9,stroke:#a66c00,color:#4d3100
    style R fill:#e7f5e9,stroke:#278553,color:#163b25
~~~

A **CVE** is a reported vulnerability identifier. A **Finding** is our *potential* connection between that advisory and **one installed software version on one asset**. The same CVE may create multiple Findings across different installations.

AVM only creates a Finding when it has an **approved exact software identity** and supported version evidence. It can still be a false positive due to vendor fixes, backports, edition differences or incomplete inventory. **AVM never patches the host.**

### The four facts to check on every important Finding

1. **Which asset?** Hostname/source ID, operating system and service context.
2. **Which software and version?** Raw inventory identity, approved ecosystem and package.
3. **Why vulnerable?** Matching affected-version evidence; which provider actually supplied that evidence?
4. **How urgent?** CVSS severity, EPSS, verified CISA KEV membership, asset importance, exposure, SLA and business owner.

Only after investigating these should an operator call the issue confirmed or remediate it.

## 3. A guided walk through all nine dashboards

### 01 · Security Command Center — start here

**Question:** how many assets are monitored, and where should I begin reviewing?

You will see fleet totals, potential exposure metrics, severity distribution and high-activity hosts. Select **Prioritize Investigations** to see which systems have the most potential matches.

**Important:** a high number of potential matches is not the same as a high number of confirmed vulnerabilities; coverage depends on approved mappings and source freshness.

### 02 · Asset Explorer — inspect the inventory

**Question:** is the Endpoint Central inventory actually arriving?

Look for a plausible hostname, domain, OS and last-seen timestamp. In **Demo**, these hosts are fictional. In **Live**, compare counts with Endpoint Central.

If there are no Live assets, **do not troubleshoot CVEs first**: inspect the Worker log and Endpoint Central API configuration. [Exact commands](TROUBLESHOOTING.md#3-no-inventory-or-no-findings).

### 03 · Software Catalog — inspect installed versions

**Question:** which software was found, on how many assets, and has it been mapped to an advisory package?

The table includes vendor, software name, version, ecosystem, package name and asset count. A missing **ecosystem/package** means the product has not yet been approved for package-level vulnerability correlation.

**This is the most useful place to begin a real mapping approval.** Copy the observed vendor and product names **exactly**, independently confirm their official package identity, then use the [Mapping Review guide](MAPPING-REVIEW.md).

### 04 · Vulnerability Intelligence — the advisory catalogue

**Question:** which public vulnerabilities are currently known to this instance?

The catalogue can show CVE identifiers, titles, source-supplied severity/CVSS, FIRST EPSS, verified CISA KEV and dates.

A CVE appearing here is **not evidence that any monitored host has it**. This view includes general advisories that have not been linked to approved installed versions.

### 05 · Affected Assets & Evidence — why this host matched

**Question:** which actual host/software/version combinations have a potential vulnerability match?

Read the fields in this order:

| Field | How to interpret it |
|---|---|
| Vulnerability ID | Canonical CVE (or a source ID where no single CVE alias exists) |
| Hostname / IP | The affected **inventory record**, not proof of network reachability |
| Software / vendor / version | What Endpoint Central reported as installed |
| Confidence / evidence | Why the Worker linked it; this is **potential-structured-range**, not validated exploitation |
| First detected | When AVM first produced the potential connection |
| Severity / CVSS / KEV | Context for triage, not proof of applicability |

Open **08** for remediation candidates, risk factors and lifecycle. Open **09** for *which sources* provided the evidence.

### 06 · Pipeline Health & Coverage — can I trust freshness?

**Question:** when did inventory and advisory collection last succeed, and what is missing?

A healthy Docker container does not necessarily mean public feeds are being updated. This dashboard shows collection run status and data-quality gaps.

Use it when:
- inventory counts look stale;
- public feeds are blocked by firewall/DNS;
- the newest CVEs are missing;
- you expect more approved mappings than you see.

Read [Troubleshooting](TROUBLESHOOTING.md) before restarting anything or deleting data.

### 07 · Mapping Quality & Review — control false matches

**Question:** which discovered software products have no verified advisory package identity?

This dashboard shows **mapped/unmapped products**, pending review proposals, audits, unknown versions and vendor/OS/domain coverage.

**A fresh Live instance starts with an empty approved mapping catalogue.** This is a security design choice; seeing a large **Unmapped Products** number is expected. A trusted reviewer uses the privileged CLI to approve exact package identities. Metabase itself **cannot approve mappings**.

~~~mermaid
flowchart LR
    S["Unmapped software"] --> P["Propose identity"]
    P --> Q["Pending review"]
    Q --> V{"Independent reviewer"}
    V -- Verified --> A["Approved mapping<br/>next inventory sync"]
    V -- Not verified --> X["Rejected<br/>kept in audit"]
    style A fill:#e5f5ec,stroke:#278553,color:#163b25
    style X fill:#fceaea,stroke:#bb5757,color:#572323
~~~

Read the [copy-ready proposal and approval commands](MAPPING-REVIEW.md).

### 08 · Risk Intelligence & Remediation — prioritize the work

**Question:** which potential findings should an analyst investigate first, and what should they check?

This dashboard includes:
- **Risk-Based Remediation Queue**: P1–P4, CVSS, EPSS, KEV, asset owner, service and SLA.
- **Finding Evidence & Candidate Remediation**: installed version, package identity, machine-readable affected ranges and candidate fixed versions.
- **CISA KEV Exposure Queue**: potentially affected hosts with a **verified CISA KEV** CVE.
- **Risk Acceptance & Lifecycle**: active, accepted, not-observed and reopened records.
- **Daily Priority Trend**: trend in the application's **modeled priority points**, not incident probability.

**Risk score is not EPSS.** AVM's risk score is an internal 0–100 triage model. EPSS is a source-supplied probability estimate of exploitation within 30 days. A risk score of 80 **does not mean an 80% chance of compromise**.

Default priorities:

| Priority | Modeled score | Default internal SLA |
|---|---:|---|
| P1 | 75–100 | 7 days |
| P2 | 50–74.99 | 30 days |
| P3 | 25–49.99 | 90 days |
| P4 | Below 25 | 180 days |

These are application defaults, **not** your organization's mandatory policy. An explicit CISA KEV match sets a minimum of 75 modeled points. Missing EPSS or asset importance remains **unknown**, not guessed.

A **candidate fixed version** is not an automated patch instruction: check the vendor advisory, actual release, distribution backports and package edition first.

### 09 · Source Intelligence & Coverage — show your sources

**Question:** who reported this vulnerability, where did it originate, and which evidence was actually used?

This is particularly important for the multi-source V3 design.

| Item on dashboard | What it really tells you |
|---|---|
| **Finding Source Attribution** | Providers whose **version-match evidence actually contributed** to this Finding |
| **Source Metadata Coverage** | Advisory records fetched from cve.now, OSV, NVD and EUVD |
| **Per-Source Advisory and CVSS Provenance** | Original source ID, aliases, per-source score and selected CVSS source |
| **Source Range Disagreements** | Explicit comparably structured version-range conflicts that need review |
| **Retracted OSV Evidence** | Previously reported OSV match that is no longer present for the same query |
| **Feed Health / Cursor Backlog** | Last completed/failing sync and pending NVD/EUVD pages |
| **OSV Cache Coverage** | Count of unique mapped package/version queries and advisory results |

**Two different meanings of "source":**

- **Received via** — which API AVM queried, e.g. cve.now or OSV.
- **Original advisory** — the upstream GHSA/vendor/CVE record, where identified.

Two routes to the same GHSA are **not necessarily independent confirmations**.

**Example (illustrative, not a real finding):**

| Attribute | Example |
|---|---|
| Canonical identifier | CVE-2026-12345 |
| Asset | sample-app-01 |
| Installed package | example-package 1.2.0 |
| Actually matched via | OSV and cve.now |
| Selected CVSS provenance | NVD |
| EPSS provenance | FIRST |
| Known exploited provenance | CISA KEV |
| Action | Investigate vendor release/backport before remediation |

If only OSV reports a supported version match, AVM may keep the Finding even if cve.now is silent. A conflicting version range triggers a **review flag**; silent sources do not veto a report.

## 4. A simple daily routine

Open dashboards **06 → 07 → 08 → 09** in that order:

1. **06:** verify that inventory and sources are fresh.
2. **07:** approve high-value product identities that were independently verified.
3. **08:** investigate and prioritize potential findings, especially KEV and overdue items.
4. **09:** confirm exactly which provider and version evidence supported important issues.

Use **02/03** when you need host/software details, and **05** when you need evidence on a specific host/version.

## 5. What do I do when a dashboard is blank?

| Blank view | Most likely explanation | First action |
|---|---|---|
| Asset Explorer | No successful Endpoint Central collection | Worker logs + API preflight |
| Mapping Review | All products are unmapped and there is no seed approved catalogue | Manually propose your first verified mapping |
| Findings / Risk | No supported affected-version match yet | Verify inventory, mappings, OSV/cve.now coverage |
| Source Intelligence | Still Demo, source not enabled or feed failed/stale | Check source-health and Worker logs |
| Owner / Criticality | Asset context is optional and unknown by default | Add only verified source IDs to asset-context.yaml |

**Do not respond to a blank dashboard by deleting PostgreSQL volumes** or treating it as proof that endpoints are free of vulnerabilities.

## 6. Export and share carefully

Metabase can provide table export controls, depending on the Metabase version and permissions. Export only the fields needed by your audience, verify the active filters and never include API tokens, local passwords or private asset details in public tickets. A report exported from AVM is a **point-in-time observation**, not a confirmed security assessment.

Next: [operator commands](COMMANDS.md), [mapping approvals](MAPPING-REVIEW.md), [finding lifecycle and risk actions](V03-OPERATIONS.md).
