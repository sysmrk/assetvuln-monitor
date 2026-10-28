# How the six vulnerability-intelligence sources work

**One inventory. Multiple evidence sources. One explainable decision.**

This is the complete architecture and operator explanation of V3's multi-source feature. It does **not** require setting up six scanners. The existing Python Worker automatically talks to the configured public providers, stores evidence in the existing PostgreSQL database, and presents the result in Metabase.

If you only want to install the product, start with the [beginner guide](INSTALLATION.md). Everything in this page is designed to clarify the *meaning* and *trustworthiness* of its results.

## The 60-second explanation

~~~mermaid
flowchart TD
    EC["Endpoint Central<br/>one inventory collection"] --> INV["Assets + installed software in PostgreSQL"]
    INV --> MAP{"Exact package identity approved?"}
    MAP -- No --> U["Unmapped / needs review<br/>No guessed Finding"]
    MAP -- Yes --> DUP["Unique ecosystem + package + version"]
    DUP --> OSV["OSV QueryBatch<br/>package/version matches"]
    CVE["cve.now<br/>advisory feed"] --> E["Structured evidence store"]
    OSV --> E
    NVD["NVD CVE metadata/CVSS"] --> E
    EUVD["EUVD supplemental advisories"] --> E
    E --> COR{"Supported version evidence?"}
    COR -- No --> INT["Advisory record only"]
    COR -- Yes --> FIND["One potential Finding<br/>per installation + canonical advisory"]
    FIRST["FIRST EPSS"] --> R["Risk priority + provenance"]
    KEV["CISA KEV"] --> R
    FIND --> R
    R --> MB["Metabase: nine dashboards"]
~~~

**Important:** a source telling us that a CVE exists is not the same as a source proving that a particular installed version is affected. The code makes that distinction explicitly.

## 1. What is each provider responsible for?

| Provider | Role | Can it support a version-based Finding on its own? | Notes |
|---|---|---|---|
| **cve.now** | Recent aggregated advisory discovery | **Yes**, with a reviewed package identity and supported structured version range | Aggregated data may originate upstream in OSV/GHSA/NVD |
| **OSV.dev** | Exact package/ecosystem/version lookup | **Yes**, for the queried version when a detailed advisory confirms package identity | Uses public HTTPS POST QueryBatch for a **read-only lookup** |
| **NVD / NIST** | CVE metadata, selected CVSS and reference identifiers | **Not in current implementation** | CPE configuration applicability is not yet evaluated with verified package mapping |
| **ENISA EUVD** | European vulnerability identifiers, explicit CVE aliases and supplemental metadata | **Not in current implementation** | Free-text affected-product descriptions are not treated as exact package evidence |
| **FIRST EPSS** | Statistical exploit-likelihood score and percentile | **No** | Probability of exploitation over a 30-day horizon; prioritization only |
| **CISA KEV** | List of vulnerabilities known exploited in the wild | **No** | Prioritization only; being listed does not identify a local affected installation |

The wording **"reported via"** matters: cve.now may incorporate the same upstream record as OSV. Two feeds are **not necessarily two independent confirmations**.

## 2. Who decides if only one provider reports a CVE?

**The correlation engine decides**, not a global provider ranking. We use **union with valid version evidence**:

| What happened? | AVM's decision | Why |
|---|---|---|
| Only OSV returns a matching package/version advisory | Potential Finding | Exact approved identity and queried version evidence |
| Only cve.now provides a supported affected version range | Potential Finding | Structured match is sufficient |
| Both report the **same canonical CVE** for that installed version | **One Finding** with two evidence paths | Prevent duplicate host/CVE records |
| NVD reports a CVE but no trusted package-to-CPE applicability exists | Advisory metadata only | Existence of a CVE is not a host match |
| EUVD reports a vulnerability but only free-text product data | Advisory metadata only | Free text cannot safely prove affectedness |
| FIRST has EPSS but package applicability is unknown | Score metadata, no new Finding | EPSS is not a detector |
| CISA lists a CVE in KEV but installed version is unverified | KEV enrichment, no new Finding | Exploitation signal is not package evidence |
| One source is silent, another has valid evidence | Keep the potential Finding | **Silence is not a negative vote** |
| One explicit comparable version range conflicts with another | Keep the Finding and flag a **range disagreement** | Requires human vendor validation |
| OSV withdraws/retracts previous evidence | Preserve history; require review if still installed | A source change does not prove the host was patched |
| A public API fails or returns incomplete pages | Keep last valid data; log failure | No false remediation due to source outage |

**Finding is always potential**, not proof of a patched/unpatched target. A distro backport may have already fixed the real installed build.

## 3. Does the Worker check every Asset six times?

**No.** Endpoint Central inventory collection happens once on its own schedule. The different data sources operate on a local snapshot or public CVE identifiers.

For **OSV**, the Worker extracts distinct, already-approved tuples:

**ecosystem + package_name + installed_version**

Example (illustrative, not a performance claim):

| Inventory | Count |
|---|---:|
| Managed assets | 100,000 |
| Total software installations | 5,000,000 |
| Distinct approved package/version combinations | 20,000 |
| OSV lookups required for the *first* sweep | 20,000, **not 5 million** |

Default batch budget: **50 tuples per batch × 4 batches per 20-minute cycle = up to 200 unique tuples per cycle**. Therefore an initial full sweep over 20,000 different tuples could take many cycles (roughly 100 cycles, **about 33 hours** if every cycle reaches the full budget, with no retries or pagination overhead). Real capacity depends on API latency, source rate limits, local database performance and approved mapping coverage.

**This is not an enterprise-scale benchmark.** With a very large fleet, also increase **manageengine.max_assets** from its safe initial 10,000 cap and validate Endpoint Central's per-device API cost. Do not increase budgets without staging tests.

### Why the OSV cache matters

~~~mermaid
flowchart TD
    P["Approved unique package/version"] --> C{"Valid cached result<br/>younger than 24h?"}
    C -- Yes --> REUSE["Reuse local PostgreSQL evidence"]
    C -- No --> Q["HTTPS POST /v1/querybatch"]
    Q --> PG{"All pages/details<br/>valid and complete?"}
    PG -- Yes --> SAVE["Store cache, source IDs,<br/>match evidence and timestamp"]
    PG -- No --> KEEP["Keep previous data<br/>record failure"]
    SAVE --> REUSE
~~~

Both **positive** and **negative** cache entries expire and are refreshed. A cached "no result" means **no record returned at that check time**, not proof that the software is safe forever.

The Worker follows per-query pagination, rejects incomplete/malformed batch results and caches detailed OSV records using the upstream modification timestamp when available.

**Privacy:** OSV sees the approved **package name, ecosystem and version**, **not hostname, IP, source ID or business owner**. Package names/versions can still be confidential technology-stack information; approve outbound sharing before Live deployment.

## 4. How are NVD, EUVD, FIRST and CISA synchronized?

| Source | Initial window / input | Update behavior | Important limitation |
|---|---|---|---|
| **cve.now** | Bounded latest advisory pages | Polls every 30 minutes by default | Not a complete historical CVE archive |
| **NVD 2.0** | Recent **48-hour modified** CVE window | Two-hour cadence, checkpoint, short overlap, paginated | Does not automatically backfill all older CVEs |
| **EUVD** | Recent **7-day publication** window | Four-hour cadence, paging, stored progress and overlap | Historical records modified outside the current window may be missed |
| **FIRST EPSS** | Official full daily gzip CSV | Daily validation and local updates of already-known CVEs | No new asset Finding solely from a CSV score |
| **CISA KEV** | Official complete JSON catalogue | Daily lookup and verification | Only enriches known CVE correlations |
| **OSV** | Approved unique package/version tuples | Twenty-minute worker cadence; 24-hour per-tuple TTL | Does not cover every commercial product |

These are **default polling intervals**, not claims about provider publication latency. Network/API schemas can change. NVD optionally accepts **NVD_API_KEY** in the local .env to support higher permitted rates; all public sources work without mandatory signup.

**Why FIRST CSV instead of thousands of API calls?** FIRST recommends its daily bulk data file for large local synchronization. AVM streams and validates the compressed CSV, updating only CVEs already stored locally. It does not import every EPSS entry as a new host Finding.

## 5. What exactly gets stored?

The **application database** stores distinct records for:

- Assets, software products and individual installations.
- Canonical vulnerability identifiers (prefer one explicit CVE alias).
- **Advisory observations per provider**: source name, original ID, known aliases, source CVSS, fetched/updated timestamps, withdrawal status.
- **Affected package evidence**: precise ecosystem/package, structured range or exact matched version, evidence status and source.
- **OSV query cache**: checked unique package/version, result IDs and time.
- **NVD/EUVD checkpoints**: completed/pending windows and page positions.
- Findings: installation, canonical vulnerability ID, risk score, evidence packet, remediation candidates and lifecycle events.

The existing database constraint **(installation_id, vulnerability_id)** prevents duplicate Findings for **the same canonical ID**. **If two advisories lack a shared, unambiguous CVE alias**, their identities may remain separate; AVM deliberately does not guess equivalence from titles.

### CVSS selection and source independence

When competing source CVSS values exist, the current selection preference is:

**NVD → EUVD → cve.now → OSV**

That is a **field-specific metadata preference**, not a statement that NVD always wins package/version matching. Different CVSS vector versions and authoritative vendor ratings may require manual review. Per-source values remain visible.

**FIRST EPSS** and **CISA KEV** are sourced directly from their respective official feeds. AVM does not trust another advisory provider's unverified KEV/EPSS hint as an official statement.

## 6. In Metabase, can I see who reported an issue?

**Yes — open Dashboard 09 · Source Intelligence & Coverage.**

| Card | How to use it |
|---|---|
| **Finding Source Attribution** | Which provider's **version-match evidence** was actually used for this host/installation |
| **Per-Source Advisory and CVSS Provenance** | Original source IDs/aliases, individual CVSS and selected CVSS provider |
| **Source Metadata Coverage** | Number of retrieved records from each provider |
| **Source Range Disagreements** | Explicit comparable positive/negative version-range disagreement |
| **Retracted OSV Evidence** | Former positive match for a queried tuple that is no longer reported |
| **Feed Health** | Latest successful or failed collection by source |
| **Incremental Feed Cursor and Backlog** | NVD/EUVD pending/finished update windows |
| **OSV Cache Coverage** | How many unique package/version tuples have been checked |

**Example, completely fictional:**

| Question | Example answer |
|---|---|
| Which host? | sample-app-01 |
| Which installed version? | example-package 1.2.0 |
| Canonical CVE | CVE-2026-12345 |
| Version matched by | OSV, cve.now |
| Selected CVSS by | NVD |
| EPSS by | FIRST |
| Known exploited by | CISA KEV |
| Source conflict | none observed |

NVD providing the selected CVSS does **not** mean NVD itself produced the installed-version match. The two kinds of provenance are reported separately.

## 7. What happens when providers disagree or go offline?

A successful inventory scan is not the same as a successful public feed update. Each provider is logged separately. The Worker should preserve earlier source data when another provider fails.

**Lifecycle safeguard:** when a previously matched OSV result disappears but the installation is still active, AVM keeps the Finding for review instead of treating the host as patched. A Finding is only marked **not_observed** when its installation is absent after a complete successful inventory; even that does not certify remediation.

**Current limits of conflict checking:** AVM flags explicit version-range disagreements it can compare using its supported parser. It does **not** claim to solve all vendor-specific version semantics, all cross-ecosystem aliases or every CPE AND/OR configuration.

## 8. Do I have to configure each source?

**No.** A standard Live installation enables OSV, NVD, EUVD, cve.now, CISA KEV and FIRST EPSS with their default schedules. All run in the **existing Worker**; no new service is installed.

You can adjust the optional **vulnerability_sources**, **cve** and **threat_intelligence** sections in **config/application.yaml**. If your network does not allow a provider, disable **that one** and observe the coverage gap in dashboards 06/09.

Follow [Configuration](CONFIGURATION.md) for exact YAML examples and restart instructions.

## 9. What this implementation does not promise

- Complete vulnerability coverage for every software product or every historical CVE.
- Evidence-independent majority voting across sources.
- Correct matching of arbitrary vendor CPE configurations or distro backports.
- A single merged identity for ambiguous aliases or all GHSA/EUVD entries.
- Production performance proven on hundreds of thousands of Endpoint Central devices.
- No need for a human to approve genuine package identity and validate patch applicability.

The goal is **conservative, explainable evidence with a low-friction deployment**, not an unverified declaration that every detected product is vulnerable.

**Official documentation:**
- [OSV API reference](https://google.github.io/osv.dev/post-v1-querybatch/)
- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- [ENISA EUVD](https://euvd.enisa.europa.eu/)
- [FIRST EPSS data](https://www.first.org/epss/data)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
