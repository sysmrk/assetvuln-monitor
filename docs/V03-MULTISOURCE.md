# V3 Multi-Source Vulnerability Intelligence

**Simple setup:** run the existing ./install.sh --demo or --live. Existing four
containers, one Worker and one PostgreSQL volume remain unchanged. No new
credentials are mandatory. Public-source fetching is automatic in Live mode.

## Why six sources rather than six scanners?

Endpoint Central collects installed software **once**. The Worker correlates
that inventory with **four advisory sources** and **two threat-priority sources**:

| Source | What it contributes | Does it independently create an asset Finding? |
|---|---|---|
| cve.now | Broad recent advisory discovery and machine-readable affected ranges | Yes, only with exact approved package identity + supported version range |
| OSV.dev | Explicit package/ecosystem/version lookup, aliases and fix events | Yes, for the exact mapped package/version returned by querybatch, after detail verification |
| NVD 2.0 | Authoritative CVE metadata and preferred CVSS | **No**: CPE applicability requires separate trusted CPE mappings and AND/OR evaluation |
| ENISA EUVD | Independent EUVD record IDs, explicit CVE aliases and supplemental CVSS | **No**: product text/ranges are not translated into guaranteed package-version evidence |
| FIRST EPSS | Daily exploit-likelihood probability and percentile for known CVEs | No; prioritization only |
| CISA KEV | Verified catalog of vulnerabilities known exploited in the wild | No; prioritization only |

Some feeds reuse the same upstream OSV/CVE/GHSA data. Seeing the same record
via two transports is not two independent vendor confirmations.

**Detection policy: union-with-evidence.** Either cve.now or OSV can support a
*potential* Finding on its own. One source being absent/silent is NOT a
negative vote. NVD/EUVD metadata and EPSS/KEV cannot independently convert
a software installation into a Finding. No fuzzy software matching is used.

## No double-scanning at enterprise scale

Only approved unique triples (ecosystem, package name, installed version) are
sent to OSV; hostnames/IP addresses/asset source IDs are **never** included.
All installations using the same package/version reuse the cached result.
OSV QueryBatch uses batches of up to 50 and limits work to four batches per
20-minute cycle by default; these are *operator-tunable budgets*, not claims
about global OSV API rate limits. Pagination is followed per query until
complete; malformed, repeated-token or partial responses are rejected.

The cache persists in PostgreSQL with a 24-hour TTL for *both positive and
negative* results. The Worker periodically rechecks unchanged packages so
freshly published advisories can still be discovered. Detailed OSV records
are reused when the upstream modified timestamp is unchanged.

The API uses HTTPS **POST** to /v1/querybatch for read-only lookup; this
does not mutate OSV data or any managed endpoint. All Endpoint Central
requests remain HTTPS **GET-only**.

## How are duplicate advisories resolved?

- One explicit CVE alias: use that CVE as the canonical vulnerability ID.
- An advisory without a CVE alias: retain its original OSV/EUVD ID.
- Multiple conflicting CVE aliases: do not automatically merge or guess.
- Existing source identity that acquires a new CVE alias: preserve its
  previous canonical association until an explicitly reviewed migration.
- The Finding table's existing installation_id + vulnerability_id uniqueness
  continues to enforce only one Finding for an identical canonical CVE.
- Per-source IDs, aliases, original advisory URLs, fetched/modified dates,
  and affected-version evidence remain separate in source tables.

**Current limitation:** changing aliases over time may require deliberate
manual reconciliation. We deliberately do not silently rewrite old Finding
foreign keys or assume two similar GHSA/EUVD records are the same issue.

## Source disagreement, removal and lifecycle

1. If cve.now alone has usable version evidence, generate a potential Finding.
2. If OSV alone returns a matching package/version, generate a potential
   Finding with the specific lookup identity and exact queried version.
3. If both refer to the same canonical CVE, preserve both evidence rows; emit
   one Finding for that installation/CVE and display both reporting paths.
4. A source returning no records is **not** proof of a patch. Previously
   returned OSV evidence is marked retracted for analyst review, not deleted.
5. When the installation still exists but no current positive version
   evidence remains, keep the Finding active and set needs_review.
6. Only the disappearance of that installation after an explicitly successful
   full inventory can produce not_observed; still not a proven remediation.
7. Failed/partial source requests never overwrite the last successful
   source evidence or close findings.

When two machine-comparable affected ranges for the same approved package
and installed version disagree explicitly, the Finding stays active and
source_conflict is set to potential_range_disagreement. Silence and absence
from a feed are never counted as disagreement. The ninth Metabase dashboard
has review queues for explicit range disagreements and source retractions;
neither can be resolved automatically by majority vote.

## NVD and EUVD delta collection

NVD uses the documented CVE API 2.0 modified-date window, a short overlap,
offset pagination, and a durable checkpoint. EUVD uses ENISA's dated,
paged vulnerability listing and a 2-day overlap; EUVD's date filter covers
published records rather than all historic modifications. Both sources
process a limited page budget and resume large, unfinished windows without
losing place. The initial lookbacks are 48 hours for NVD and 7 days for EUVD;
**neither is a full historical mirror**.

NVD has source-specific CVSS priority over EUVD and the aggregator. A lower
priority feed cannot silently overwrite the selected NVD score. Original
per-source CVSS values are retained for comparison. Real-world CVSS
selection still needs validation against vendor advisories where relevant.

NVD 2.0 without an API key is throttled automatically; optional NVD_API_KEY
in .env permits higher-rate use. EUVD public availability and schema can
change; source errors are isolated and reported without stopping other feeds.

## FIRST EPSS and CISA KEV

FIRST recommends the full daily EPSS gzip CSV for enterprise syncing, not
bulk use of its lookup endpoint. The Worker streams the HTTPS download with
decompression/row caps, validates the data, and updates **only known local
CVEs** with score, percentile and sync date. The entire public population
is not stored. Malformed/truncated files do not replace existing values.

CISA's complete KEV catalog is retrieved daily as before. Only CISA-listed
real CVEs receive a verified CISA KEV flag; an unrelated feed's own
exploitation or EPSS indicator is not treated as official CISA/FIRST data.
Neither feed is evidence of an installed vulnerable version.

## Metabase reporting and operator ergonomics

There are now **nine read-only dashboards**. Dashboard
**09 · Source Intelligence & Coverage** adds:
- source-level advisory counts, withdrawals and CVSS coverage;
- freshness/failed syncs per provider;
- OSV unique package-version cache coverage;
- Finding-level source attribution from the **actual matched evidence**, not
  a general advisory list;
- per-source CVE aliases, scores, original publishers and timestamps;
- structured package evidence and retraction status.

The existing dashboard 08 prioritization still uses the same CVSS/EPSS/KEV
model, with source-provenance fields. Use the existing privileged CLI for risk
acceptance. No additional web admin UI or dashboard credentials are created.

## Minimal configuration (all optional)

The installer writes config/application.yaml from the example. Public
integration switches under vulnerability_sources default to enabled in Live.
To disable a source in a restricted network, set its enabled value to false.
NVD_API_KEY is optional in private .env.

Source schedules default to: cve.now 30 minutes, OSV 20 minutes (24-hour
cache), NVD 2 hours (10-minute backlog continuation), EUVD 4 hours
(10-minute backlog continuation), FIRST EPSS 24 hours, CISA KEV 24 hours.
These are operational budgets, **not guaranteed source publication timings**.

Demo never connects to public vulnerability providers or a real Endpoint
Central instance; its CVE-DEMO-* values and exposure are synthetic.

## Safety boundaries and production prerequisites

- This feature sends verified package names and versions to OSV. Even without
  host identifiers, software inventory can be confidential: approve outbound
  data sharing with security/network owners before enabling Live.
- A positive package/version match is still **potential exposure**. Confirm
  distro backports, build flags, vendor patches and business exposure manually.
- Source overlap does not increase statistical confidence automatically.
- SQLAlchemy migrations are additive. Existing database rows and dashboards
  are retained. Back up/restore in staging before promoting V3.
- NVD/CPE full applicability and EUVD free-text ranges do not automatically
  create Findings: correct matching is more important than false coverage.
- Large-inventory performance, OSV/NVD/EUVD public network compatibility
  and real Endpoint Central API behavior need live staging measurements.
- Failures are observable in reporting.source_sync_health and Worker logs.
- The synthetic Docker Demo smoke and PostgreSQL unit/integration tests
  verify code paths, not all production provider schemas or changing feeds.

Relevant source documentation:
- OSV API: https://google.github.io/osv.dev/post-v1-querybatch/
- NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities
- EUVD API: https://euvd.enisa.europa.eu/apidoc
- FIRST data: https://www.first.org/epss/data
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
