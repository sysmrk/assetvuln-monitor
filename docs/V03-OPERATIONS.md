# Risk, evidence and lifecycle — everyday operation

This is the practical guide for analysts who want to **prioritize, investigate and document** vulnerability findings without learning database administration.

**Start here:** [install the product](INSTALLATION.md), [learn the dashboards](USER-GUIDE.md), and [learn exact commands](COMMANDS.md).

## What happens automatically?

~~~mermaid
flowchart TD
    I["Endpoint Central inventory sync"] --> M["Approved software identity"]
    S["cve.now + OSV exact version evidence"] --> C["Correlation"]
    M --> C
    C --> F["Potential Finding"]
    N["NVD + EUVD CVSS / advisory details"] --> R["Risk model"]
    K["FIRST EPSS + CISA KEV"] --> R
    F --> R
    R --> Q["P1–P4 queue + evidence + SLA"]
    Q --> A["Analyst validation, remediation or exception"]
~~~

The Worker, **without extra containers or jobs**, refreshes source data and updates local PostgreSQL. Dashboard data is **read-only from Metabase**. It **never** patches endpoint software, remotely executes code or tests exploits.

## 1. Show the top potential Findings

Open a Linux terminal in the correct **V3 checkout**:

~~~bash
docker compose exec -T worker python -m avm.ops queue --limit 20
~~~

**This command is read-only.** Each JSON line contains approximately:

~~~json
{
  "finding_id": 12,
  "asset": "EXAMPLE-HOST",
  "cve": "CVE-2026-12345",
  "risk_score": 81.5,
  "priority": "P1",
  "reporting_sources": ["osv", "cve_now"],
  "state": "open",
  "accepted_until": null
}
~~~

**The example values are fictional.** Use the actual printed Finding IDs for subsequent actions.

### What does P1 mean?

AVM uses an internal **0–100 prioritization score**:

| Signal | Maximum |
|---|---:|
| CVSS base score | 40 |
| FIRST EPSS probability, transformed for prioritization | 20 |
| Official CISA KEV membership | 25 |
| Verified asset criticality | 10 |
| Verified Internet-facing status | 5 |

- **P1** = 75 or higher; default SLA **7 days**.
- **P2** = 50–74.99; default SLA **30 days**.
- **P3** = 25–49.99; default SLA **90 days**.
- **P4** = below 25; default SLA **180 days**.

Verified KEV membership sets a minimum of **75 modeled points** on a potential match. Missing signals are marked **unknown** rather than guessed. SLA targets are calculated from the first observed potential Finding; your organization should adjust them before relying on them as operational deadlines.

**An AVM score of 80 is NOT an 80% chance of compromise.** FIRST EPSS is a separate estimated probability of exploitation over a 30-day horizon.

## 2. Investigate why AVM produced a Finding

Open **08 · Risk Intelligence & Remediation** in Metabase, and use **09 · Source Intelligence & Coverage** for source attribution.

Check:
1. **Host:** correct asset, operating system, owner and business service.
2. **Installed version:** exactly what the inventory returned.
3. **Approved mapping:** the package identity matches the actual installed product/edition.
4. **Version evidence:** a supported affected-version range, or an exact OSV package/version query result.
5. **Source:** cve.now or OSV provided the matching evidence; NVD/EUVD may add metadata and selected CVSS.
6. **Vendor remediation:** fixed version, backports, edition exceptions, build flags and compensating controls.

**A generated fixed-version candidate is a clue, not an instruction to patch blindly.** Compare with the vendor's own supported releases and OS distribution security bulletins.

## 3. Add business importance (optional)

The installer creates a private file **config/asset-context.yaml**. It may remain empty.

~~~bash
nano config/asset-context.yaml
~~~

Example with **illustrative** values:

~~~yaml
assets:
  - source_id: "12345"
    criticality: critical
    internet_facing: true
    business_service: "Payment API"
    owner: "Platform Team"
~~~

Use the **verified Endpoint Central source ID**, not a guessed ID from a hostname. The Worker reads the file on the **next inventory sync**. A missing value remains **unknown**.

Do not set **internet_facing: true** solely because a server has an IP address.

## 4. Understand lifecycle states correctly

~~~mermaid
stateDiagram-v2
    [*] --> open: Potential match detected
    open --> accepted: Risk accepted by privileged operator
    accepted --> open: Acceptance expires or released
    open --> needs_review: Evidence withdrawn or unmatchable<br/>but installation still observed
    needs_review --> open: Supported match observed again
    open --> not_observed: Installation absent after complete inventory
    not_observed --> open: Previously absent match returns
~~~

| State/event | What it tells you | What it does not prove |
|---|---|---|
| **detected / open** | Current potential host–version correlation | That the machine is exploitable |
| **accepted** | An administrator recorded a time-bounded exception | That the issue disappeared |
| **needs_review** | Installed software remains but support for an earlier match changed | That the source or version is definitely wrong |
| **not_observed** | Relevant installation absent after completed inventory | That a secure patch was deployed |
| **reopened** | Previously not-observed potential match returned | That a new exploit occurred |
| **acceptance_expired** | The modeled exception date elapsed | That the organization remediated anything |

**Partial/failed inventory or a public-source timeout cannot automatically close Findings.** Unexpectedly empty inventory is rejected where active assets were previously present. A changed source may flag a review rather than declare remediation.

A successful application-level audit is not immutable WORM storage.

## 5. Temporarily accept a risk (explicit DB write)

**Only authorized staff should run these commands.** The CLI asks for an actor name and reason, but **does not verify the human identity with SSO/RBAC**. Obtain approval using your organization's existing change or risk-acceptance process.

First identify the actual Finding ID with the read-only queue command in section 1.

Example: accept **Finding 12** for the next **30 days** (replace **12** and actor/reason with your approved real values):

~~~bash
docker compose exec -T worker python -m avm.ops accept \
  --finding-id 12 \
  --actor "risk-owner" \
  --until "$(date -u -d '+30 days' +%F)" \
  --reason "Approved change ticket: temporary exception with compensating controls"
~~~

The command writes to AVM's **findings** and **finding_events** tables only. It does **not** change endpoints or hide the Finding. The expiry must be **1–180 days** in the future and the reason must provide sufficient detail.

**Release an acceptance early:**

~~~bash
docker compose exec -T worker python -m avm.ops release \
  --finding-id 12 \
  --actor "risk-owner" \
  --reason "Approved exception withdrawn following updated vendor assessment"
~~~

The release is also a **local application database write**.

## 6. Simulate remediation impact safely

These two commands are **read-only**:

~~~bash
docker compose exec -T worker python -m avm.ops simulate --top 20
docker compose exec -T worker python -m avm.ops simulate --kev
~~~

They calculate how many **modeled score points** would be removed if the selected Findings disappeared. They do not change the current Finding state, install a patch or estimate how many real incidents would be prevented.

This is an **operational prioritization exercise**, not a validated model of real-world risk reduction.

## 7. What should I do each day?

A practical first routine:

1. Open **06 · Pipeline Health & Coverage**. If inventory or public feeds failed, treat coverage as potentially stale.
2. Open **07 · Mapping Quality & Review**. Work through important, **verifiable** identity proposals.
3. Open **08 · Risk Intelligence & Remediation**. Review P1/KEV and overdue potential findings first.
4. Open **09 · Source Intelligence & Coverage**. Check the *actual source match* on important issues, explicit version-range conflicts and withdrawn evidence.
5. Validate the affectedness with the vendor, agree on a patch or exception, and record decisions using your organization's process.

For audits and governance, preserve source timestamps, approved mapping decisions and business context. Never call a discrepancy a confirmed exploit or a completed patch without independent supporting evidence.

## 8. Backup and recovery

~~~bash
./scripts/backup.sh
docker compose ps
docker compose logs --tail=120 worker
~~~

Back up **both** PostgreSQL databases and separately preserve private runtime configuration, tokens and certificates. Never run **docker compose down -v** as a troubleshooting step.

For restore commands and their destructive consequences, use [Operator command book](COMMANDS.md#8-back-up-stop-and-restart).

### What has and has not been validated?

The **synthetic Docker Demo and ephemeral PostgreSQL integration tests** run in GitHub Actions. Live Endpoint Central response schemas, each changing external feed, giant inventories, browser-facing production TLS and recovery on an existing production deployment must still be validated in staging. This application is a V3 technical preview, **not a production certification**.
