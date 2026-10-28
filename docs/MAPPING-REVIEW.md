# Software mapping review — make reliable matches, not guesses

**Why this exists:** Endpoint Central might report **"Example Web Framework"** while a vulnerability feed names a PyPI package **"example-web-framework"**. The names look similar, but software names alone cannot prove they are the same product or build.

AssetVuln Monitor therefore requires a **verified mapping** between the exact observed software/vendor and the advisory ecosystem/package. A similarity suggestion stays a **pending suggestion** until a trusted operator approves it.

This page shows each command and explains what changes. You do **not** need to edit source code or send any write request to Endpoint Central.

[Start with Live installation](INSTALLATION.md#part-b--connect-real-inventory-live) · [Dashboard tour](USER-GUIDE.md) · [Full operator command book](COMMANDS.md)

## 1. Three words to understand

| Word | Meaning |
|---|---|
| **Discovered software** | A product/vendor/version returned by Endpoint Central and stored in AVM |
| **Proposed mapping** | A candidate package identity that has **not been approved** and cannot create new Findings |
| **Approved mapping** | An exact, independently verified vendor + product → ecosystem + package identity that AVM may use for version correlation |

~~~mermaid
flowchart TD
    I["Endpoint Central software inventory"] --> Q{"Has a trusted mapping?"}
    Q -- No --> U["Unmapped product remains visible"]
    U --> P["Manual proposal or suggestion"]
    P --> R["Pending review"]
    R --> D{"Independent analyst"}
    D -- Reject --> X["Rejected + audit trail"]
    D -- Approve --> A["Approved mapping + audit trail"]
    Q -- Yes --> A
    A --> S["Next successful inventory sync"]
    S --> V["Potential CVE matching<br/>only with supported version evidence"]
~~~

**Important:** a mapping approval itself **does not guarantee a vulnerability**. There must still be supported affected-version evidence from a source.

## 2. Before you type a command

1. Install **Live** and check that assets/software appear in dashboards **02 / 03**.
2. Open a Linux terminal **in the V3 Live checkout**, for example:

~~~bash
cd "$HOME/projects/assetvuln-monitor-v03-live"
docker compose ps
~~~

3. Verify the **worker** is running. All example commands use **docker compose exec -T worker** to execute the existing application CLI **inside** the Worker container. No extra software installation is required.
4. Limit access to trusted operators: **CLI writes to the AVM database**, and Docker access itself is highly privileged.

## 3. Find an unmapped product

Open **03 · Software Catalog** in Metabase and locate an installed product with empty **ecosystem** or **package_name**. Write down its exact **vendor** and **software name**.

For a real match, investigate its actual upstream vendor/package documentation:

- Is the package's **ecosystem** really PyPI, npm, Maven, etc.?
- Does its registered package name match this particular product/edition?
- Are the installed version and vulnerability version semantics comparable?
- Could vendor-specific backports or enterprise builds change affectedness?

If you cannot verify the identity, **do not approve** it just to increase dashboard coverage.

## 4. Check the queue (read-only)

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status pending
~~~

**Output:** zero or more JSON lines, each with an **id**, vendor, product, proposed package and status. The final line shows how many review records were returned.

A new Live installation starts with **products: []**, so the suggestion engine initially has **no approved catalogue to compare names against**. An empty queue is normal. Seed your first verified identity manually in the next step.

View all recent decisions:

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status all --limit 50
~~~

These list commands **do not change anything**.

## 5. Propose the first mapping (local DB write)

After independently verifying the exact package identity, create a **pending** proposal. Replace **all quoted example values** with the real values from your own inventory and vendor documentation:

~~~bash
docker compose exec -T worker python -m avm.review_cli propose \
  --vendor "Exact Vendor From Dashboard 03" \
  --name "Exact Product From Dashboard 03" \
  --ecosystem "PyPI" \
  --package "verified-package-name" \
  --actor "analyst-1" \
  --evidence "Compared installed vendor/product against official package documentation"
~~~

**What happens?**
- The application creates a **pending mapping review record** and writes its proposal audit.
- It prints a numeric **Review ID** (for example **12**).
- It does **not** approve the mapping, create a finding, change YAML or call Endpoint Central.

**Do not copy the example product name literally.** It is explanatory text, not a real verified mapping.

## 6. Independently approve or reject it

A **different person** should validate a manual proposal; the CLI enforces different self-reported actor strings for manual proposal and approval.

**Approve** (replace **12** with the actual ID):

~~~bash
docker compose exec -T worker python -m avm.review_cli approve \
  --id 12 \
  --actor "reviewer-2" \
  --reason "Independently verified exact product, vendor, ecosystem and package identity"
~~~

**Or reject** an incorrect proposal:

~~~bash
docker compose exec -T worker python -m avm.review_cli reject \
  --id 12 \
  --actor "reviewer-2" \
  --reason "Advisory package belongs to a different product edition"
~~~

Both commands **write only to AVM mapping-review tables**, with an actor, reason and timestamp. They do not deploy anything on endpoints.

To inspect the decision trail for that ID:

~~~bash
docker compose exec -T worker python -m avm.review_cli history --review-id 12
~~~

This last command is **read-only**.

## 7. When do approved mappings start working?

**At the next successful inventory synchronization** — default **360 minutes (six hours)**. The approval CLI does not rewrite existing software installations immediately.

**Recommended:** allow the normal schedule and check Worker logs:

~~~bash
docker compose logs --tail=100 worker
docker compose exec -T worker python -m avm.ops queue --limit 20
~~~

**For a small staging Demo/Live environment only**, an administrator may trigger an immediate inventory refresh by restarting the Worker:

~~~bash
docker compose restart worker
~~~

This **re-fetches inventory**, potentially many GET requests per device. Do not do it during production peak hours without an approved operational plan.

**Expected:** the product becomes mapped in dashboard 03/07. Findings will only appear if **OSV or cve.now has matching supported affected-version evidence**; the public sources need to have synchronized successfully.

## 8. What does the audit really guarantee?

| Control | Implemented | Boundary |
|---|---|---|
| Explicit proposal vs approval | Yes | Similarity suggestions cannot self-approve |
| Separate actor names for manual proposal/review | Yes | Actor is self-reported, **not authenticated by SSO** |
| Reason and timestamps | Yes | Stored in AVM PostgreSQL |
| Duplicate approved mapping prevention | Yes | DB uniqueness rules |
| Read-only dashboard | Yes | Metabase cannot submit approvals |
| Immutable/WORM audit log | **No** | PostgreSQL privileged owners could alter records |
| Approval revocation UI / SSO / RBAC | **No** | Future work; follow organizational change control |

If your policy requires independent authenticated approval, use your organization's ticketing/change workflow and limit Docker shell access until a true RBAC-backed reviewer interface exists.

## 9. Optional: propose from a local CSV (advanced)

The repository includes **scripts/suggest_mappings.py**, a **read-only offline research tool**. It compares inventory CSV vendor/product labels against an *already approved* mapping catalogue and creates **suggestions**, never approvals.

If your inventory CSV has these columns:

~~~csv
vendor,name,version
Example Vendor,Example App,1.2.3
~~~

you can run the tool using a local Python environment. The exact commands and a bundled synthetic example are in [Operator commands → optional tools](COMMANDS.md#9-optional-developer-and-diagnostic-tools).

Use only approved exports, store reports privately and never commit them to Git.

## 10. If this workflow does not produce Findings

| Symptom | Check |
|---|---|
| Inventory is empty | Endpoint Central preflight and Worker inventory logs |
| Product still says unmapped | Was the proposal approved? Has the next inventory sync finished? |
| No pending suggestions | Empty initial Live catalogue is intentional; propose first real verified identity manually |
| Mapping approved, no Findings | Are public feeds current? Does that package/version actually appear in OSV/cve.now evidence? |
| Product name differs in whitespace/case | AVM normalizes approved vendor/name (Unicode NFKC, casefold, whitespace) |
| Same-looking product in different edition | Do not approve without exact identity; avoid false positives |

Further reading: [Source evidence](V03-MULTISOURCE.md), [Risk & lifecycle](V03-OPERATIONS.md), [Troubleshooting](TROUBLESHOOTING.md).
