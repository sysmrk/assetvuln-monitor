# V3 operations — priorities, evidence, lifecycle and remediation

These commands run inside the existing v0.3 Worker container. There is **no second API, scheduler, database or new login screen**. All access to managed Endpoint Central devices remains GET-only.

## What happens automatically

1. The existing Worker periodically downloads asset/software inventory (ManageEngine) and structured advisories (cve.now).
2. Software identity suggestions are held for human review. Only verified YAML or explicitly approved DB mappings can create potential findings.
3. Each potential finding gets a JSON evidence snapshot, priority components, an SLA target and a conservative remediation suggestion.
4. Every ~24 hours **in Live only**, the same Worker requests CISA KEV and FIRST EPSS for known CVEs using HTTPS GET. API keys are **not required**. On failures, previous intelligence is kept and the Worker retries later.
5. Successful inventory observations update the lifecycle. A missing match becomes **not_observed**, never automatically **resolved** or **patched**; incomplete/failed inventory does not close prior findings.
6. The eighth Metabase dashboard tracks priorities, KEV, overdue findings, ownership, evidence, lifecycle/audit, context completeness and one daily modeled-score snapshot.

**Scope:** the provider inventory APIs and cve.now integration still require verification against a real deployment. CVE polling is bounded to recent pages. Realtime EPSS or comprehensive historic CVE coverage is not claimed.

## One-command synthetic Demo

~~~bash
./install.sh --demo
~~~

This automatically generates local credentials, creates safe default files, configures isolated Compose resources and provisions the dashboards. Find the admin account in the private .env:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

Open https://localhost:8445. Demo findings are synthetic and never emailed.

## Read the prioritized queue

~~~bash
docker compose exec worker python -m avm.ops queue --limit 20
~~~

Example entry (illustrative, **not** a finding from your infrastructure):

~~~json
{
  "finding_id": 12,
  "asset": "SAMPLE-SERVER",
  "cve": "CVE-2026-12345",
  "risk_score": 81.5,
  "priority": "P1",
  "state": "open",
  "accepted_until": null
}
~~~

P1 means composite score at least 75; P2 ≥50, P3 ≥25, and P4 otherwise. The score combines up to 40 CVSS points, up to 20 EPSS points, 25 KEV points, up to 10 explicitly configured asset-criticality points and 5 explicitly verified Internet-exposure points. KEV sets a minimum of 75 points. Missing signals appear in the evidence factors and **are not inferred from other signals**.

This is a relative workload-prioritization model, *not* a calibrated likelihood of compromise. Verify product identity, actual patch levels and host exposure before declaring an issue confirmed.

## Optional: annotate critical assets

The installer creates config/asset-context.yaml from a safe template; this file is git-ignored. Add only verified information:

~~~yaml
assets:
  - source_id: "301"
    criticality: critical
    internet_facing: true
    business_service: "Payment API"
    owner: "Platform Team"
~~~

Use the precise source ID returned by Endpoint Central. Criticality can be unknown, low, medium, high or critical. Internet-facing can be true, false or null (unknown). **Do not infer exposure from an RFC1918 address or name alone.** On the next successful inventory sync, the Worker applies the context automatically. No credentials or source-code changes are needed.

## Remediation and evidence

The Metabase **08 · Risk Intelligence & Remediation** dashboard provides:
- **Risk-Based Remediation Queue:** ranked potential findings, ownership, CVSS/EPSS/KEV, SLA due date and status.
- **Finding Evidence & Candidate Remediation:** exact installed version, approved package identity, structured version ranges and candidate fixed-version events.
- **CISA KEV Exposure Queue:** findings with a CISA KEV catalogue entry, not proof of exploitability on the local asset.
- **Risk Acceptance & Lifecycle** and **Finding Decision & State Audit:** read-only history.

Candidate fixed versions are derived only from machine-readable fixed events. A vendor backport or product edition may invalidate a simplistic package upgrade recommendation. The system **never deploys updates or remotely changes endpoints**.

## Temporarily accept a known risk

This is an **explicit privileged database write** and requires container/database access. Actor strings are self-reported; **SSO/RBAC and approval delegation are NOT implemented**. Implement organizational change control outside this tool and restrict Docker access.

~~~bash
docker compose exec worker python -m avm.ops accept \
  --finding-id 12 \
  --actor "risk_owner" \
  --until 2026-12-01 \
  --reason "Time-bound exception approved in change record; mitigation applied."
~~~

The expiry must be 1–180 days from today. The original finding remains visible and active; acceptance does not prove remediation. The next matching cycle expires outdated acceptance. To withdraw one:

~~~bash
docker compose exec worker python -m avm.ops release \
  --finding-id 12 \
  --actor "risk_owner" \
  --reason "Risk acceptance withdrawn after review of new evidence."
~~~

All changes append an event to the finding_events table; this audit is **application-level, not cryptographically immutable**.

## Read-only remediation simulation

~~~bash
docker compose exec worker python -m avm.ops simulate --top 20
docker compose exec worker python -m avm.ops simulate --kev
~~~

Simulation mathematically removes ranking points for a selected group of current findings and reports the percentage reduction in the **model's summed points**. It neither marks findings resolved nor patches software. The model assumes independent findings and is not a reliable measure of true organizational risk reduction. Do not use the percentage as a forecast of prevented attacks.

## Finding lifecycle and data quality

- New affected product/version association: **detected** → **open**.
- Match not found after a completed inventory: **not_observed**. This means only that the potential match was absent from the scan, not that the software was patched.
- Previously unseen match returns: **reopened** → **open**.
- Accepted risk reaches expiration: **acceptance_expired** → **open**.
- Reviewer can change acceptance using explicit CLI commands; dashboards cannot edit state.

A source error cannot trigger closure based on missing data. An unexpectedly empty inventory when the database contains active assets is rejected rather than deactivating the fleet.

## Backups, separation and limitations

~~~bash
./scripts/backup.sh
docker compose ps
docker compose logs --tail=200 worker
~~~

Keep V1, V2 and V3 in **separate checkouts and Compose projects**; V3 defaults to assetvuln-monitor-v03, HTTPS 8445. Demo and Live cannot share the same installation/database. Never use docker compose down -v unless you intend to destroy that project's data and have verified backups.

The V3 migrations are **additive**, non-destructive column additions, but PostgreSQL 17 upgrade/load behavior, API compatibility and Metabase provisioning against a real corporate setup remain staging validation requirements. See [security](SECURITY.md) and [troubleshooting](TROUBLESHOOTING.md).
