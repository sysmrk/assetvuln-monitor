# AssetVuln Monitor v0.3 — Risk Intelligence & Remediation

A self-hosted, **read-only toward managed endpoints** asset/vulnerability monitoring tool. Endpoint Central inventory and structured vulnerability data are correlated conservatively; V3 adds evidence, ranking, public threat intelligence and remediation planning.

**Development branch:** develop/v0.3, based on develop/v0.2. The stable v0.1 main and v0.2 branch are unchanged. **Experimental software—not production certified.**

## Architecture: same four containers, no new infrastructure

Endpoint Central (GET-only inventory) + cve.now + OSV QueryBatch (read-only POST) + NVD 2.0 + ENISA EUVD + CISA KEV + FIRST daily EPSS CSV → existing Worker → PostgreSQL → Metabase behind NGINX HTTPS. Public sources run in Live mode only.

- **9 Metabase dashboards:** the original seven plus **08 · Risk Intelligence & Remediation** and **09 · Source Intelligence & Coverage**.
- **Finding evidence:** version, approved package, machine-readable affected ranges, candidate fixed versions and validation caveats.
- **Risk priority P1–P4:** explainable ranking based on available CVSS, EPSS, CISA KEV and *explicit* asset context. Missing information is labelled unknown, not fabricated.
- **Lifecycle:** detected, reopened and not-observed events. Missing inventory is never proof of remediation. Time-limited risk acceptance is auditable.
- **Remediation:** candidates only where source advisories declare an explicit fixed version; no auto patching or remote execution.
- **Read-only simulation:** hypothetical reduction of model score points for top-ranked or KEV findings. This is **not** a prediction of actual risk reduction.
- **Daily public threat enrichment:** bounded CISA KEV requests and full FIRST EPSS daily CSV; no API key or second Worker required. On failure, last good values remain.
- **Mapping governance from V2:** human approval still required for candidate software identity matches; a fuzzy match never creates a Finding.

## Quick start: Demo in one command

Requirements: Docker Engine/Desktop, Docker Compose v2, Git, OpenSSL and Python 3.

~~~bash
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03
cd assetvuln-monitor-v03
./install.sh --demo
~~~

On first run, the installer creates **private .env with independent random credentials**, a safe empty asset-context file, Demo configuration and localhost TLS. It does not overwrite credentials you already set. The synthetic Demo requires **no Endpoint Central account or public threat feed**.

**Open:** https://localhost:8445

~~~bash
# Read the generated administrator login locally; don't paste secrets into tickets.
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env

docker compose ps
docker compose logs --tail=100 worker
~~~

The project defaults to Compose project name assetvuln-monitor-v03, HTTPS 8445, loopback binding. It cannot reuse the V1/V2 default Compose namespaces.

## Live setup: only two external inputs are required

On a fresh **separate checkout/Compose project**, edit the inventory URL and add a read-only API token:

~~~bash
cp config/application.example.yaml config/application.yaml
# Edit: manageengine.url = your HTTPS Endpoint Central base URL
nano config/application.yaml
mkdir -p secrets
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token
python3 scripts/test_manageengine_api.py    # read-only API preflight
./install.sh --live
~~~

The installer generates passwords and automatically selects the **empty** Live mappings file. You must independently approve real software identities before producing CVE correlations. Configure a trusted CA when Endpoint Central uses private PKI.

**Do not reuse a Demo database for Live.** The installer records the original mode and refuses to switch it in place. See [complete installation guide](docs/INSTALLATION.md).

## Inspect risks without changing anything

~~~bash
# Most important potential findings
docker compose exec worker python -m avm.ops queue --limit 20

# What if the top 20 findings disappeared? Model points only.
docker compose exec worker python -m avm.ops simulate --top 20

# What if the currently observed CISA KEV matches were remediated?
docker compose exec worker python -m avm.ops simulate --kev

# Mapping approvals still use the existing review CLI:
docker compose exec worker python -m avm.review_cli list --status pending
~~~

Setting asset criticality and internet exposure is **optional**: edit the auto-generated, git-ignored config/asset-context.yaml with verified source IDs. Unknown context is not guessed. To record a temporary, time-limited risk acceptance, follow [operator guide](docs/V03-OPERATIONS.md).

## Nine dashboards

| Dashboard | Purpose |
|---|---|
| 01 · Security Command Center | Fleet and potential exposure overview |
| 02 · Asset Explorer | Hosts, operating systems and domain inventory |
| 03 · Software Catalog | Products, installed versions and owners of installs |
| 04 · Vulnerability Intelligence | Advisory catalog, CVSS/EPSS/KEV where known |
| 05 · Affected Assets & Evidence | Potential CVE–host–version correlations |
| 06 · Pipeline Health & Coverage | Data source collection and mapping coverage |
| 07 · Mapping Quality & Review | Review queue, identity coverage, audit, data gaps |
| **08 · Risk Intelligence & Remediation** | Priorities, SLA, KEV, vendor evidence, ownership and daily trends |
| **09 · Source Intelligence & Coverage** | Source provenance, original IDs, aliases, sync health, source evidence and OSV cache |

All dashboard questions select from approved reporting views; Metabase does not get SQL write permissions to the application schema.

## Tests and operational safety

~~~bash
python3 -m pip install -r requirements.txt pytest
python3 -m pytest -q tests
docker compose config --quiet
~~~

GitHub Actions on this development branch additionally tests an ephemeral PostgreSQL 17 database, verifies read-only reporting privileges and compares Compose resources with V1 and V2. A **full synthetic Docker/Metabase Demo startup** has passed in GitHub Actions, including HTTPS health, initialized risk reporting views and read-only CLI checks. Real Endpoint Central/Live integrations and corporate production-like behavior have **not** been verified.

The score is **an operational priority metric**, not an exploit probability. An observed version match is **potential exposure**, not proof that a vendor-provided fix is absent. EPSS is a probability estimated by FIRST; the project's composite risk points are not probabilities. cve.now polling is bounded and does not provide complete historical CVE coverage.

## Documentation

- [Installation / Demo / Live](docs/INSTALLATION.md)
- [Multi-source advisory integration (OSV, NVD, EUVD, FIRST)](docs/V03-MULTISOURCE.md)
- [V3 operations: priorities, simulation, acceptance](docs/V03-OPERATIONS.md)
- [Configuration fields and context](docs/CONFIGURATION.md)
- [Security model and remaining risks](docs/SECURITY.md)
- [V2/V3 software mapping review](docs/MAPPING-REVIEW.md)
- [Roadmap and remaining work](docs/ROADMAP-v0.3.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

Apache-2.0. Independent project, not affiliated with ManageEngine, FIRST, CISA, cve.now or Metabase.
