# V3 installation — minimal steps, isolated by default

**Status:** develop/v0.3 is an experimental branch built from V2. The application does not execute changes on managed assets. Live Endpoint Central compatibility and end-to-end Metabase deployment still need verification on a real staging system.

## Requirements

Docker Engine/Desktop with Docker Compose v2, Python 3, Git and OpenSSL. A recent Ubuntu/WSL2 or Linux workstation is sufficient for the Demo. Keep adequate RAM available for Metabase.

Check installation prerequisites:

~~~bash
docker compose version
docker info
python3 --version
openssl version
~~~

## DEMO: fresh installation in one command

~~~bash
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03
cd assetvuln-monitor-v03
./install.sh --demo
~~~

No manual .env setup is required. The installer:
1. Copies example.env to a private .env and generates **different, random local passwords**.
2. Sets the current user/group for secret-file ownership.
3. Creates private Demo application YAML and empty business-context YAML.
4. Creates a temporary localhost certificate if TLS material is missing.
5. Validates the Compose project name, required passwords and Demo/Live mode lock.
6. Builds and starts the four existing containers and provisions all nine dashboards.

The default URL is **https://localhost:8445** (self-signed certificate warning expected). To read your local account:

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
docker compose ps
docker compose logs --tail=100 worker
~~~

Passwords are **never printed by the installer**, and the .env file is git-ignored with permission 0600. The Demo uses synthetic hosts and advisories (CVE-DEMO-*) and does not send email or call real Endpoint Central / CISA / FIRST services.

## LIVE: fresh isolated installation

Never switch a Demo project/volume to Live. Create a **new** checkout/Compose name, preferably on a separate host.

~~~bash
git clone --branch develop/v0.3 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v03-live
cd assetvuln-monitor-v03-live

cp config/application.example.yaml config/application.yaml
nano config/application.yaml
# Set application.mode to live, manageengine.url to the verified HTTPS base URL,
# and an optional trusted custom CA bundle.

mkdir -p secrets
nano secrets/manageengine_token
chmod 600 secrets/manageengine_token
python3 scripts/test_manageengine_api.py
./install.sh --live
~~~

The independent API test checks one computer page and one software page via **GET only**. A success does not prove all API versions and pagination shapes. No API token should be committed to Git, embedded in YAML, or sent to a support ticket.

If TLS uses an internal CA, place the PEM in secrets/certs/ and configure the in-container CA bundle path in config/application.yaml. Never disable TLS verification.

A new Live installation automatically selects config/product-mappings.live.yaml (initially empty). This is a deliberate safeguard: real product identities must first be independently verified and approved. Only then can structured version-based correlations produce findings.

Before exposing the site to other hosts, replace self-signed certificates, use a strong admin identity/email, set BIND_IP, HTTPS_PORT and PUBLIC_URL in the private .env, and restrict network/firewall access.

## Separation from V1/V2

| Branch | Compose project default | HTTPS default |
|---|---|---|
| main (V1) | assetvuln-monitor | 8443 |
| develop/v0.2 | assetvuln-monitor-v02 | 8444 |
| develop/v0.3 | assetvuln-monitor-v03 | 8445 |

V3 refuses either earlier project's Compose name and checks the resolved Compose name before starting. Check each checkout with:

~~~bash
docker compose config --quiet
python3 scripts/check_compose_isolation.py --baseline-dir /path/to/v02 --candidate-dir .
~~~

**Do not run docker compose down -v** if you want to preserve databases and dashboards.

## Automatically created and editable files

- .env — passwords, local HTTPS port, Compose project identity.
- config/application.yaml — source settings, sync cadence and optional mail.
- config/asset-context.yaml — optional verified business criticality, owner and exposure. No guessed data.
- secrets/manageengine_token — Live-only, read-only Endpoint Central credential.
- secrets/tls — TLS certificate and private key.

These are local data. Do not add them to public repositories.

## Common commands

~~~bash
# Verify containers
docker compose ps
docker compose logs --tail=200 worker

# View current priority queue (read only)
docker compose exec worker python -m avm.ops queue --limit 20

# Read-only hypothetical score reduction
docker compose exec worker python -m avm.ops simulate --top 20

# Review pending software mappings (read only)
docker compose exec worker python -m avm.review_cli list --status pending

# Create a snapshot backup of both application and Metabase DBs
./scripts/backup.sh

# Reprovision missing dashboards after upgrade
docker compose --profile setup run --rm bootstrap

# Stop without removing data
docker compose stop
~~~

The v0.3 database migration adds nullable/defaulted columns and new tables automatically on Worker startup; it does **not** delete existing data. It does not migrate or merge databases across different Compose projects. Back up data before attempting any update. For recovery, review scripts/restore.sh and use it only against a verified target with explicit confirmation.

## Run automated checks without touching infrastructure

~~~bash
python3 -m pip install -r requirements.txt pytest
python3 -m pytest -q tests
docker compose config --quiet
~~~

The V3 GitHub Actions workflow runs Unit tests, a throwaway PostgreSQL integration job, shell/Compose checks and V1/V2 collision comparisons. The GitHub Actions synthetic Docker Demo smoke test has also passed (one-command install, Metabase HTTPS health, risk reporting views and CLI). These are **not** a production certification or a real Endpoint Central test. See [V3 operations](V03-OPERATIONS.md), [security](SECURITY.md) and [troubleshooting](TROUBLESHOOTING.md).

## Public data sources

Live automatically enables OSV package-version lookup, NVD delta CVE metadata, EUVD supplemental metadata, the daily FIRST EPSS CSV and CISA KEV alongside cve.now. These require **no additional containers or mandatory API keys**. An optional NVD_API_KEY can be set in the private .env for greater API throughput. Outbound access is needed to public APIs; approve sharing unique installed package/version information with OSV. See [source design and audit controls](V03-MULTISOURCE.md).

## Critical limitation

A Finding is a **potential affected-version match**, not proof that a particular installation is exploitable. Vendor backports/patches and product-specific advisories must be verified. Daily KEV/EPSS enrich already discovered CVEs; neither feed replaces a full historical vulnerability source.
