# Installation (WSL and small on-premises deployments)

## Before you begin

- Install Docker Desktop and enable WSL integration for Ubuntu, or use a supported Linux Docker Engine + Compose v2.
- Install Git and OpenSSL on the Linux/WSL host. Docker containers contain all Python and PostgreSQL dependencies.
- Run `docker compose version` and `docker info` to verify the runtime.
- Keep secrets, backup dumps and TLS private keys in this deployment folder, protected by filesystem permissions.
- For network access beyond localhost, terminate TLS with a certificate trusted by your users and review firewall rules. Default bind IP is `127.0.0.1`.

## One-command local demo

```bash
./install.sh --demo
```

This provisions a local generated password, TLS certificate, PostgreSQL roles/databases, data schema and reporting views, demo data, and all Metabase dashboards.

Log in at `https://localhost:8443` as `admin@example.local`; find the generated password in `.env`. No production token is required.

## Start/stop/update

```bash
docker compose stop                 # keep data
docker compose start                # reuse data; services restart
docker compose ps                   # list health
./scripts/backup.sh                 # backup FIRST before upgrading
# Pull source updates from your reviewed Git branch and rerun:
./install.sh --demo
```

## Live setup

In `config/application.yaml`, select `live`, set your Endpoint Central HTTPS URL, and place a READ ONLY token in `secrets/manageengine_token`. Then run `./install.sh --live`.

If you use `--live` after demo on the same database, demo data remains until it is explicitly removed by an administrator or a fresh data volume is initialized. **Do not mix demo with real data in production.** Prefer a separate, fresh deployment path or remove the demo database volume after creating a backup and verifying its content.

## Backup and recovery

Use `./scripts/backup.sh` to export separate PostgreSQL-format backup files of the application and Metabase metadata. They include the dashboards. `scripts/restore.sh <backup-directory>` prompts for confirmation and rewrites current data. Test restoration in staging first.

## How to confirm a successful WSL test

- `docker compose ps` shows postgres, worker, metabase, nginx as healthy/running.
- Metabase opens over HTTPS; all six named dashboards and 25+ questions exist.
- In `01 · Security Command Center`, the demo data shows 10 assets and nonzero demo findings.
- In `03 · Software Catalog`, every synthetic host has its software/version records.
- In `06 · Pipeline Health & Coverage`, the inventory, CVE and matching sync jobs have a green successful run.
- `docker compose logs worker` has no repeated exceptions.
- After rerunning `./install.sh --demo`, no duplicate collections, dashboards or questions appear.
