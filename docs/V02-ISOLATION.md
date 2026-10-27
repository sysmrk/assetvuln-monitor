# v0.2 — Isolated installation alongside v0.1

This guide applies **only** to the `develop/v0.2` branch. v0.1 remains on `main`.

## Isolation design

- v0.1 Compose project: `assetvuln-monitor` (unchanged).
- v0.2 Compose project: `assetvuln-monitor-v02` (configurable via `COMPOSE_PROJECT_NAME`).
- v0.1 HTTPS port: `8443`; v0.2 default: `8444`.
- Compose-scoped named volumes, networks, containers, and generated resource names are separated by project name.
- **Do not set the v0.2 project name to `assetvuln-monitor`.** The v0.2 installer rejects it.
- **Never point both versions at the same external PostgreSQL database or shared secret files.** Current default Compose uses project-scoped PostgreSQL storage.

## Prepare v0.2 checkout

```bash
git clone --branch develop/v0.2 https://github.com/sysmrk/assetvuln-monitor.git assetvuln-monitor-v02
cd assetvuln-monitor-v02
cp example.env .env
nano .env
```

Replace every `CHANGE_ME_*` placeholder with a unique secret. Confirm:

```dotenv
COMPOSE_PROJECT_NAME=assetvuln-monitor-v02
BIND_IP=127.0.0.1
HTTPS_PORT=8444
PUBLIC_URL=https://localhost:8444
```

Keep a separate `config/application.yaml`, API token, TLS keys and mappings in this checkout. If you are using Live, follow `docs/INSTALLATION.md` for the GET-only API preflight and verified live mappings.

## Read-only configuration preflight

After creating `.env` and `config/application.yaml`, run:

```bash
docker compose config --quiet
docker compose config --format json | python3 -c 'import json,sys; d=json.load(sys.stdin); print("project:",d["name"]); print("HTTPS bindings:",d["services"]["nginx"]["ports"])'
```

Confirm the project is `assetvuln-monitor-v02` and HTTPS is bound to `127.0.0.1:8444`. **Do not run** `docker compose down -v` against an existing environment.

## Automated Compose collision check

Once you have **two separate checkouts**, create their private `.env` and `config/application.yaml` files, then run from the v0.2 checkout:

```bash
python3 scripts/check_compose_isolation.py \
  --baseline-dir /opt/src/assetvuln-monitor \
  --candidate-dir .
```

This **read-only** command runs `docker compose config --format json` for both checkouts. It compares project names, named volumes, Docker networks, published host ports, named containers and bind-mount source paths. A conflict prints `FAIL` and returns exit code 1; failure to resolve a Compose file returns 2. No containers start or stop and the tool does not print expanded passwords. A PASS verifies **configuration isolation only**, not actual runtime behavior or operational backups.

To run only the unit tests without Docker:

```bash
python3 -m pytest -q tests/test_compose_isolation.py
```

## Start and stop

```bash
./install.sh --demo
docker compose ps
docker compose logs --tail=100 worker
# Stop only the v0.2 project, retaining data:
docker compose stop
```

If both versions run on the same Docker daemon, run the collision checker and verify resolved Compose project names before any `up`, `stop`, `down`, or backup operation. The new namespace and port separation have been implemented in Git but **have not been runtime-tested** here.

## Rollback

Stop v0.2 with `docker compose stop` from its own checkout. v0.1 should remain untouched because Compose resources have different project names. Do not remove volumes until backups and project ownership have been checked.
