#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
umask 077

usage() {
  printf '%s\n' 'Usage: ./install.sh [--demo|--live]' '  --demo: synthetic inventory and CVEs, NO ManageEngine required (default)' '  --live: use your configured ManageEngine API token and cve.now'
}
mode=demo
case "${1:-}" in
  ''|--demo) mode=demo ;;
  --live) mode=live ;;
  *) usage; exit 2 ;;
esac

for program in docker openssl; do
  if ! command -v "$program" >/dev/null 2>&1; then
    echo "ERROR: $program is required. Please install it first." >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo 'ERROR: Docker Compose v2 plugin is required.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo 'ERROR: Docker daemon is not accessible. Start Docker Desktop/Engine.' >&2
  exit 1
fi
mkdir -p secrets/tls secrets/certs
if [[ ! -f config/application.yaml ]]; then
  cp config/application.example.yaml config/application.yaml
fi
if [[ "$mode" == demo ]]; then
  sed -i 's/^  mode: live *# demo | live/  mode: demo                       # demo | live/' config/application.yaml
fi
if [[ "$mode" == live ]]; then
  sed -i 's/^  mode: demo *# demo | live/  mode: live                       # demo | live/' config/application.yaml
fi
if [[ ! -f secrets/manageengine_token ]]; then
  : > secrets/manageengine_token
fi
if [[ ! -s .env ]]; then
  cat > .env <<ENV
# PRIVATE GENERATED CREDENTIALS. Keep chmod 600 and NEVER upload this file.
HOST_UID=$(id -u)
HOST_GID=$(id -g)
POSTGRES_PASSWORD=$(openssl rand -hex 30)
APP_DB_PASSWORD=$(openssl rand -hex 30)
REPORT_DB_PASSWORD=$(openssl rand -hex 30)
MB_DB_PASSWORD=$(openssl rand -hex 30)
METABASE_ADMIN_EMAIL=admin@example.local
METABASE_ADMIN_PASSWORD=$(openssl rand -hex 24)
BIND_IP=127.0.0.1
HTTPS_PORT=8443
PUBLIC_URL=https://localhost:8443
ENV
fi
chmod 600 .env secrets/manageengine_token config/application.yaml
if [[ ! -s secrets/tls/tls.key || ! -s secrets/tls/tls.crt ]]; then
  echo 'Generating temporary TLS certificate for localhost (browser warning is expected)...'
  openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
    -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout secrets/tls/tls.key -out secrets/tls/tls.crt >/dev/null 2>&1
fi
chmod 600 secrets/tls/tls.key

if [[ "$mode" == live ]]; then
  if [[ ! -s secrets/manageengine_token ]]; then
    echo 'ERROR: Add your read-only Inventory.READ token to secrets/manageengine_token.' >&2
    exit 1
  fi
  if grep -q 'endpoint-central.example.org' config/application.yaml; then
    echo 'ERROR: Replace the sample ManageEngine URL in config/application.yaml.' >&2
    exit 1
  fi
fi

echo 'Checking Compose configuration...'
docker compose config --quiet
echo 'Building application and starting services...'
docker compose up -d --build postgres worker metabase nginx

echo 'Provisioning the Metabase account, reporting connection and dashboards...'
if ! docker compose --profile setup run --rm bootstrap; then
  echo 'ERROR: Metabase provisioning failed; run: docker compose --profile setup run --rm bootstrap' >&2
  exit 1
fi

echo
echo '==============================================================='
echo '  AssetVuln Monitor - installation finished'
echo '  URL: https://localhost:8443'
echo '  Login email: admin@example.local'
echo '  Initial admin password: stored in .env (METABASE_ADMIN_PASSWORD)'
echo "  Data source mode: $mode"
echo '  Self-signed TLS warning: expected for local WSL demo.'
echo '  View logs: docker compose logs -f worker'
echo '  Check status: docker compose ps'
echo '==============================================================='
