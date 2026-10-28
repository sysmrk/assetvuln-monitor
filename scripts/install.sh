#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
umask 077

usage() {
  printf '%s\n' 'Usage: ./install.sh [--demo|--live] [--skip-build]' '  --demo: synthetic inventory and CVEs, NO ManageEngine required (default)' '  --live: use Endpoint Central inventory and the configured public intelligence sources' '  --skip-build: use an already built local worker image (for offline/restricted Docker builds)'
}
mode=demo
skip_build=false
mode_seen=false
for arg in "$@"; do
  case "$arg" in
    --demo|--live)
      if [[ "$mode_seen" == true ]]; then usage; exit 2; fi
      mode="${arg#--}"
      mode_seen=true
      ;;
    --skip-build) skip_build=true ;;
    *) usage; exit 2 ;;
  esac
done

for program in docker openssl python3; do
  if ! command -v "$program" >/dev/null 2>&1; then
    echo "ERROR: $program is required." >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo 'ERROR: Docker Compose v2 is required.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo 'ERROR: Docker daemon is inaccessible.' >&2
  exit 1
fi

# Configure fresh Demo automatically. Never echo auto-generated passwords.
python3 scripts/prepare_env.py --mode "$mode"
project_name="$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' .env | tail -n 1 | tr -d '"')"
if [[ ! "$project_name" =~ ^[a-z0-9][a-z0-9_-]*$ ||
      "$project_name" == assetvuln-monitor ||
      "$project_name" == assetvuln-monitor-v02 ]]; then
  echo 'ERROR: Use a distinct valid COMPOSE_PROJECT_NAME for v0.3.' >&2
  exit 1
fi
if [[ -n "${COMPOSE_PROJECT_NAME:-}" && "$COMPOSE_PROJECT_NAME" != "$project_name" ]]; then
  echo 'ERROR: Shell COMPOSE_PROJECT_NAME conflicts with .env.' >&2
  exit 1
fi

# Never attach a fresh checkout to an existing project's PostgreSQL volume.
# An intentional recovery must use a verified backup/restore procedure instead.
if [[ ! -f secrets/installation-mode ]] &&
   docker volume inspect "${project_name}_postgres_data" >/dev/null 2>&1; then
  echo 'ERROR: This Compose project already owns a PostgreSQL volume. Use a new project name to avoid data mixing.' >&2
  exit 1
fi

# Prevent accidentally reusing a Demo database as Live (or vice versa).
if [[ -f secrets/installation-mode ]]; then
  installed_mode="$(cat secrets/installation-mode)"
  if [[ "$installed_mode" != "$mode" ]]; then
    echo 'ERROR: Cannot switch an existing project between Demo and Live. Use a new Compose project/volume.' >&2
    exit 1
  fi
fi

mkdir -p secrets/tls secrets/certs
if [[ ! -f config/application.yaml ]]; then
  cp config/application.example.yaml config/application.yaml
fi
if [[ ! -f config/asset-context.yaml ]]; then
  cp config/asset-context.example.yaml config/asset-context.yaml
fi
if [[ "$mode" == demo ]]; then
  sed -i 's/^  mode: live *# demo | live/  mode: demo                       # demo | live/' config/application.yaml
else
  sed -i 's/^  mode: demo *# demo | live/  mode: live                       # demo | live/' config/application.yaml
fi
if [[ ! -f secrets/manageengine_token ]]; then
  : > secrets/manageengine_token
fi

# Validate required credentials without printing secret values or modifying .env.
# Do not source .env as shell code: validate with Compose interpolation instead.
required=(POSTGRES_PASSWORD APP_DB_PASSWORD REPORT_DB_PASSWORD MB_DB_PASSWORD METABASE_ADMIN_PASSWORD)
for key in "${required[@]}"; do
  value="$(docker compose --profile setup config --format json 2>/dev/null | python3 -c '
import json,sys
try:
    c=json.load(sys.stdin)
    k=sys.argv[1]
    mapping={"POSTGRES_PASSWORD":("postgres","POSTGRES_PASSWORD"),"APP_DB_PASSWORD":("worker","APP_DB_PASSWORD"),"REPORT_DB_PASSWORD":("bootstrap","REPORT_DB_PASSWORD"),"MB_DB_PASSWORD":("metabase","MB_DB_PASS"),"METABASE_ADMIN_PASSWORD":("bootstrap","METABASE_ADMIN_PASSWORD")}
    service,field=mapping[k]
    print(c["services"][service]["environment"][field])
except Exception:
    sys.exit(1)
' "$key")" || { echo "ERROR: Invalid Compose configuration or missing $key in .env" >&2; exit 1; }
  if [[ -z "$value" || "$value" == CHANGE_ME* ]]; then
    echo "ERROR: Set a strong value for $key in .env before installation." >&2
    exit 1
  fi
done
chmod 600 .env secrets/manageengine_token config/application.yaml
if [[ "$(id -u)" == 0 ]]; then
  # Root-launched setup must not silently run the Worker as root.
  worker_uid="$(sed -n 's/^HOST_UID=//p' .env | tail -n 1)"
  worker_gid="$(sed -n 's/^HOST_GID=//p' .env | tail -n 1)"
  if [[ "$worker_uid" == 0 || "$worker_gid" == 0 ]]; then
    echo 'ERROR: Root-run installation requires a non-root HOST_UID/HOST_GID in .env.' >&2
    exit 1
  fi
  chown "$worker_uid:$worker_gid" secrets/manageengine_token config/application.yaml
fi
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

# Keep synthetic demo mappings out of real inventory correlation.
mapping_file="$(sed -n 's/^PRODUCT_MAPPINGS_FILE=//p' .env | tail -n 1)"
mapping_file="${mapping_file%\"}"
mapping_file="${mapping_file#\"}"
if [[ "$mode" == live ]]; then
  if [[ "$mapping_file" != "./config/product-mappings.live.yaml" ]]; then
    echo 'ERROR: For Live, set PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml in .env.' >&2
    exit 1
  fi
elif [[ -n "$mapping_file" && "$mapping_file" != "./config/product-mappings.yaml" ]]; then
  echo 'ERROR: For Demo, set PRODUCT_MAPPINGS_FILE=./config/product-mappings.yaml in .env.' >&2
  exit 1
fi

echo 'Checking Compose configuration...'
docker compose config --quiet
resolved_name="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
if [[ "$resolved_name" != "$project_name" ]]; then
  echo 'ERROR: Resolved Docker project does not match .env isolation identity.' >&2
  exit 1
fi
# Create the mode marker before starting any container (also protects failed first installs).
printf '%s\n' "$mode" > secrets/installation-mode
chmod 600 secrets/installation-mode
if [[ "$skip_build" == true ]]; then
  worker_image="${project_name}-worker:latest"
  if ! docker image inspect "$worker_image" >/dev/null 2>&1; then
    echo "ERROR: Missing local image $worker_image. Build it first using docker build -f docker/Dockerfile ." >&2
    exit 1
  fi
  echo 'Starting services using the existing worker image (no build)...'
  docker compose up -d --no-build postgres worker metabase nginx
else
  echo 'Building application and starting services...'
  docker compose up -d --build postgres worker metabase nginx
fi

echo 'Provisioning the Metabase account, reporting connection and dashboards...'
if ! docker compose --profile setup run --rm bootstrap; then
  echo 'ERROR: Metabase provisioning failed; run: docker compose --profile setup run --rm bootstrap' >&2
  exit 1
fi

echo
echo '==============================================================='
echo '  AssetVuln Monitor - installation finished'
echo '  URL: see PUBLIC_URL in .env'
echo '  Login email: see METABASE_ADMIN_EMAIL in .env'
echo '  Initial admin password: view locally with grep ^METABASE_ADMIN_PASSWORD= .env'
echo "  Data source mode: $mode"
echo '  Self-signed TLS warning: expected for local WSL demo.'
echo '  View logs: docker compose logs -f worker'
echo '  Check status: docker compose ps'
echo '==============================================================='
