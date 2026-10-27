#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
folder="${1:-}"
if [[ -z "$folder" || ! -s "$folder/avm.dump" || ! -s "$folder/metabase.dump" ]]; then
  echo 'Usage: scripts/restore.sh backups/YYYYMMDDTHHMMSSZ' >&2
  exit 2
fi
printf '%s\n' 'WARNING: Restoration DELETES/REPLACES current application and Metabase contents.'
read -r -p 'Type RESTORE to proceed: ' reply
if [[ "$reply" != RESTORE ]]; then echo 'Cancelled'; exit 1; fi

docker compose stop worker metabase nginx
docker compose up -d postgres
# Restore into existing initialized databases. Recreates application objects.
docker compose exec -T postgres pg_restore -U postgres --clean --if-exists --no-owner -d avm < "$folder/avm.dump"
docker compose exec -T postgres pg_restore -U postgres --clean --if-exists --no-owner -d metabase < "$folder/metabase.dump"
# Ensure the database's logical owner can manage restored objects.
docker compose exec -T postgres psql -U postgres -d avm -c 'REASSIGN OWNED BY postgres TO avm_app;'
docker compose exec -T postgres psql -U postgres -d metabase -c 'REASSIGN OWNED BY postgres TO mb_user;'
docker compose up -d worker metabase nginx
echo 'Restore submitted. Check docker compose ps and then rerun setup if needed.'
