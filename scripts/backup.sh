#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
umask 077
if [[ ! -f .env ]]; then echo 'ERROR: Install first.' >&2; exit 1; fi
mkdir -p backups
folder="backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$folder"
echo 'Backing up application data and Metabase dashboards...'
docker compose exec -T postgres pg_dump -U postgres --format=custom --no-owner --dbname=avm > "$folder/avm.dump"
docker compose exec -T postgres pg_dump -U postgres --format=custom --no-owner --dbname=metabase > "$folder/metabase.dump"
chmod 600 "$folder"/*.dump
echo "Backup saved in $folder"
