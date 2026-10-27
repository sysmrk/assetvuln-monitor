#!/bin/sh
set -eu
# Runs ONLY when the PostgreSQL data volume is initialized the first time.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_pass="$APP_DB_PASSWORD" -v report_pass="$REPORT_DB_PASSWORD" -v mb_pass="$MB_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE avm_app LOGIN PASSWORD %L', :'app_pass') \gexec
SELECT format('CREATE ROLE avm_reader LOGIN PASSWORD %L', :'report_pass') \gexec
SELECT format('CREATE ROLE mb_user LOGIN PASSWORD %L', :'mb_pass') \gexec
ALTER DATABASE avm OWNER TO avm_app;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
CREATE DATABASE metabase OWNER mb_user;
SQL
