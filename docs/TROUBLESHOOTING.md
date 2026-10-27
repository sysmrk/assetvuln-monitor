# V3 troubleshooting — shortest safe path

Use the current V3 checkout (not V1 or V2). Never copy a populated .env or a database volume across Demo/Live or across project versions without a tested migration.

| Symptom | Safe action |
|---|---|
| Fresh Demo needs passwords / missing .env | Run ./install.sh --demo. V3 generates private local credentials automatically; look up the Metabase login in .env. |
| Docker or Compose unavailable | Verify docker info and docker compose version. V3 requires Compose v2. |
| Port 8445 already taken | Edit HTTPS_PORT and PUBLIC_URL in local .env; keep the Compose project name unique. |
| Browser TLS warning | Expected only with the default localhost self-signed certificate; replace it before exposing the service. |
| Installer refuses V1/V2 project name | Set a new COMPOSE_PROJECT_NAME in .env, never assetvuln-monitor or assetvuln-monitor-v02. |
| Installer refuses switching Demo to Live | Correct. Create a new checkout and Compose project; the original database contains synthetic data. |
| Metabase setup or dashboards missing | Inspect docker compose logs worker metabase; after Worker schema initialization rerun docker compose --profile setup run --rm bootstrap. |
| PostgreSQL connection fails | Inspect docker compose logs postgres. Never fix it by deleting volumes. |
| Live Endpoint Central API fails | Run python3 scripts/test_manageengine_api.py; verify the exact API path, read-only token, HTTPS URL and trusted internal CA. |
| Source sync shows no current data | Check reporting.ingestion_health / reporting.data_quality_sync_freshness and worker logs. Missing data cannot establish remediation. |
| No live CVE findings | The approved Live mapping catalogue starts empty; approve real software identities and verify cve.now structured affected-version ranges. Empty results do **not** imply no vulnerabilities. |
| No automatic similarity suggestions | The similarity engine compares to an existing approved catalogue; an empty approved catalogue intentionally produces no candidates. Create a manual proposal first. |
| No CISA/EPSS metrics | Public threat intelligence runs only in Live on a daily schedule; verify outbound HTTPS/DNS and worker logs. A failed request preserves old values. |
| Many unknown criticality / exposure values | Expected until verified source_id entries are added to config/asset-context.yaml. The application never guesses these fields. |
| Mapping approval seems ignored | The Worker applies approved DB identities at the next successful inventory synchronization. The CLI itself never changes old software rows. |
| Potential findings marked not_observed | This is a conservative state after a successful inventory; it does not assert that a patch was installed or issue fully resolved. |
| Risk acceptance rejected | Actor/reason must be valid, Finding active, expiry within 180 days; the action requires privileged DB access. |
| Risk scores appear low despite missing signals | Missing CVSS, EPSS or asset context are labelled as unknown, not interpolated. Check the evidence factors and source freshness. |
| Risk Intelligence dashboard not visible | Confirm the Worker schema is upgraded, then rerun bootstrap as above. |
| Container restarts too often | docker compose logs --tail=200 worker; check configuration syntax, database readiness and source exceptions. |
| Out of WSL memory | Increase WSL/Docker RAM allocation; Metabase is a JVM application. |

Useful **read-only** commands:

~~~bash
docker compose config --quiet
docker compose ps
docker compose logs --tail=200 worker
docker compose exec worker python -m avm.ops queue --limit 10
docker compose exec worker python -m avm.ops simulate --top 10
docker compose exec worker python -m avm.review_cli list --status pending
~~~

To preserve data, use ./scripts/backup.sh and never casually invoke docker compose down -v. Do not share .env, token files, private keys, backups or raw software inventory in support discussions.
