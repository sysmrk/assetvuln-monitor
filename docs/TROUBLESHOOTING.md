# Troubleshooting

| Symptom | Action |
|---|---|
| `.env` missing or `CHANGE_ME_*` password | Run `cp example.env .env`, edit all required credentials, then rerun installer; it will not overwrite your settings |
| HTTPS port not published when frontend is internal | NGINX must also attach to the non-internal `ingress` bridge; keep the Metabase-only `frontend` internal. Verify with `docker port assetvuln-monitor-nginx-1` |
| Docker image build cannot reach PyPI | Set a trusted `PIP_INDEX_URL` in `.env` and rerun; avoid untrusted package mirrors for production |
| Docker not found | Install Docker Desktop, enable WSL integration, restart your Ubuntu WSL shell |
| `docker compose` unavailable | Upgrade to Docker Compose v2 |
| Browser shows certificate warning | Expected for WSL self-signed TLS; install a trusted cert in production |
| Dashboard initial setup failed | Run `docker compose --profile setup run --rm bootstrap`; inspect `docker compose logs metabase worker` |
| Postgres connection refused | `docker compose logs postgres`; verify no accidental volume loss |
| ManageEngine API smoke test FAIL/SKIP | Run `python3 scripts/test_manageengine_api.py`; check HTTPS URL, read-only token, internal CA, HTTP status and JSON response shape. For an empty scan, use `--resource-id ID` to test softwareInfo independently |
| Inventory empty in live mode | Confirm least-privilege token, DNS, custom CA, version-compatible `/dcapi` endpoints; check worker logs |
| Many unmapped software entries | Add verified exact software→package mappings; do not treat unmapped as safe |
| No CVE findings in live mode | Verify current cve.now response schema, affected package/range data and mappings; zero is NOT proof of safety |
| Metabase can't connect reports | Ensure the `worker` initialized reporting views; run `docker compose logs worker` |
| Running out of memory on WSL | Allocate adequate RAM to Docker Desktop/WSL (Metabase is a JVM application) |

Do not share `.env`, `secrets/manageengine_token`, or database backups when requesting support.
