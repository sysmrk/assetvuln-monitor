# Configuration reference

`config/application.yaml` is the only ordinary runtime configuration file. It is created from the heavily commented `config/application.example.yaml` during install.

- `application.mode`: `demo` or `live`; use `demo` in WSL without ManageEngine.
- `manageengine.url`: HTTPS base URL (example `https://ec.example.org:8383`). Do **not** add an `/api` suffix.
- `manageengine.token_file`: default `/run/secrets/manageengine_token`; this is read-only inside the container.
- `manageengine.verify_tls`: must stay `true` in live mode.
- `manageengine.ca_bundle`: optional container path to CA file mounted from `secrets/certs`.
- `manageengine.sync_minutes`: inventory refresh cadence, default 360 minutes.
- `cve.url`: default `https://cve.now`.
- `cve.sync_minutes`: advisory polling interval, default 30 minutes.
- `cve.max_pages_per_poll`: bounded number of latest CVE pages. **Not** a guarantee of historical coverage.
- `matching.mappings_file`: explicit package identity mapping file mounted into the worker.
- `notifications.email_enabled`: default `false` (never sends in demo mode). SMTP only supports STARTTLS; add SMTP_USER and SMTP_PASSWORD environment variables for optional authentication.

`.env` is generated automatically, mode `0600`, and intentionally not committed. It holds the PostgreSQL / Metabase passwords and localhost bind settings. For multiuser deployments, replace `PUBLIC_URL`, `BIND_IP`, and `HTTPS_PORT`, install proper TLS files in `secrets/tls`, then rerun.

## Version mapping

When an inventory entry identifies a package with a verified ecosystem (e.g. PyPI, npm), define exact vendor+name mapping in `config/product-mappings.yaml`. Do not map general software names to unrelated package versions just to increase matches. The conservative engine does **not** currently implement generic CPE-range logic, vendor backport verification, or a full SBOM parser.

## Credentials

In production, create a least-privilege Endpoint Central account/token with only the inventory read scope. Store it in `secrets/manageengine_token` (permission `0600`). Never paste passwords into GitHub issues, screenshots or logs.
