# Configuration reference

Runtime configuration uses **both** `.env` (Compose credentials, bind settings and build index) and `config/application.yaml` (application behavior). It is created from the heavily commented `config/application.example.yaml` during install.

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

Before installing, run `cp example.env .env` and edit `.env`: replace all `CHANGE_ME_*` placeholders with unique strong secrets, set `HOST_UID`/`HOST_GID` from `id -u` / `id -g`, and adjust `PUBLIC_URL`, `BIND_IP`, `HTTPS_PORT` as needed. Installer requires `.env`, protects it with mode `0600`, and never overwrites it. `PIP_INDEX_URL` optionally selects the Python package index used during Docker image builds; use a trusted index. `.env` is intentionally excluded from Git. Install proper TLS files in `secrets/tls` before a network-facing deployment.

## Version mapping

When an inventory entry identifies a package with a verified ecosystem (e.g. PyPI, npm), define exact vendor+name mapping in `config/product-mappings.yaml`. Do not map general software names to unrelated package versions just to increase matches. The conservative engine does **not** currently implement generic CPE-range logic, vendor backport verification, or a full SBOM parser.

## Credentials

In production, create a least-privilege Endpoint Central account/token with only the inventory read scope. Store it in `secrets/manageengine_token` (permission `0600`). Never paste passwords into GitHub issues, screenshots or logs.

## Software identity mappings

**Demo** uses `config/product-mappings.yaml`: two deliberately synthetic identities matching `avm/demo.py`. **Live** must use `config/product-mappings.live.yaml` by setting `PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml` in `.env`. This file starts with `products: []` so that real assets are inventoried but not assigned unverified CVE findings.

Each mapping has four fields: `vendor` and `name` (exact, case-insensitive match against ManageEngine software inventory), and `ecosystem` and `package` (verified identity in the structured CVE advisory). Example **format only**:

```yaml
products:
  - vendor: "Verified Vendor From Inventory"
    name: "Verified Product From Inventory"
    ecosystem: "PyPI"
    package: "verified-package-from-advisory"
```

Do not map unrelated products based on name similarity. A missing mapping does not hide the software from inventory; it prevents unsupported version-based CVE correlation. Vendor patches and backports still require manual verification.

## Independent ManageEngine API test

Before `./install.sh --live`, run `python3 scripts/test_manageengine_api.py` after configuring the HTTPS URL and read-only token. It lists both GET endpoints and checks their initial JSON responses, with PASS/FAIL/SKIP results. Options include `--resource-id 12345` and `--ca-bundle secrets/certs/org-ca.pem`. No Docker or database required; no secrets printed. This is a smoke test, not exhaustive API compatibility validation.

## v0.2 mapping review and normalization

In the `develop/v0.2` branch, the runtime worker matches only **operator-approved** YAML identities, now comparing software vendor/name with Unicode NFKC, case folding and collapsed whitespace. Duplicate approved identities are rejected instead of silently overwritten. The offline `scripts/suggest_mappings.py` produces candidate suggestions and coverage metrics from a CSV export, but **never modifies the YAML, database or findings**. All similar-name suggestions require manual verification. See [normalization guide](SOFTWARE-NORMALIZATION.md).
