# Security model and non-goals

**Design invariant:** Neither AssetVuln Monitor nor the account used for collection may change any managed Endpoint Central asset. The external ManageEngine and cve.now clients deliberately expose *only* a `.get()` method and reject cleartext HTTP.

## Trust boundaries

- ManageEngine token exists as a private host file and is mounted read-only into the worker, not Metabase/NGINX/PostgreSQL.
- Only NGINX publishes an HTTPS port, bound to `127.0.0.1` by default.
- PostgreSQL is internal-only; no host port binding.
- The Metabase connection to the application database uses `avm_reader` with SELECT on reporting views only.
- Dashboard content is hidden behind Metabase login; no anonymous/public links are provisioned.
- Python worker runs as the host installer’s unprivileged UID/GID (recorded in `.env`), enabling access to the owner-only 0600 token without opening world-read permissions. Its filesystem is read-only with `no-new-privileges`.
- Demo advisories use conspicuously fake CVE identifiers and are never emailed.
- Upstream timeouts and collection errors preserve the existing inventory, rather than deleting assets due to partial reads.

## Residual risks and hardening TODOs

- Docker Compose `.env` passwords are visible to local Docker administrators. Docker administration is privileged; restrict host access.
- The Metabase image's own system permissions and JVM memory are controlled by upstream. Verify the pinned image digest, dependencies, and CVEs before production rollout.
- HTTPS from NGINX terminates at the proxy; private Docker-network service traffic is HTTP by default. Do not place untrusted containers on these networks.
- Local certificate is self-signed; replace with a trusted certificate on production instances.
- Metabase's internal users can modify saved charts when their Metabase role allows it, but they cannot modify Endpoint Central assets through this project.
- Change and audit handling for real vulnerability confirmations require additional workflow support; version matches should be reviewed by security staff.
- Build and upgrade require image supply-chain verification. Test all operational changes in staging, including vendor API compatibility.
