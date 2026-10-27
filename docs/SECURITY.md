# Security model and non-goals

**Design invariant:** Neither AssetVuln Monitor nor the account used for collection may change any managed Endpoint Central asset. The external ManageEngine and cve.now clients deliberately expose *only* a `.get()` method and reject cleartext HTTP.

## Trust boundaries

- ManageEngine token exists as a private host file and is mounted read-only into the worker, not Metabase/NGINX/PostgreSQL.
- Only NGINX publishes an HTTPS port, bound to `127.0.0.1` by default. NGINX is attached to the non-internal `ingress` bridge for Docker port publishing and to the internal `frontend` network for Metabase proxying; Metabase is not attached to `ingress`.
- PostgreSQL is internal-only; no host port binding.
- The Metabase connection to the application database uses `avm_reader` with SELECT on reporting views only.
- Dashboard content is hidden behind Metabase login; no anonymous/public links are provisioned.
- Python worker runs as the host installer’s unprivileged UID/GID (recorded in `.env`), enabling access to the owner-only 0600 token without opening world-read permissions. Its filesystem is read-only with `no-new-privileges`.
- Demo advisories use conspicuously fake CVE identifiers and are never emailed.
- Upstream timeouts and collection errors preserve the existing inventory, rather than deleting assets due to partial reads.

## Residual risks and hardening TODOs

- Copy `example.env` to `.env` before installation, replace all placeholder credentials, and never commit the populated file. The installer does not overwrite existing `.env` values.
- Docker Compose `.env` passwords are visible to local Docker administrators. Docker administration is privileged; restrict host access.
- The Metabase image's own system permissions and JVM memory are controlled by upstream. Verify the pinned image digest, dependencies, and CVEs before production rollout.
- HTTPS from NGINX terminates at the proxy; private Docker-network service traffic is HTTP by default. Do not place untrusted containers on these networks.
- Local certificate is self-signed; replace with a trusted certificate on production instances.
- Metabase's internal users can modify saved charts when their Metabase role allows it, but they cannot modify Endpoint Central assets through this project.
- Change and audit handling for real vulnerability confirmations require additional workflow support; version matches should be reviewed by security staff.
- Build and upgrade require image supply-chain verification. Test all operational changes in staging, including vendor API compatibility.

## Mapping review trust boundary (v0.2)

- The new reviewer CLI runs only inside the privileged Worker execution context and writes local application PostgreSQL review records; it never sends mutation requests to Endpoint Central.
- Suggestions are **not trusted mappings**. Approval inserts a separate unique approved identity, used at the next inventory sync. Rejected candidates cannot be automatically reopened.
- `avm_reader` receives SELECT on approved `reporting.*` views only, including review queue/audit, and has **no write permission** on mapping tables. Restrict report access because software inventories and reviewer identifiers are sensitive.
- Manual proposals enforce a distinct proposer/reviewer **identifier**, not real cryptographic authentication. Someone with Worker shell or application database credentials could impersonate identities or modify application-level audit records. SSO/RBAC, WORM logging and external audit forwarding are still required for enterprise readiness.
- Any update to a reviewed identity or approved mapping should go through future controlled revocation/change-management features, never ad hoc database edits.
