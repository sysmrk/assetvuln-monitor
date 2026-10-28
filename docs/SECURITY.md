# V3 security model, trust boundaries and outstanding controls

## Non-negotiable invariant

AssetVuln Monitor is **read-only toward managed Endpoint Central assets**. External inventory, CVE and public threat-intelligence clients support GET-only operations. No patch deployment, SSH execution, configuration changes, vulnerability exploitation, or remote endpoint actions are implemented. Metabase bootstrap can issue authenticated POST/PUT requests **only to the local Metabase service** to create dashboard configuration; this is not an Endpoint Central action.

## Separation and secrets

- V3 defaults to a different Compose project (assetvuln-monitor-v03) and port (8445) from V1/V2. The installer rejects the two legacy project names and checks the effective Compose name.
- Initial Demo .env is generated locally with distinct random passwords and file mode 0600. Existing custom credentials are retained.
- Credentials and asset context are never committed to Git. The installation is bound to the selected Demo or Live data mode using a local marker.
- Endpoint Central token is in a private, read-only file mounted into the Worker, not exposed to NGINX or Metabase.
- Worker uses a non-root host UID/GID, no-new-privileges, and a read-only root filesystem. PostgreSQL is on an internal network, with no host port.
- NGINX is the only published network-facing service (loopback HTTPS by default), with TLS v1.2/v1.3 support.
- Metabase's application-data role (avm_reader) has SELECT on approved reporting views. It does not own or have write permissions on raw inventory, finding, audit or approval tables.
- Docker administrators and anyone able to execute arbitrary commands inside Worker are highly privileged and may access credentials/application DB; restrict access and log host administration.

## Evidence and false-positive controls

- Only operator-approved exact package identities may yield findings, and only when machine-readable affected-version evidence matches the installed version. A fuzzy identity suggestion never triggers findings.
- Findings are **potential exposure**, not proof of actual vulnerable installation or exploitable service. Vendor backports, patched distribution packages and deployment configuration must be considered.
- Evidence snapshots include raw software identity, observed version, approved package and structured ranges. Candidate fixed versions are derived only from explicit machine-readable fixed events; never automatically applied.
- Missing or partial source inventory cannot legitimately prove that a vulnerability is resolved. V3 distinguishes **not_observed** from confirmed remediation and records reappearance events.
- EPSS is a provider-supplied statistical probability estimate; AVM's weighted priority points are **not** a probability, a certified risk assessment or a warranty of attack prevention. Unavailable source signals are explicitly flagged as missing.

## Public sources and failure behavior

- The Live Worker checks CISA KEV and FIRST EPSS once per day (configurable). CISA requests are fixed-origin HTTPS GET; FIRST EPSS uses the official daily compressed CSV download. OSV uses a fixed public HTTPS POST QueryBatch for read-only lookups, while Endpoint Central remains GET-only.
- An invalid/incomplete CISA feed or failed FIRST EPSS request prevents updating that intelligence cycle and preserves the last good signals. The next attempt occurs on a limited retry schedule.
- Demo never contacts real Endpoint Central, CISA or FIRST. Synthetic CVEs are identified as CVE-DEMO-*.
- The cve.now feed reader is limited to a configurable recent-page window, **not historical completeness**. An absent CVE match cannot establish absence of risk.
- Source changes and internal CA problems need staging verification. Do not disable TLS validation to work around source errors.

## Approvals and state changes

- Mapping proposal review requires privileged access to the application's database through the Worker CLI. A separate manually entered reviewer identifier is required for manual proposals.
- Risk acceptance is explicitly requested by a privileged operator, has a maximum 180-day duration and records actor/reason/timestamps.
- Reviewer/actor fields are **self-declared identifiers**. There is currently NO cryptographic identity verification, SSO, strong RBAC or independently immutable audit storage. Two-person checks are administrative workflow guidance, not a security boundary.
- Mapping and FindingEvent history is application-level append-only under normal code paths, but a database owner can still mutate it. For regulated workflows, add an external tamper-evident audit target and authorized reviewers.
- No public web endpoint permits mutation of mapping approvals or Finding workflow.

## Risks to address before production use

1. Validate Endpoint Central on-premises API schemas, pagination, rate limits, CA chain and read-only privileges against the actual deployed version.
2. Validate the structured CVE provider and upstream KEV/EPSS feeds end to end, including timeouts, response-size limits and source freshness.
3. Use real TLS certificates, review reverse-proxy headers and restrict exposure beyond localhost.
4. Add integrated SSO/RBAC and policy-bound risk acceptance; current operator CLI relies on shell/database access.
5. Verify immutable audit forwarding, patch/version corroboration, product identity and vendor backport handling before relying on findings.
6. Test PostgreSQL schema upgrades, backup/restore, concurrency and Metabase dashboard provisioning in staging. GitHub Actions covers unit tests, temporary PostgreSQL, static Compose configuration and a successful disposable **synthetic Docker/Metabase Demo startup**. It does not validate a real corporate Endpoint Central system or production network configuration.
7. Control inventory and report sensitivity; Metabase viewers may see hostnames, installed software, owners and proposed vulnerabilities.
8. Verify pinned container image digests, supply-chain integrity and current CVEs of the runtime itself.

See [one-command installation](INSTALLATION.md), [V3 operations](V03-OPERATIONS.md) , [mapping governance](MAPPING-REVIEW.md) and [source provenance](V03-MULTISOURCE.md).
