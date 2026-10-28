# Security model & production checklist

AssetVuln Monitor is designed to be **read-only toward managed endpoints**. It writes its own inventory, evidence, audit records, application configuration and Metabase metadata locally. This guide explains **what that guarantee includes, what it does not include, and what to check before connecting real company assets**.

[Installation](INSTALLATION.md) · [Configuration](CONFIGURATION.md) · [Operational commands](COMMANDS.md) · [Multi-source provenance](V03-MULTISOURCE.md)

## 1. The trust boundary, in one picture

~~~mermaid
flowchart LR
    subgraph CORP["Company network"]
        EC["Endpoint Central<br/>Inventory-only token"]
    end
    subgraph HOST["AVM Docker host"]
        NG["NGINX HTTPS<br/>127.0.0.1 by default"]
        MB["Metabase UI<br/>reporting views only"]
        W["Python Worker"]
        DB[("PostgreSQL<br/>application + Metabase DB")]
        NG --> MB
        MB -->|"read-only reporting role"| DB
        W -->|"writes local evidence, findings and audit"| DB
    end
    subgraph PUBLIC["Public sources"]
        OSV["OSV · cve.now"]
        NVD["NVD · EUVD"]
        PRI["FIRST EPSS · CISA KEV"]
    end
    W -->|"HTTPS GET, inventory only"| EC
    W -->|"HTTPS fetch; OSV querybatch uses POST"| OSV
    W -->|"HTTPS GET"| NVD
    W -->|"HTTPS GET"| PRI
~~~

**Managed endpoint actions:** the Endpoint Central connector uses GET-only inventory endpoints; no patch deployment, endpoint shell, remote execution or write API exists in the intended application workflow. Public OSV QueryBatch uses **POST for a read-only lookup**, not a remote mutation.

**Local actions:** Worker legitimately writes to PostgreSQL; install/bootstrap scripts create files and Metabase dashboards; backup/restore tools write or replace local data. **Read-only toward managed assets does not mean every command is read-only.**

## 2. Secrets and accounts

The installer generates **separate, random local passwords** and stores them in a private **.env**. It does not print passwords while generating them. Private token/config files are mounted into the Worker as read-only bind mounts.

| Secret / access | Recommended control |
|---|---|
| Endpoint Central token | Dedicated **inventory-only** account; no admin, patch or remote execution permission |
| **secrets/manageengine_token** | Local file permission 0600; never commit or paste into tickets |
| **.env** | Local file permission 0600; private database credentials and admin password |
| PostgreSQL | Private internal Docker network; no host port published by default |
| **avm_app** database role | Local application writes, not Metabase reporting |
| **avm_reader** database role | SELECT only on dedicated reporting views |
| Metabase admin | Trusted organization identity; use a strong credential and protected network access |
| TLS private key | Local secret path; replace demo certificate for any shared deployment |
| Backups / exported inventory | Confidential organizational security data; encrypt/store with appropriate controls |

**Do not assume** that the **docker** group is unprivileged; its members generally have root-equivalent control over the Docker host.

### Important limitation: operator identity

The mapping-review and risk-acceptance CLIs accept an **actor string supplied by the caller**. There is no integrated SSO, cryptographic signoff or per-operator application RBAC for these privileged operations. The application audit trail is useful, but a privileged PostgreSQL administrator can change it. Limit shell/container/database access and use your organizational approval system.

## 3. Network exposure and TLS

The default NGINX publication is **127.0.0.1:8445** for Demo and the separately configured local port for Live. This is intentional.

- **Do not set BIND_IP=0.0.0.0 merely for convenience.** A public bind expands attack surface and can interact unexpectedly with host firewall rules.
- For initial remote access, use an **SSH tunnel** rather than publishing Metabase to an entire network.
- The generated localhost certificate is **self-signed** and suitable only for a temporary local test. Replace it with a certificate trusted by your company's browsers before network-facing use.
- Place database and bootstrap credentials on private networks; do not expose Metabase's underlying report database to end users.
- Continue using **TLS verification** for Endpoint Central. For a private CA, mount the PEM under **secrets/certs/** and set **manageengine.ca_bundle** to its in-container path.
- Review outbound traffic to cve.now, OSV, NVD, EUVD, FIRST and CISA. Failures should be visible as source-sync errors; they must not erase valid last-known data.

## 4. Data sent to external providers

**The most important privacy distinction:**

- Endpoint Central sees inventory requests about your managed devices, authenticated by your least-privilege token.
- **OSV receives approved unique package ecosystem/name/version tuples** for vulnerability lookup. AVM does **not** send hostname, IP address, source asset ID, domain or user identity in an OSV QueryBatch request.
- NVD/EUVD/cve.now collection retrieves public advisory information without uploading your full corporate inventory.
- FIRST's daily CSV downloads public EPSS scores; CISA's catalog download fetches public KEV data.
- Application DB and Metabase contain **private host and software inventory** and should be treated as confidential.

**Package names and versions can still reveal a company's technology stack**, even without hostnames. Obtain explicit egress and information-sharing approval before enabling OSV in a restricted corporate network.

Demo fixtures are locally generated and **do not call these providers**.

## 5. Detection integrity: avoiding false positives

1. An exact, reviewed software→package identity is required before correlation.
2. A source must provide a supported affected-version range or exact package/version match.
3. Name similarity alone cannot approve identity or assert vulnerability.
4. NVD CPE applicability is **not assumed** to be equivalent to OSV/PURL package matches; EUVD free-text product descriptions do not independently create Findings.
5. FIRST EPSS and CISA KEV are **priority signals**, not software-version matching evidence.
6. Sources retain separate identities, aliases and evidence records. One upstream GHSA appearing through two APIs is not two independent confirmations.
7. Source silence is not a rejection. Retracted OSV evidence or explicit range disagreements are flagged for review.
8. Partial/failed inventory or a broken public source cannot automatically declare endpoints patched.

**A Finding is a potential match, not a confirmed security exposure.** Vendor backports, custom builds, distribution policies and endpoint-specific patches need independent verification.

## 6. Database and backup boundaries

AVM uses one PostgreSQL container with separate **avm** and **metabase** databases. The Worker initializes application schema and read-only reporting views; Metabase's report connection uses the **avm_reader** role.

~~~bash
# Read-only health check
docker compose ps

# Create both PostgreSQL database dumps
./scripts/backup.sh
~~~

The backup script creates **avm.dump** and **metabase.dump** in a timestamped local directory. It does **not** include .env, tokens, TLS files or private application YAML. Protect those separately.

**Never use docker compose down -v during incident response** unless the intentional objective is to destroy the project's persistent database volumes and a tested recovery path exists.

The restore script is **destructive to current application and Metabase DB contents** and requires explicit confirmation. Test it in an isolated environment before any real use.

## 7. What is automatically hardened — and what remains yours

| Included by default | Additional production responsibility |
|---|---|
| NGINX TLS termination | Trusted certificate and access controls beyond localhost |
| Internal-only PostgreSQL network | Host OS patching, backups, storage encryption and Docker daemon controls |
| Worker non-root UID, read-only root filesystem, no-new-privileges | Container image provenance review and vulnerability monitoring |
| Metabase reporting account with SELECT-only views | Metabase authentication/access lifecycle, organization SSO if required |
| Private .env and token files | Secrets management/rotation and access audit |
| Source retries, checkpoints and no source-driven auto-close | Monitoring data completeness, rate limits and API schema drift |
| Manual approval of package identities | Vendor backport review and approved remediation decisions |
| CI synthetic Docker and throwaway PostgreSQL tests | Real corporate staging, large-inventory sizing, disaster-recovery drills |

**Current functional limitations:** no application-native SSO/RBAC for mapping/risk CLI, no authenticated vendor backport resolver, no patch automation, no complete historic CVE mirror, no validated universal CPE applicability evaluator, and no claim of production certification.

## 8. Before you enable Live — checklist

- [ ] Endpoint Central token is **GET-only, inventory-only**, and the exact deployment/API response has passed the [read-only preflight](INSTALLATION.md#b6-test-endpoint-central-before-deploying-containers).
- [ ] HTTPS certificate validation is active; internal CA trust is configured if needed.
- [ ] A **new, isolated** Compose project and volume is used; Demo/V1/V2 volumes untouched.
- [ ] **max_assets / max_pages** are set for verified fleet size and API limits.
- [ ] Public-source egress and sharing package/version information with OSV are approved.
- [ ] Metabase is localhost-only or protected by an explicitly approved access architecture.
- [ ] The admin account, secrets, Docker permissions and backup targets meet company policy.
- [ ] Test restoration in a disposable staging project; preserve configs/certs/tokens separately.
- [ ] Approval, false-positive handling and risk exceptions have named organizational owners.
- [ ] A staging collection proves actual inventory completeness and version precision.
- [ ] Source freshness and failed syncs are visible in dashboards **06 / 09**.
- [ ] Security accepts that the current build is a **technical preview**, not certified production software.

If the checklist is incomplete, use **Demo** or an isolated **staging Live deployment**, not a production network publication.
