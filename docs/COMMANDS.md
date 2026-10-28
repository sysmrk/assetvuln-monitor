# Operator command book — copy, run, understand

This page explains **every main script and routine command** in V3. It is written for an operator who does not know the internals.

**First rule:** open a Linux terminal, enter the directory containing the V3 **docker-compose.yml**, and run the commands **there**. The example directory is from the beginner installation:

~~~bash
cd "$HOME/projects/assetvuln-monitor-v03"
~~~

**For Live**, change the directory to **assetvuln-monitor-v03-live** instead. Never run V3 commands from the V1 or V2 directory.

## 1. The commands you will use most

| What you want | Command | Does it change data? |
|---|---|---|
| Show container status | **docker compose ps** | No |
| Read the latest Worker messages | **docker compose logs --tail=100 worker** | No |
| Follow ongoing Worker activity | **docker compose logs -f worker** | No |
| Read Metabase messages | **docker compose logs --tail=100 metabase** | No |
| Check Compose configuration | **docker compose config --quiet** | No |
| Show top 10 potential findings | **docker compose exec -T worker python -m avm.ops queue --limit 10** | No |
| List pending mapping approvals | **docker compose exec -T worker python -m avm.review_cli list --status pending** | No |
| Stop containers but keep databases | **docker compose stop** | Stops services, preserves data |
| Start previously stopped containers | **docker compose start** | Starts services |
| Back up two PostgreSQL databases | **./scripts/backup.sh** | Creates local dump files |
| Repair missing Metabase setup | **docker compose --profile setup run --rm bootstrap** | Updates/creates Metabase metadata |

**Never include the "-v" option with docker compose down unless you intentionally want to delete this project's persistent volumes.**

### Confirm you are using the right checkout

~~~bash
pwd
git branch --show-current
docker compose ps
~~~

Expected Git branch: **develop/v0.3**. The Compose project normally starts with **assetvuln-monitor-v03**. A separate Live checkout should have a distinct project name and port.

## 2. What does each repository script do?

| File | Purpose | When to run it | Changes |
|---|---|---|---|
| **install.sh** | Simple entry point; forwards to scripts/install.sh | First install or safe reprovision | Creates config/passwords, starts services, provisions UI |
| **scripts/install.sh** | Checks prerequisites, project isolation, secrets/TLS, starts 4 containers and Metabase bootstrap | Normally use top-level install.sh instead | Local install only |
| **scripts/prepare_env.py** | Creates/reuses private .env; fills missing local passwords with random values | Installer does this for Demo; run before editing a new Live .env | Local .env only |
| **scripts/test_manageengine_api.py** | Tests first inventory and software-info API responses | Before Live installation or when diagnosing access | **GET-only** Endpoint Central calls |
| **scripts/backup.sh** | Saves AVM + Metabase PostgreSQL dumps | Before maintenance and on your backup schedule | Writes backup files |
| **scripts/restore.sh** | Restores both databases from a verified backup | Recovery only; requires typing RESTORE | **Destructive for current database contents** |
| **scripts/suggest_mappings.py** | Offline proposed mappings from a local inventory CSV | Optional advanced research | Writes JSON report only when --output is given |
| **scripts/check_compose_isolation.py** | Compares resource names/ports with another checkout | Optional before colocating versions | Reads Compose configuration, starts nothing |
| **avm.review_cli** | Privileged proposal/approval/rejection workflow | After you have confirmed package identity | Local DB writes for propose/approve/reject |
| **avm.ops** | Read-only priority queue/simulation; explicit risk acceptance/release | Daily review and approved exceptions | queue/simulate = read; accept/release = local DB write |
| **avm.bootstrap** | Metabase account, report connection, questions and dashboards | Installer does this automatically | Metabase metadata, never endpoints |

**Important distinction:** scripts may write **local application data**; they never deploy a patch or change Endpoint Central devices. Docker access itself is highly privileged on the server.

## 3. Install or reinstall setup safely

**Fresh synthetic Demo:**

~~~bash
./install.sh --demo
~~~

**Fresh Live (after URL/token/API preflight and dedicated project setup):**

~~~bash
./install.sh --live
~~~

Use the correct mode for the existing installation. The installer blocks switching modes in place. **Do not blindly rerun the installer after a failed database restore**; first read the error and [recovery guide](TROUBLESHOOTING.md).

For a new Live environment, generate passwords *before* editing .env:

~~~bash
python3 scripts/prepare_env.py --mode live
nano .env
~~~

Read [full Live setup instructions](INSTALLATION.md#part-b--connect-real-inventory-live) before running the installer.

## 4. Diagnose the stack without changing it

~~~bash
docker compose ps
docker compose logs --tail=100 worker
docker compose logs --tail=100 postgres
docker compose logs --tail=100 metabase
docker compose logs --tail=100 nginx
~~~

Expected output: four services running/healthy. Logs may show **upstream timeout** even while the container is healthy; check the collection result and source freshness separately.

Follow logs live; press **Ctrl+C** to stop viewing (this does **not** stop the container):

~~~bash
docker compose logs -f worker
~~~

Check the generated Metabase login (prints a secret on your local terminal):

~~~bash
grep '^METABASE_ADMIN_EMAIL=' .env
grep '^METABASE_ADMIN_PASSWORD=' .env
~~~

Get a localhost HTTPS health response, bypassing **only** the deliberately self-signed local Demo certificate:

~~~bash
curl --insecure --fail --silent --show-error https://127.0.0.1:8445/api/health
~~~

**Expected:** a small JSON response containing a healthy status. This command assumes the default **Demo** port **8445**. Change it to your configured Live port if needed. **Do not use --insecure for routine production connections.**

## 5. Inspect and approve software mappings

Before any real Findings can appear in Live, an authoritative package identity must be approved. Full instructions: [Mapping Review](MAPPING-REVIEW.md).

**List pending proposals (read-only):**

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status pending
~~~

**Show all recently reviewed identities (read-only):**

~~~bash
docker compose exec -T worker python -m avm.review_cli list --status all --limit 50
~~~

**Create a new pending proposal** — replace every example field with **verified values from dashboard 03 and an official package advisory**:

~~~bash
docker compose exec -T worker python -m avm.review_cli propose \
  --vendor "Exact Vendor" \
  --name "Exact Software Name" \
  --ecosystem "PyPI" \
  --package "verified-package" \
  --actor "analyst-1" \
  --evidence "Verified exact vendor/software identity against the upstream package"
~~~

Result: a **review ID**. **No finding is created from a proposal.**

**Approve only after independent review** — replace **12** with your returned review ID, and use a different analyst for manual proposals:

~~~bash
docker compose exec -T worker python -m avm.review_cli approve \
  --id 12 \
  --actor "reviewer-2" \
  --reason "Independently verified package identity and application edition"
~~~

**Reject an incorrect proposal**, again replacing **12**:

~~~bash
docker compose exec -T worker python -m avm.review_cli reject \
  --id 12 \
  --actor "reviewer-2" \
  --reason "Package belongs to a different vendor or edition"
~~~

**Read the audit history for one ID (read-only):**

~~~bash
docker compose exec -T worker python -m avm.review_cli history --review-id 12
~~~

**When does it take effect?** On the **next successful scheduled inventory sync**, not immediately. For a small staging environment, restarting the Worker triggers another inventory sync but creates another round of Endpoint Central read requests:

~~~bash
docker compose restart worker
~~~

Do not force this on a large production fleet without scheduling the extra load.

## 6. Investigate current potential findings

**Get the highest priority items (read-only):**

~~~bash
docker compose exec -T worker python -m avm.ops queue --limit 20
~~~

Each JSON line contains the Finding ID, host, advisory ID, priority, score, matched evidence sources and workflow state.

**Read-only scenario simulation:**

~~~bash
docker compose exec -T worker python -m avm.ops simulate --top 20
docker compose exec -T worker python -m avm.ops simulate --kev
~~~

These **do not patch hosts or close Findings**; they only calculate hypothetical changes in the application's own score-point totals.

**Time-limited risk acceptance** (**writes to local AVM DB**, needs a real approval outside AVM):

~~~bash
docker compose exec -T worker python -m avm.ops accept \
  --finding-id 12 \
  --actor "risk-owner" \
  --until 2026-12-01 \
  --reason "Approved temporary business exception; compensating controls documented"
~~~

Replace **12**, the actor and expiry with values appropriate to your organization. The expiry must be **1 to 180 days from the day you run it**. If this example date is in the past, it will fail, as it should. Approval is **not validated by SSO**; restrict who can run it.

**Release an acceptance** (writes to local AVM DB):

~~~bash
docker compose exec -T worker python -m avm.ops release \
  --finding-id 12 \
  --actor "risk-owner" \
  --reason "Exception withdrawn after reviewing current patch and exposure"
~~~

See [Risk & lifecycle](V03-OPERATIONS.md) for exact semantics.

## 7. Inspect database reports (optional; advanced, read-only queries)

Most people should use the Metabase dashboards. For troubleshooting, these examples query the **current project's PostgreSQL** and do not change its rows:

~~~bash
# List feed names and latest successful collection timestamps.
docker compose exec -T postgres psql -U postgres -d avm \
  -c "SELECT source, MAX(finished_at) AS last_attempt FROM sync_runs GROUP BY source ORDER BY source;"

# Count active potential findings.
docker compose exec -T postgres psql -U postgres -d avm \
  -c "SELECT active_findings FROM reporting.risk_overview;"

# Check OSV cache coverage.
docker compose exec -T postgres psql -U postgres -d avm \
  -c "SELECT * FROM reporting.osv_cache_coverage;"
~~~

These read-only SQL statements are examples run using PostgreSQL's **administrative container account**. Do not expose PostgreSQL outside the Docker network or give its admin access to general dashboard users.

## 8. Back up, stop and restart

**Back up both application databases:**

~~~bash
./scripts/backup.sh
~~~

Output: a directory like **backups/20261028T120000Z/** containing **avm.dump** and **metabase.dump**. These are **sensitive backups**. The script backs up databases only; preserve private YAML, .env, token, certificates and reviewed mapping files separately using approved secret-handling procedures.

**Stop the application, keeping persistent data:**

~~~bash
docker compose stop
~~~

**Start it again:**

~~~bash
docker compose start
~~~

**Restart only the Worker after a configuration change:**

~~~bash
docker compose restart worker
~~~

This triggers fresh startup logic and scheduled jobs. It does not change remote endpoints, but can re-read many endpoints and sources.

**Recreate missing dashboards without reinstalling databases:**

~~~bash
docker compose --profile setup run --rm bootstrap
~~~

The bootstrap job creates missing Metabase artifacts and reuses known names where possible. Existing customized saved questions are **not guaranteed to be overwritten with newer query definitions**; review those after updates.

### Database recovery — destructive; use only with a verified backup

**Never run this against a production/live project casually.** Validate the backup directory and test restoring into a disposable, isolated project first.

~~~bash
./scripts/restore.sh backups/20261028T120000Z
~~~

The folder above is an **example**; use your actual backup folder. The script asks you to type **RESTORE**, then replaces the existing AVM and Metabase database contents and restarts services. It cannot rebuild lost private configuration, tokens or TLS certificates by itself. For a different Compose project or disaster recovery, the database ownership, project identity, configuration and secrets need an independently tested procedure.

## 9. Optional developer and diagnostic tools

**Test Endpoint Central without starting Docker (GET-only):**

~~~bash
python3 scripts/test_manageengine_api.py
~~~

With your own corporate CA:

~~~bash
python3 scripts/test_manageengine_api.py --ca-bundle secrets/certs/org-ca.pem
~~~

**Read-only mapping suggestions from a sample CSV (requires Python dependencies on the host):**

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/suggest_mappings.py \
  --inventory-csv examples/software-inventory.sample.csv \
  --approved-mappings examples/mapping-catalog.sample.yaml \
  --output mapping-review.json
~~~

The output file is a local review report, **not approved mapping changes**. On Ubuntu, if venv is unavailable, install your distribution's **python3-venv** package before trying again. The virtual environment is optional and separate from the Docker deployment.

**Run the test suite:**

~~~bash
python -m pip install pytest
python -m pytest -q tests
python scripts/check_docs.py
~~~

If you run the Python commands in the preceding optional venv, they use that environment. CI additionally runs disposable PostgreSQL and Docker integration checks; local unit tests may skip CI-only tests.

**Compare Compose resources with a separate V2 checkout (optional):**

~~~bash
python3 scripts/check_compose_isolation.py \
  --baseline-dir "$HOME/projects/assetvuln-monitor-v02" \
  --candidate-dir .
~~~

The baseline directory and its configuration must exist. The script reads Compose definitions; it does not start containers or migrate data.

## 10. Dangerous commands to recognize

| Command or action | Why to be careful |
|---|---|
| **docker compose down -v** | **Deletes named project volumes**, including application/Metabase data |
| **scripts/restore.sh ...** | Replaces current DB contents after confirmation |
| Changing **COMPOSE_PROJECT_NAME** in a populated checkout | May point Compose at a **different database volume**, making data appear missing |
| Changing **POSTGRES_PASSWORD** after first initialization | Does **not** automatically rotate the password inside an existing PostgreSQL volume |
| Changing **application.mode** between Demo and Live in one checkout | Violates data isolation; installer blocks this |
| Editing **config/product-mappings.live.yaml** without evidence | Can generate unsupported or wrong findings |
| Publishing **.env**, token, TLS keys or dumps | Leaks sensitive credentials or infrastructure metadata |

If you are unsure, **stop and read** [Troubleshooting](TROUBLESHOOTING.md) instead of deleting anything.
