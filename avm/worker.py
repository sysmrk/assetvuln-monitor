"""One process: sync sources, correlate, send alerts, and repeat at safe intervals."""
import json
import logging
import os
import smtplib
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
import yaml
from sqlalchemy import select
from avm.settings import config
from avm.models import (Asset, Software, Installation, Vulnerability, AffectedPackage,
                        Finding, SyncRun, initialize, now, session_factory)
from avm.collectors import ManageEngineCollector, CveNowCollector
from avm.demo import (inventory as demo_inventory,
                      vulnerabilities as demo_vulnerabilities,
                      seed_multisource_demo)
from avm.matching import extract_affected, is_affected
from avm.normalization import normalized_label, runtime_lookup
from avm.mapping_review import approved_runtime_lookup, refresh_review_queue
from avm.asset_context import load_asset_context, apply_asset_context
from avm.lifecycle import recalculate_findings
from avm.threat_intel import PublicThreatIntel, enrich_vulnerabilities
from avm.source_engine import note_advisory
from avm.source_collectors import sync_osv, sync_nvd, sync_euvd
from avm.epss_csv import sync_epss_csv

logging.basicConfig(level=os.environ.get('LOG_LEVEL','INFO'),
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
log = logging.getLogger('avm.worker')


def timestamp(s):
    if s is None or s == '':
        return None
    try:
        return datetime.fromisoformat(str(s).replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


def mapping_rows(cfg):
    data = yaml.safe_load(Path(cfg['matching']['mappings_file']).read_text()) or {}
    if not isinstance(data, dict) or not isinstance(data.get('products'), list):
        raise ValueError('Software mappings must contain a products list')
    return data['products']


def mappings(cfg, session=None):
    # Existing callers/tests can read YAML alone. Runtime merges *approved*
    # database identities; proposals never influence CVE matching.
    rows = mapping_rows(cfg)
    return runtime_lookup(rows) if session is None else approved_runtime_lookup(session, rows)


def upsert_inventory(session, records, lookup, asset_context=None):
    # Never deactivate an existing fleet based on an unexpectedly empty scan.
    records = list(records)
    if not records and session.scalar(select(Asset.id).where(Asset.active.is_(True)).limit(1)):
        raise ValueError('Empty inventory would deactivate known assets; keeping previous state')
    stamp = now()
    seen_assets, seen_installs = set(), set()
    for asset_data, packages in records:
        rid = str(asset_data['source_id'])
        if rid in seen_assets:
            raise ValueError(f'Duplicate asset ID from source: {rid}')
        seen_assets.add(rid)
        asset = session.scalar(select(Asset).where(Asset.source_id == rid))
        if asset is None:
            asset = Asset(source_id=rid)
            session.add(asset)
        for k in ('hostname','fqdn','ip_address','os_name','os_version','domain','agent_status'):
            setattr(asset, k, asset_data.get(k) or '')
        asset.active, asset.last_seen = True, stamp
        if asset_context is not None:
            apply_asset_context(asset, asset_context)
        session.flush()
        for item in packages:
            name = (item.get('name') or '').strip()
            vendor = (item.get('vendor') or 'Unknown').strip()
            installed_version = (item.get('version') or 'unknown').strip()
            if not name:
                continue
            software = session.scalar(select(Software).where(Software.name == name, Software.vendor == vendor))
            if software is None:
                software = Software(name=name, vendor=vendor)
                session.add(software)
            identity = lookup.get((normalized_label(name), normalized_label(vendor)))
            software.ecosystem = identity[0] if identity else None
            software.package_name = identity[1] if identity else None
            session.flush()
            installation = session.scalar(select(Installation).where(
                Installation.asset_id == asset.id, Installation.software_id == software.id,
                Installation.version == installed_version))
            if installation is None:
                installation = Installation(asset_id=asset.id, software_id=software.id,
                                            version=installed_version)
                session.add(installation)
            installation.active, installation.last_seen = True, stamp
            session.flush()
            seen_installs.add(installation.id)
    for asset in session.scalars(select(Asset)).all():
        if asset.source_id not in seen_assets:
            asset.active = False
    for install in session.scalars(select(Installation)).all():
        if install.id not in seen_installs:
            install.active = False
    return len(seen_assets)


def upsert_vulnerabilities(session, raw_entries):
    processed = 0
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        ident = entry.get('id') or entry.get('cveId') or entry.get('cve_id')
        if not isinstance(ident, str) or not ident.strip() or len(ident) > 100:
            continue
        ident = ident.strip()
        v = session.get(Vulnerability, ident)
        if v is None:
            v = Vulnerability(id=ident)
            session.add(v)
        v.title = str(entry.get('title') or entry.get('summary') or ident)[:500]
        v.summary = str(entry.get('summary') or entry.get('description') or '')[:5000]
        score = entry.get('cvss') or entry.get('cvssScore')
        if isinstance(score, dict):
            score = score.get('score') or score.get('baseScore')
        try:
            advisory_cvss = float(score) if score is not None else None
        except (ValueError, TypeError):
            advisory_cvss = None
        if advisory_cvss is not None and not 0 <= advisory_cvss <= 10:
            advisory_cvss = None
        # NVD/EUVD CVSS values retain their own provenance and priority.
        if v.cvss_source not in ('nvd', 'euvd'):
            v.cvss = advisory_cvss
            if advisory_cvss is not None:
                v.cvss_source = 'cve_now'
        # Severity must correspond to the selected authoritative CVSS,
        # not an unrelated aggregator label after NVD/EUVD enrichment.
        derived_severity = ('CRITICAL' if v.cvss is not None and v.cvss >= 9 else
                            'HIGH' if v.cvss is not None and v.cvss >= 7 else
                            'MEDIUM' if v.cvss is not None and v.cvss >= 4 else
                            'LOW' if v.cvss is not None else 'UNKNOWN')
        if v.cvss_source in ('nvd', 'euvd'):
            v.severity = derived_severity
        else:
            v.severity = str(entry.get('severity') or derived_severity).upper()
        # Live KEV/EPSS rankings require separate official-feed provenance.
        # Keep synthetic demo indicators for tests, never treat advisory hints
        # as confirmed CISA/FIRST intelligence.
        v.synthetic = entry.get('synthetic') is True
        if v.synthetic:
            epss = entry.get('epss')
            try:
                v.epss = float(epss) if epss is not None and 0 <= float(epss) <= 1 else None
            except (ValueError, TypeError):
                v.epss = None
            v.kev = entry.get('kev') is True or entry.get('isKev') is True
        else:
            v.kev = bool(v.kev_verified)
        v.published_at = timestamp(entry.get('publishedAt') or entry.get('published'))
        v.modified_at = timestamp(entry.get('modifiedAt') or entry.get('updatedAt') or entry.get('modified'))
        v.retrieved_at = now()
        v.synthetic = entry.get('synthetic') is True
        v.raw = entry
        session.flush()
        # A refresh by cve.now must never delete OSV or other-source evidence.
        if not v.synthetic:
            note_advisory(session, source='cve_now', source_id=ident,
                          aliases=entry.get('aliases') or [],
                          title=v.title, summary=v.summary, cvss=advisory_cvss,
                          updated_at=v.modified_at,
                          original_source=entry.get('source') if isinstance(entry.get('source'), str) else None,
                          raw={'published': entry.get('publishedAt') or entry.get('published'),
                               'affected_records': len(entry.get('affected') or [])})
        for old in session.scalars(select(AffectedPackage).where(
                AffectedPackage.vulnerability_id == ident,
                AffectedPackage.source == 'cve_now')).all():
            session.delete(old)
        session.flush()
        for pkg in extract_affected(entry):
            session.add(AffectedPackage(vulnerability_id=ident, ecosystem=pkg['ecosystem'].casefold(),
                                        package_name=pkg['name'].casefold(), affected_spec=pkg['spec'],
                                        source='cve_now', source_id=ident,
                                        evidence_status='current'))
        processed += 1
    return processed


def recalculate(session, allow_disappearance=False, sla_days=None):
    """Legacy public entrypoint; delegate to the versioned evidence lifecycle."""
    return recalculate_findings(session, allow_disappearance=allow_disappearance, sla_days=sla_days)


def record_run(session, source, fn):
    run = SyncRun(source=source, started_at=now())
    session.add(run)
    session.commit()
    try:
        count = fn()
        run.success, run.record_count, run.message = True, count, 'OK'
        session.commit()
        return count
    except Exception as exc:
        session.rollback()
        run = session.get(SyncRun, run.id)
        run.success, run.message = False, str(exc)[:1000]
        session.commit()
        raise
    finally:
        run = session.get(SyncRun, run.id)
        run.finished_at = now()
        session.commit()


def notify(session, cfg, demo):
    info = cfg.get('notifications', {})
    if demo or not info.get('email_enabled', False):
        return
    pending = session.scalars(select(Finding).where(Finding.active == True, Finding.alerted_at == None)).all()
    if not pending:
        return
    if not info.get('smtp_starttls', True):
        raise ValueError('SMTP STARTTLS is required')
    msg = EmailMessage()
    msg['Subject'] = f'[AssetVuln Monitor] {len(pending)} newly detected software-CVE correlations'
    msg['From'] = info['sender']
    msg['To'] = ', '.join(info['recipients'])
    msg.set_content('New potential vulnerability correlations have been detected.\n'
                    'Sign in to the AssetVuln Monitor dashboard to investigate.\n'
                    'These are version-based indications, NOT proof of exploitability.')
    with smtplib.SMTP(info['smtp_host'], int(info.get('smtp_port',587)), timeout=20) as smtp:
        smtp.starttls()
        if os.environ.get('SMTP_USER'):
            smtp.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
        smtp.send_message(msg)
    for finding in pending:
        finding.alerted_at = now()
    session.commit()


def main():
    cfg = config()
    mode = cfg['application']['mode']
    engine, factory = session_factory()
    initialize(engine)
    log.info('Started in %s mode; ManageEngine permissions: GET-only', mode)
    last_inventory = 0
    last_cve = 0
    last_intel = 0
    last_epss_csv = 0
    last_osv = 0
    last_nvd = 0
    last_euvd = 0
    while True:
        current = time.monotonic()
        run_match = False
        inventory_success = False
        with factory() as session:
            if not last_inventory or current - last_inventory >= int(cfg['manageengine']['sync_minutes'])*60:
                try:
                    operator_rows = mapping_rows(cfg)
                    lookup = approved_runtime_lookup(session, operator_rows)
                    context = load_asset_context(os.environ.get('AVM_ASSET_CONTEXT',
                                                                '/opt/avm/config/asset-context.yaml'))
                    incoming = demo_inventory() if mode == 'demo' else ManageEngineCollector(cfg['manageengine']).collect()

                    def write_inventory_and_reviews():
                        count = upsert_inventory(session, incoming, lookup, asset_context=context)
                        # Same transaction: failed/partial inventory never seeds reviews.
                        created = refresh_review_queue(session, operator_rows)
                        log.info('Mapping proposals queued for human review: %s', created)
                        return count

                    count = record_run(session, 'inventory', write_inventory_and_reviews)
                    log.info('Inventory synchronized: %s assets', count)
                    run_match = True
                    inventory_success = True
                    last_inventory = current
                except Exception:
                    log.exception('Inventory synchronization FAILED; previous data preserved')
                    last_inventory = current
            if not last_cve or current - last_cve >= int(cfg['cve']['sync_minutes'])*60:
                try:
                    incoming = demo_vulnerabilities() if mode == 'demo' else CveNowCollector(cfg['cve']).collect()
                    def write_advisories():
                        count = upsert_vulnerabilities(session, incoming)
                        if mode == 'demo':
                            seed_multisource_demo(session)
                        return count
                    count = record_run(session, 'cve', write_advisories)
                    log.info('CVE entries synchronized: %s', count)
                    run_match = True
                    last_cve = current
                except Exception:
                    log.exception('CVE synchronization FAILED; previous data preserved')
                    last_cve = current
            # Public vulnerability sources operate on the already-ingested
            # software inventory. No second endpoint scan occurs.
            if mode == 'live':
                feeds = cfg.get('vulnerability_sources', {})
                current_time = now()
                if feeds.get('osv', {}).get('enabled', True) and (
                        not last_osv or current - last_osv >= int(
                            feeds.get('osv', {}).get('sync_minutes', 20)) * 60):
                    try:
                        count = record_run(session, 'osv', lambda: sync_osv(
                            session, feeds.get('osv', {})))
                        log.info('OSV approved package/version checks: %s', count)
                        run_match = run_match or count > 0
                    except Exception:
                        log.exception('OSV refresh failed; existing evidence retained')
                    last_osv = current

                for name, sync_fn, last_value, hours in (
                        ('nvd', sync_nvd, last_nvd, 2),
                        ('euvd', sync_euvd, last_euvd, 4)):
                    options = feeds.get(name, {})
                    if not options.get('enabled', True):
                        continue
                    cadence = max(15, int(options.get('sync_minutes', hours * 60))) * 60
                    if last_value and current - last_value < cadence:
                        continue
                    try:
                        count = record_run(session, name,
                                           lambda fn=sync_fn, opt=options: fn(session, opt))
                        log.info('%s advisory metadata rows: %s', name.upper(), count)
                        run_match = run_match or count > 0
                    except Exception:
                        log.exception('%s refresh failed; existing source metadata retained', name)
                    # Large update windows resume from persisted page cursors
                    # on a short interval, without skipping unseen advisories.
                    from avm.models import FeedCheckpoint
                    checkpoint = session.get(FeedCheckpoint, name)
                    pending_pages = bool(checkpoint and (checkpoint.state or {}).get('start'))
                    next_interval = max(1, int(options.get('pending_sync_minutes', 10))) * 60
                    elapsed_adjustment = cadence - next_interval if pending_pages else 0
                    if name == 'nvd':
                        last_nvd = current - elapsed_adjustment
                    else:
                        last_euvd = current - elapsed_adjustment

                intel_cfg = cfg.get('threat_intelligence', {})
                intel_interval = max(1, int(intel_cfg.get('sync_hours', 24))) * 3600
                if intel_cfg.get('enabled', True):
                    if not last_intel or current - last_intel >= intel_interval:
                        try:
                            kev_catalog = PublicThreatIntel().fetch_kev()
                            updated = record_run(session, 'threat_intel',
                                lambda: enrich_vulnerabilities(
                                    session, kev_catalog=kev_catalog, epss_values={}))
                            log.info('Official CISA KEV refreshed for %s local CVEs', updated)
                            run_match = True
                            last_intel = current
                        except Exception:
                            log.exception('CISA KEV refresh failed; preserving prior flags')
                            last_intel = current - intel_interval + 3600

                    # FIRST recommends one full daily CSV for bulk synchronization.
                    if not last_epss_csv or current - last_epss_csv >= intel_interval:
                        try:
                            updated = record_run(
                                session, 'epss_csv', lambda: sync_epss_csv(session))
                            log.info('Official FIRST daily CSV matched %s local CVEs', updated)
                            run_match = True
                            last_epss_csv = current
                        except Exception:
                            log.exception('FIRST daily CSV failed; preserving prior EPSS values')
                            last_epss_csv = current - intel_interval + 3600
            if run_match:
                try:
                    count = record_run(session, 'matching',
                                       lambda: recalculate(session,
                                                           allow_disappearance=inventory_success,
                                                           sla_days=cfg.get('risk', {}).get('sla_days')))
                    log.info('Active matches: %s', count)
                    notify(session, cfg, mode == 'demo')
                except Exception:
                    log.exception('Matching or notifications failed')
        time.sleep(15)


if __name__ == '__main__':
    main()
