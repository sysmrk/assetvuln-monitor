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
from avm.demo import inventory as demo_inventory, vulnerabilities as demo_vulnerabilities
from avm.matching import extract_affected, is_affected

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


def mappings(cfg):
    data = yaml.safe_load(Path(cfg['matching']['mappings_file']).read_text()) or {}
    lookup = {}
    for item in data.get('products', []):
        key = (item['name'].casefold().strip(), item['vendor'].casefold().strip())
        lookup[key] = (item['ecosystem'].casefold().strip(), item['package'].casefold().strip())
    return lookup


def upsert_inventory(session, records, lookup):
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
            identity = lookup.get((name.casefold(), vendor.casefold()))
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
            v.cvss = float(score) if score is not None else None
        except (ValueError, TypeError):
            v.cvss = None
        if v.cvss is not None and (v.cvss < 0 or v.cvss > 10):
            v.cvss = None
        v.severity = str(entry.get('severity') or ('CRITICAL' if v.cvss and v.cvss >= 9 else
                         'HIGH' if v.cvss and v.cvss >= 7 else 'MEDIUM' if v.cvss and v.cvss >= 4 else 'UNKNOWN')).upper()
        try:
            epss = entry.get('epss')
            v.epss = float(epss) if epss is not None and not isinstance(epss, dict) else None
        except (ValueError, TypeError):
            v.epss = None
        v.kev = entry.get('kev', False) is True or entry.get('isKev', False) is True
        v.published_at = timestamp(entry.get('publishedAt') or entry.get('published'))
        v.modified_at = timestamp(entry.get('modifiedAt') or entry.get('updatedAt') or entry.get('modified'))
        v.retrieved_at = now()
        v.synthetic = entry.get('synthetic') is True
        v.raw = entry
        session.flush()
        for old in session.scalars(select(AffectedPackage).where(AffectedPackage.vulnerability_id == ident)).all():
            session.delete(old)
        session.flush()
        for pkg in extract_affected(entry):
            session.add(AffectedPackage(vulnerability_id=ident, ecosystem=pkg['ecosystem'].casefold(),
                                        package_name=pkg['name'].casefold(), affected_spec=pkg['spec']))
        processed += 1
    return processed


def recalculate(session):
    stamp = now()
    matches = set()
    packages = {}
    for affected in session.scalars(select(AffectedPackage)).all():
        packages.setdefault((affected.ecosystem, affected.package_name), []).append(affected)
    soft = {s.id: s for s in session.scalars(select(Software)).all()}
    for install in session.scalars(select(Installation).where(Installation.active == True)).all():
        product = soft.get(install.software_id)
        if not product or not product.ecosystem or not product.package_name:
            continue
        for affected in packages.get((product.ecosystem, product.package_name), []):
            result = is_affected(install.version, affected.affected_spec)
            if result is not True:
                continue
            identity = (install.id, affected.vulnerability_id)
            if identity in matches:
                continue
            matches.add(identity)
            finding = session.scalar(select(Finding).where(Finding.installation_id == install.id,
                                                           Finding.vulnerability_id == affected.vulnerability_id))
            if finding is None:
                finding = Finding(installation_id=install.id, vulnerability_id=affected.vulnerability_id)
                session.add(finding)
            finding.active, finding.last_detected = True, stamp
            finding.confidence = 'structured-range'
            finding.evidence = f'Exact mapped package identity and affected-version evidence for {install.version}; verify vendor advisories/backports.'
    for finding in session.scalars(select(Finding)).all():
        if (finding.installation_id, finding.vulnerability_id) not in matches:
            finding.active = False
    return len(matches)


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
    while True:
        current = time.monotonic()
        run_match = False
        with factory() as session:
            if not last_inventory or current - last_inventory >= int(cfg['manageengine']['sync_minutes'])*60:
                try:
                    lookup = mappings(cfg)
                    incoming = demo_inventory() if mode == 'demo' else ManageEngineCollector(cfg['manageengine']).collect()
                    count = record_run(session, 'inventory', lambda: upsert_inventory(session, incoming, lookup))
                    log.info('Inventory synchronized: %s assets', count)
                    run_match = True
                    last_inventory = current
                except Exception:
                    log.exception('Inventory synchronization FAILED; previous data preserved')
                    last_inventory = current
            if not last_cve or current - last_cve >= int(cfg['cve']['sync_minutes'])*60:
                try:
                    incoming = demo_vulnerabilities() if mode == 'demo' else CveNowCollector(cfg['cve']).collect()
                    count = record_run(session, 'cve', lambda: upsert_vulnerabilities(session, incoming))
                    log.info('CVE entries synchronized: %s', count)
                    run_match = True
                    last_cve = current
                except Exception:
                    log.exception('CVE synchronization FAILED; previous data preserved')
                    last_cve = current
            if run_match:
                try:
                    count = record_run(session, 'matching', lambda: recalculate(session))
                    log.info('Active matches: %s', count)
                    notify(session, cfg, mode == 'demo')
                except Exception:
                    log.exception('Matching or notifications failed')
        time.sleep(15)


if __name__ == '__main__':
    main()
