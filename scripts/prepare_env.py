#!/usr/bin/env python3
"""Prepare local .env safely, without sourcing it or printing credentials.

Fresh demo installation is zero-config. Live still requires the operator's
Endpoint Central HTTPS URL and inventory-only token. Existing values are kept.
"""
import argparse
import os
from pathlib import Path
import secrets
import tempfile


PASSWORDS = {'POSTGRES_PASSWORD', 'APP_DB_PASSWORD', 'REPORT_DB_PASSWORD',
             'MB_DB_PASSWORD', 'METABASE_ADMIN_PASSWORD'}


def prepare(root, mode):
    root = Path(root)
    target = root / '.env'
    template = root / 'example.env'
    if not target.exists():
        target.write_text(template.read_text(encoding='utf-8'), encoding='utf-8')
        target.chmod(0o600)
    content = target.read_text(encoding='utf-8')
    output = []
    found = set()
    changed = False
    for line in content.splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            output.append(line)
            continue
        name, old = line.split('=', 1)
        if name in found:
            raise ValueError('Duplicate .env key: ' + name)
        found.add(name)
        value = old
        if name in PASSWORDS and (not old or old.startswith('CHANGE_ME_')):
            value = secrets.token_urlsafe(36)
        elif name == 'HOST_UID' and old == '1000':
            value = str(os.getuid() or 10001)
        elif name == 'HOST_GID' and old == '1000':
            value = str(os.getgid() or 10001)
        elif name == 'PRODUCT_MAPPINGS_FILE' and mode == 'live':
            if old in ('./config/product-mappings.yaml', './config/product-mappings.live.yaml'):
                value = './config/product-mappings.live.yaml'
        if value != old:
            changed = True
        output.append(f'{name}={value}')
    needed = PASSWORDS - found
    for key in sorted(needed):
        output.append(key + '=' + secrets.token_urlsafe(36))
        changed = True
    if 'COMPOSE_PROJECT_NAME' not in found:
        output.append('COMPOSE_PROJECT_NAME=assetvuln-monitor-v03')
        changed = True
    if mode == 'live' and 'PRODUCT_MAPPINGS_FILE' not in found:
        output.append('PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml')
        changed = True
    if changed:
        fd, tmp = tempfile.mkstemp(prefix='.env-', dir=root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write('\n'.join(output) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    target.chmod(0o600)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('demo', 'live'), default='demo')
    parser.add_argument('--root', default='.')
    args = parser.parse_args()
    prepare(args.root, args.mode)
    print('Private .env ready (passwords are not printed).')


if __name__ == '__main__':
    main()
