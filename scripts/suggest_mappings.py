#!/usr/bin/env python3
"""Offline, read-only suggestions from an exported name/vendor/version CSV.

Never calls Endpoint Central and never promotes a candidate to approved mapping.
"""

import argparse
import csv
import json
import os
from pathlib import Path
import sys

import yaml

# Allow running from the repo root without installing the project as a package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from avm.normalization import approved_index, mapping_report  # noqa: E402


def load_inventory(path):
    with path.open(newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {'vendor', 'name'}.issubset(reader.fieldnames):
            raise ValueError('Inventory CSV requires vendor,name columns (version optional)')
        for row in reader:
            yield {'vendor': row['vendor'] or '', 'name': row['name'] or '',
                   'version': row.get('version') or ''}


def load_catalog(path):
    payload = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(payload, dict):
        raise ValueError('Approved mappings YAML must contain a products array')
    return approved_index(payload.get('products'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory-csv', type=Path, required=True, help='Export containing vendor,name,version columns')
    parser.add_argument('--approved-mappings', type=Path, default=Path('config/product-mappings.live.yaml'))
    parser.add_argument('--output', type=Path, help='Save review-only JSON with file permissions 0600')
    parser.add_argument('--min-similarity', type=float, default=0.88)
    parser.add_argument('--limit', type=int, default=3)
    args = parser.parse_args(argv)
    try:
        approved = load_catalog(args.approved_mappings)
        report = mapping_report(load_inventory(args.inventory_csv), approved,
                                min_similarity=args.min_similarity, limit=args.limit)
        if args.output:
            fd = os.open(args.output, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                    fd = -1
                    json.dump(report, stream, indent=2, ensure_ascii=False)
                    stream.write('\n')
            finally:
                if fd != -1:
                    os.close(fd)
        print(json.dumps(report['metrics'], indent=2))
        print('All suggestions require human review; approved mapping file remains unchanged.')
        if args.output:
            print(f'Review-only report saved: {args.output}')
        return 0
    except (OSError, UnicodeError, csv.Error, yaml.YAMLError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
