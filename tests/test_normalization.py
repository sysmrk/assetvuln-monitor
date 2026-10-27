import csv
import json

import pytest

from avm.normalization import approved_index, mapping_report, normalized_label, normalize_software, suggest_candidates
from scripts.suggest_mappings import main


CATALOG = [
    {'vendor': 'Acme Corp', 'name': 'Example Secure Client', 'ecosystem': 'PyPI', 'package': 'example-secure-client'},
    {'vendor': 'Other Inc', 'name': 'Example Server', 'ecosystem': 'npm', 'package': 'example-server'},
]


def test_preserves_source_values_and_versions():
    result = normalize_software(' ACME  Corp ', 'Example\u00a0Secure   Client', ' v1.2.3-rc1 ')
    assert result['vendor'] == ' ACME  Corp '
    assert result['normalized_vendor'] == 'acme corp'
    assert result['normalized_name'] == 'example secure client'
    assert result['normalized_version'] == 'v1.2.3-rc1'
    assert normalized_label('Ｆｏｏ') == 'foo'


def test_candidates_only_same_vendor_and_review_required():
    idx = approved_index(CATALOG)
    out = suggest_candidates('ACME CORP', 'Example Secure Clien', idx, min_similarity=.8)
    assert len(out) == 1
    assert out[0]['status'] == 'review_required'
    assert out[0]['mapping']['package'] == 'example-secure-client'
    assert not suggest_candidates('Unknown vendor', 'Example Secure Clien', idx)
    assert not suggest_candidates('Acme Corp', 'Example Secure Client', idx)


def test_duplicate_or_incomplete_approved_identity_rejected():
    with pytest.raises(ValueError, match='Duplicate'):
        approved_index(CATALOG + [dict(CATALOG[0])])
    with pytest.raises(ValueError, match='requires'):
        approved_index([{'vendor': 'X', 'name': 'Y', 'ecosystem': '', 'package': 'z'}])


def test_report_counts_only_exact_approved_products():
    idx = approved_index(CATALOG)
    inventory = [
        {'vendor': 'ACME Corp', 'name': 'Example Secure Client', 'version': '1.0'},
        {'vendor': 'ACME Corp', 'name': 'Example Secure Client', 'version': '2.0'},
        {'vendor': 'Acme Corp', 'name': 'Example Secure Clien', 'version': '1.0'},
        {'vendor': 'Unrelated', 'name': 'Example Server', 'version': '9.0'},
    ]
    result = mapping_report(inventory, idx, min_similarity=.8)
    assert result['metrics'] == {'installation_rows': 4, 'unique_products': 3,
                                 'approved_products': 1, 'unmapped_products': 2,
                                 'products_with_candidates': 1}
    assert all(p['status'] != 'approved' for p in result['suggestions'])
    assert len(result['suggestions']) == 2


def test_cli_offline_json_and_file_permission(tmp_path):
    file = tmp_path / 'inventory.csv'
    with file.open('w', newline='', encoding='utf-8') as output:
        writer = csv.DictWriter(output, fieldnames=['vendor', 'name', 'version'])
        writer.writeheader()
        writer.writerow({'vendor':'Acme Corp', 'name':'Example Secure Clien', 'version':'1.0'})
    mappings = tmp_path / 'approved.yaml'
    mappings.write_text('products:\n  - vendor: Acme Corp\n    name: Example Secure Client\n    ecosystem: PyPI\n    package: example-secure-client\n')
    target = tmp_path / 'suggestions.json'
    assert main(['--inventory-csv', str(file), '--approved-mappings', str(mappings),
                 '--output', str(target), '--min-similarity', '.8']) == 0
    body = json.loads(target.read_text())
    assert body['metrics']['products_with_candidates'] == 1
    assert body['suggestions'][0]['candidates'][0]['status'] == 'review_required'
    assert target.stat().st_mode & 0o777 == 0o600
    assert mappings.read_text().startswith('products:')


def test_cli_rejects_invalid_inventory(tmp_path):
    file = tmp_path / 'inventory.csv'
    file.write_text('other,columns\na,b\n')
    mappings = tmp_path / 'mapping.yaml'
    mappings.write_text('products: []\n')
    assert main(['--inventory-csv', str(file), '--approved-mappings', str(mappings)]) == 2
