"""The v0.2 worker must use approved-only exact normalized product identities."""
import pytest

from avm.worker import mappings


def test_worker_loads_only_explicit_approved_identities(tmp_path):
    mapping = tmp_path / 'approved.yaml'
    mapping.write_text(
        'products:\n'
        '  - vendor: "Acme   Corp"\n'
        '    name: "Example   Secure Client"\n'
        '    ecosystem: PyPI\n'
        '    package: example-secure-client\n',
        encoding='utf-8')
    keys = mappings({'matching': {'mappings_file': str(mapping)}})
    assert keys[('example secure client', 'acme corp')] == ('pypi', 'example-secure-client')
    assert ('example secure clien', 'acme corp') not in keys


def test_worker_rejects_ambiguous_approved_mappings(tmp_path):
    mapping = tmp_path / 'approved.yaml'
    mapping.write_text(
        'products:\n'
        '  - vendor: Acme\n'
        '    name: Example\n'
        '    ecosystem: PyPI\n'
        '    package: example\n'
        '  - vendor: ACME\n'
        '    name: EXAMPLE\n'
        '    ecosystem: npm\n'
        '    package: wrong-product\n',
        encoding='utf-8')
    with pytest.raises(ValueError, match='Duplicate'):
        mappings({'matching': {'mappings_file': str(mapping)}})
