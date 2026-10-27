import pytest
from types import SimpleNamespace
from avm.asset_context import load_asset_context, apply_asset_context


def test_empty_file_and_unknown_context_are_safe(tmp_path):
    file = tmp_path / 'context.yaml'
    file.write_text('assets: []\n')
    assert load_asset_context(file) == {}
    asset = SimpleNamespace(source_id='42')
    apply_asset_context(asset, {})
    assert asset.criticality == 'unknown'
    assert asset.internet_facing is None
    assert asset.owner == ''


def test_explicit_criticality_and_exposure(tmp_path):
    file = tmp_path / 'context.yaml'
    file.write_text('assets:\n'
                    '  - source_id: "42"\n'
                    '    criticality: critical\n'
                    '    internet_facing: true\n'
                    '    business_service: "Checkout"\n'
                    '    owner: "Platform"\n')
    context = load_asset_context(file)
    asset = SimpleNamespace(source_id='42')
    apply_asset_context(asset, context)
    assert asset.criticality == 'critical'
    assert asset.internet_facing is True
    assert asset.business_service == 'Checkout'


def test_ambiguous_or_guessy_context_is_rejected(tmp_path):
    file = tmp_path / 'context.yaml'
    for content in (
        'assets: [{source_id: "1"}, {source_id: "1"}]',
        'assets: [{source_id: "1", internet_facing: "true"}]',
        'assets: [{source_id: "1", criticality: super_high}]',
        'assets: invalid',
    ):
        file.write_text(content)
        with pytest.raises(ValueError):
            load_asset_context(file)
