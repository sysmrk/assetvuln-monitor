"""Optional explicit business context for risk scoring. No inferred internet exposure.

An empty configuration is valid. The importer neither queries nor changes
managed endpoints; it only annotates application-owned asset records.
"""
from pathlib import Path
import yaml

CRITICALITY = frozenset(('unknown', 'low', 'medium', 'high', 'critical'))


def load_asset_context(path):
    file = Path(path)
    if not file.is_file():
        return {}
    payload = yaml.safe_load(file.read_text(encoding='utf-8')) or {}
    if not isinstance(payload, dict) or not isinstance(payload.get('assets', []), list):
        raise ValueError('Asset context requires an assets list')
    seen = {}
    for item in payload.get('assets', []):
        if not isinstance(item, dict):
            raise ValueError('Asset context records must be YAML objects')
        resource = str(item.get('source_id', '')).strip()
        if not resource or len(resource) > 128 or resource in seen:
            raise ValueError('Asset context requires unique non-empty source_id values')
        level = str(item.get('criticality', 'unknown')).lower().strip()
        exposure = item.get('internet_facing')
        if level not in CRITICALITY:
            raise ValueError('Invalid asset criticality for source_id ' + resource)
        if exposure is not None and type(exposure) is not bool:
            raise ValueError('internet_facing must be true, false or null')
        owner = str(item.get('owner') or '').strip()[:200]
        service = str(item.get('business_service') or '').strip()[:200]
        seen[resource] = {'criticality': level,
                          'internet_facing': exposure, 'owner': owner,
                          'business_service': service}
    return seen


def apply_asset_context(asset, context):
    record = context.get(asset.source_id)
    if record is None:
        asset.criticality = 'unknown'
        asset.internet_facing = None
        asset.business_service = ''
        asset.owner = ''
    else:
        asset.criticality = record['criticality']
        asset.internet_facing = record['internet_facing']
        asset.business_service = record['business_service']
        asset.owner = record['owner']
