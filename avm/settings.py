"""Load explicit operator configuration; never silently disable TLS."""
import os
from pathlib import Path
from urllib.parse import quote
import yaml


def config():
    path = Path(os.environ.get('AVM_CONFIG', 'config/application.yaml'))
    data = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('Configuration must be a YAML mapping')
    mode = data.get('application', {}).get('mode')
    if mode not in ('demo', 'live'):
        raise ValueError('application.mode must be demo or live')
    if mode == 'live':
        me = data.get('manageengine', {})
        if not str(me.get('url', '')).startswith('https://'):
            raise ValueError('ManageEngine requires an https:// URL')
        if not me.get('verify_tls', True):
            raise ValueError('TLS verification cannot be disabled in live mode')
        token = Path(me.get('token_file', '/run/secrets/manageengine_token'))
        if not token.exists() or not token.read_text().strip():
            raise ValueError('Missing non-empty ManageEngine API token file')
    return data


def database_url():
    password = os.environ['APP_DB_PASSWORD']
    return f"postgresql+psycopg://avm_app:{quote(password, safe='')}@postgres:5432/avm"
