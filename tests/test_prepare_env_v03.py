from pathlib import Path
import os
from scripts.prepare_env import prepare


def test_fresh_demo_is_zero_config_and_idempotent(tmp_path):
    (tmp_path / 'example.env').write_text(
        'COMPOSE_PROJECT_NAME=assetvuln-monitor-v03\n'
        'HTTPS_PORT=8445\nPUBLIC_URL=https://localhost:8445\n'
        'HOST_UID=1000\nHOST_GID=1000\n'
        'POSTGRES_PASSWORD=CHANGE_ME_POSTGRES\n'
        'APP_DB_PASSWORD=CHANGE_ME_APP\n'
        'REPORT_DB_PASSWORD=CHANGE_ME_REPORT\n'
        'MB_DB_PASSWORD=CHANGE_ME_MB\n'
        'METABASE_ADMIN_PASSWORD=CHANGE_ME_ADMIN\n'
        'PRODUCT_MAPPINGS_FILE=./config/product-mappings.yaml\n')
    assert prepare(tmp_path, 'demo')
    env = (tmp_path / '.env').read_text()
    assert 'CHANGE_ME_' not in env
    values = dict(line.split('=', 1) for line in env.splitlines())
    assert len({values[k] for k in ('POSTGRES_PASSWORD', 'APP_DB_PASSWORD',
                                   'REPORT_DB_PASSWORD', 'MB_DB_PASSWORD',
                                   'METABASE_ADMIN_PASSWORD')}) == 5
    assert (tmp_path / '.env').stat().st_mode & 0o777 == 0o600
    assert not prepare(tmp_path, 'demo')


def test_live_prepares_separate_mapping_without_replacing_custom_secret(tmp_path):
    (tmp_path / 'example.env').write_text(
        'COMPOSE_PROJECT_NAME=assetvuln-monitor-v03\n'
        'APP_DB_PASSWORD=custom-private-password\n'
        'PRODUCT_MAPPINGS_FILE=./config/product-mappings.yaml\n')
    assert prepare(tmp_path, 'live')
    env = (tmp_path / '.env').read_text()
    assert 'APP_DB_PASSWORD=custom-private-password' in env
    assert 'PRODUCT_MAPPINGS_FILE=./config/product-mappings.live.yaml' in env
