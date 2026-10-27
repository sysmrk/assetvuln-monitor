"""Strict GET-only external readers. Neither client exposes mutating HTTP verbs."""
import time
from urllib.parse import urlparse
from pathlib import Path
import requests


class ReadOnlyClient:
    def __init__(self, url, timeout=30, verify=True, headers=None):
        parsed = urlparse(url)
        if parsed.scheme != 'https' or not parsed.netloc:
            raise ValueError('External sources require HTTPS')
        self.base = url.rstrip('/')
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(headers or {})

    def get(self, path, params=None):
        if not path.startswith('/') or path.startswith('//'):
            raise ValueError('Only local API paths are allowed')
        url = self.base + path
        for attempt in range(4):
            response = self.session.get(url, params=params, timeout=self.timeout,
                                        verify=self.verify, allow_redirects=False)
            if response.status_code in (301, 302, 307, 308):
                # cve.now can redirect JSON details to its own CDN; list endpoints
                # do not need redirects. Reject arbitrary locations to avoid token leaks.
                raise RuntimeError('Unexpected HTTP redirect from upstream API')
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(min(2 ** attempt + 1, 10))
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError('Upstream retry budget exhausted')


def _list(payload, *keys):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ValueError('Expected JSON object/array')
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    for key in ('message_response', 'messageResponse', 'data', 'result'):
        value = payload.get(key)
        if isinstance(value, dict):
            for sub in keys:
                if isinstance(value.get(sub), list):
                    return value[sub]
    raise ValueError('Could not locate expected array in API response; refusing partial import')


def _value(row, *keys, default=''):
    for key in keys:
        v = row.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return default


class ManageEngineCollector:
    def __init__(self, cfg):
        token = Path(cfg['token_file']).read_text().strip()
        verify = cfg.get('ca_bundle') or True
        self.client = ReadOnlyClient(cfg['url'], verify=verify,
            headers={'Authorization': token, 'Accept': 'application/InventoryMobileAPI.v1+json'})
        self.max_assets = int(cfg.get('max_assets', 10000))
        self.max_pages = int(cfg.get('max_pages', 500))

    def _scan(self):
        assets = []
        for page in range(1, self.max_pages + 1):
            data = self.client.get('/dcapi/inventory/viewData/scanComputers', {'page': page})
            rows = _list(data, 'messageResponse', 'computers')
            assets.extend(rows)
            if len(assets) > self.max_assets:
                raise ValueError('Asset cap exceeded; increase max_assets after review')
            total_pages = int(data.get('totalPages') or 1)
            if page >= total_pages:
                return assets
        raise ValueError('Inventory page cap reached; refusing incomplete sync')

    def _software(self, source_id):
        # softwareInfo supports pagination. Some versions return plain arrays from /software;
        # use the documented softwareInfo representation to avoid silent truncation.
        results = []
        path = f'/dcapi/inventory/computers/{source_id}/softwareInfo'
        for page in range(1, self.max_pages + 1):
            response = self.client.get(path, {'offset': page, 'limit': 100})
            rows = _list(response, 'data', 'messageResponse')
            results.extend(rows)
            meta = response.get('metadata', {}) if isinstance(response, dict) else {}
            total_pages = int(meta.get('totalPages') or response.get('totalPages') or 1)
            if page >= total_pages:
                return results
        raise ValueError(f'Software pagination cap reached for {source_id}')

    def collect(self):
        result = []
        for row in self._scan():
            rid = _value(row, 'resource_id', 'resourceID')
            if not rid or not rid.isdecimal():
                raise ValueError(f'Missing or unsafe resource ID in {row!r}')
            asset = {
                'source_id': rid,
                'hostname': _value(row, 'resource_name', 'resource_name_transform', 'friendly_name'),
                'fqdn': _value(row, 'fqdn_name'),
                'ip_address': _value(row, 'ip_address', 'ip_address_transform'),
                'os_name': _value(row, 'os_name', 'os_name_transform'),
                'os_version': _value(row, 'os_version', 'os_version_transform'),
                'domain': _value(row, 'domain_netbios_name'),
                'agent_status': _value(row, 'status_label_transform', 'status_label'),
            }
            if not asset['hostname']:
                raise ValueError(f'Asset {rid} has no hostname')
            software = []
            for item in self._software(rid):
                name = _value(item, 'invsw.software_name', 'software_name', 'display_name')
                if not name:
                    continue
                software.append({
                    'name': name,
                    'vendor': _value(item, 'invmanufacturer.manufacturer_name', 'manufacturer_name', default='Unknown'),
                    'version': _value(item, 'invsw.software_version', 'software_version', default='unknown'),
                })
            result.append((asset, software))
            time.sleep(.55)  # Help stay inside documented per-minute API thresholds.
        return result


class CveNowCollector:
    def __init__(self, cfg):
        self.client = ReadOnlyClient(cfg.get('url', 'https://cve.now'),
                                     timeout=int(cfg.get('request_timeout_seconds', 30)))
        self.max_pages = int(cfg.get('max_pages_per_poll', 5))

    def collect(self):
        entries = []
        seen = set()
        cursor = None
        for _ in range(self.max_pages):
            params = {'cursor': cursor} if cursor else None
            response = self.client.get('/api/v1/entries', params=params)
            batch = _list(response, 'entries', 'items', 'data', 'results')
            entries.extend(batch)
            cursor = response.get('nextCursor') or response.get('next_cursor')
            if not cursor:
                break
            if cursor in seen:
                raise ValueError('Repeated CVE cursor')
            seen.add(cursor)
        return entries
