"""Safe, repeatable Metabase first-run dashboard provisioning via public REST APIs."""
import logging
import os
import time
import requests
from avm.dashboards import DASHBOARDS

logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('avm.bootstrap')


class Metabase:
    def __init__(self):
        self.url = os.environ.get('METABASE_INTERNAL_URL', 'http://metabase:3000').rstrip('/')
        self.http = requests.Session()
        self.session_id = None

    def request(self, method, path, data=None):
        headers = {'Content-Type': 'application/json'}
        if self.session_id:
            headers['X-Metabase-Session'] = self.session_id
        response = self.http.request(method, self.url + path, headers=headers,
                                     json=data, timeout=120)
        if not response.ok:
            raise RuntimeError(f'Metabase {method} {path}: HTTP {response.status_code}: {response.text[:450]}')
        return response.json() if response.content else None

    def login(self):
        props = self.request('GET', '/api/session/properties')
        email = os.environ.get('METABASE_ADMIN_EMAIL', 'admin@example.local')
        password = os.environ['METABASE_ADMIN_PASSWORD']
        if props.get('has-user-setup'):
            result = self.request('POST', '/api/session', {'username':email, 'password':password})
        else:
            token = props.get('setup-token')
            if not token:
                raise RuntimeError('Metabase setup token unavailable')
            result = self.request('POST', '/api/setup', {
                'token':token,
                'user': {'email':email, 'password':password, 'first_name':'Security', 'last_name':'Administrator'},
                'prefs': {'site_name':'AssetVuln Monitor', 'site_locale':'en'}
            })
        self.session_id = result['id']

    def database(self):
        existing = self.request('GET', '/api/database')
        for db in existing.get('data', []):
            if db.get('name') == 'AssetVuln Reports':
                return db['id']
        db = self.request('POST', '/api/database', {
            'name':'AssetVuln Reports', 'engine':'postgres',
            'details': {'host':'postgres', 'port':5432, 'dbname':'avm',
                        'user':'avm_reader', 'password':os.environ['REPORT_DB_PASSWORD']},
            'is_full_sync': False, 'is_on_demand': False
        })
        return db['id']

    def collection(self):
        for c in self.request('GET', '/api/collection'):
            if c.get('name') == 'AssetVuln Monitor · Security Workspace':
                return c['id']
        return self.request('POST', '/api/collection', {
            'name':'AssetVuln Monitor · Security Workspace',
            'description':'Read-only asset intelligence, version coverage and potential CVE exposure.'
        })['id']

    def cards(self, database_id, collection_id):
        # GET /api/card is paged on recent Metabase releases.
        existing = {}
        offset = 0
        while True:
            response = self.request('GET', f'/api/card?f=all&limit=200&offset={offset}')
            batch = response if isinstance(response, list) else response.get('data', [])
            for item in batch:
                if item.get('collection_id') == collection_id:
                    existing[item['name']] = item['id']
            if len(batch) < 200:
                break
            offset += len(batch)
        for dashboard, specs in DASHBOARDS.items():
            for title, display, query, _width in specs:
                name = f'{dashboard} / {title}'
                if name not in existing:
                    payload = {'name':name, 'description':'Automatically managed read-only security report',
                               'type':'question', 'collection_id':collection_id,
                               'display':display, 'visualization_settings':{},
                               'dataset_query':{'database':database_id,'type':'native',
                                                'native':{'query':query}}}
                    existing[name] = self.request('POST', '/api/card', payload)['id']
        return existing

    def dashboards(self, collection_id, cards):
        # Avoid duplicating dashboards/cards when install.sh is run again.
        records = self.request('GET', '/api/dashboard')
        existing = {d['name']:d['id'] for d in (records if isinstance(records,list) else records.get('data',[]))}
        results = []
        for name, specs in DASHBOARDS.items():
            if name in existing:
                dashid = existing[name]
                current = self.request('GET', f'/api/dashboard/{dashid}')
                if current.get('dashcards'):
                    results.append((name, dashid))
                    continue
            else:
                dashid = self.request('POST', '/api/dashboard', {
                    'name':name, 'collection_id':collection_id,
                    'description':'Provisioned by AssetVuln Monitor. All values are read-only correlations, not confirmed exploitability.'
                })['id']
            dashcards = []
            row, col, max_height = 0, 0, 0
            for idx, (title, display, query, width) in enumerate(specs):
                height = 4 if display == 'scalar' else (8 if display in ('bar','pie','line') else 10)
                if col + width > 24:
                    row, col, max_height = row + max_height, 0, 0
                dashcards.append({'id': -(idx+1), 'card_id':cards[f'{name} / {title}'],
                                  'row':row, 'col':col, 'size_x':width, 'size_y':height})
                col += width
                max_height = max(max_height, height)
                if col == 24:
                    row, col, max_height = row + max_height, 0, 0
            self.request('PUT', f'/api/dashboard/{dashid}', {'dashcards':dashcards})
            results.append((name, dashid))
        return results


def main():
    client = Metabase()
    for _ in range(90):
        try:
            if client.request('GET', '/api/health').get('status') == 'ok':
                break
        except (requests.RequestException, RuntimeError):
            pass
        time.sleep(5)
    else:
        raise RuntimeError('Metabase did not become healthy')
    client.login()
    db = client.database()
    collection = client.collection()
    cards = client.cards(db, collection)
    boards = client.dashboards(collection, cards)
    for name, ident in boards:
        log.info('Dashboard provisioned: %s (ID=%s)', name, ident)
    log.info('Bootstrap complete: %d dashboards / %d questions', len(boards), len(cards))


if __name__ == '__main__':
    main()
