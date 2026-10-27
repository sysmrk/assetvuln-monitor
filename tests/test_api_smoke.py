import io
import json
import sys

from scripts import test_manageengine_api as api


class Response:
    status = 200

    def __init__(self, payload):
        self.content = io.BytesIO(json.dumps(payload).encode('utf-8'))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.content.close()

    def read(self, size=-1):
        return self.content.read(size)


class FakeOpener:
    def __init__(self, empty=False):
        self.requests = []
        self.empty = empty

    def open(self, request, timeout):
        assert request.get_method() == 'GET'
        assert request.get_header('Authorization') == 'test-secret-not-for-logs'
        self.requests.append(request.full_url)
        if 'scanComputers' in request.full_url:
            return Response({'messageResponse': [] if self.empty else [{'resource_id': '123', 'resource_name': 'WS-01'}]})
        if '/computers/123/softwareInfo?' in request.full_url:
            return Response({'data': [{'invsw.software_name': 'Example'}]})
        raise AssertionError('Unrecognized route')


def test_smoke_exercises_exactly_two_get_endpoints_without_disclosing_token(tmp_path, monkeypatch, capsys):
    token = tmp_path / 'token'
    token.write_text('test-secret-not-for-logs')
    opener = FakeOpener()
    monkeypatch.setattr(api, 'build_opener', lambda *args: opener)
    monkeypatch.setattr(sys, 'argv', ['test_manageengine_api.py', '--url', 'https://ec.example.test',
                                     '--token-file', str(token), '--config', str(tmp_path / 'missing')])
    assert api.main() == 0
    stdout = capsys.readouterr().out
    assert 'API endpoints to test: 2' in stdout
    assert '[PASS] 1/2' in stdout and '[PASS] 2/2' in stdout
    assert 'test-secret-not-for-logs' not in stdout
    assert len(opener.requests) == 2
    assert opener.requests[0].endswith('scanComputers?page=1')
    assert opener.requests[1].endswith('softwareInfo?offset=1&limit=100')


def test_empty_inventory_skips_software_test_and_exits_nonzero(tmp_path, monkeypatch, capsys):
    token = tmp_path / 'token'
    token.write_text('test-secret-not-for-logs')
    monkeypatch.setattr(api, 'build_opener', lambda *args: FakeOpener(empty=True))
    monkeypatch.setattr(sys, 'argv', ['test_manageengine_api.py', '--url', 'https://ec.example.test',
                                     '--token-file', str(token)])
    assert api.main() == 1
    assert '[SKIP] 2/2' in capsys.readouterr().out


def test_redirects_disabled():
    assert api.NoRedirect().redirect_request(None, None, 302, 'Moved', None, 'https://bad.test') is None
