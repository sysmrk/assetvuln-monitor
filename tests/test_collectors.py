from unittest.mock import Mock
import pytest
from avm.collectors import _list, _value, ReadOnlyClient, ManageEngineCollector


def test_parse_scanned_asset_from_official_shape():
    row = {'resource_id':'301','resource_name':'sample-computer','os_name':'Windows 11',
           'ip_address':'10.0.0.1'}
    assert _value(row, 'resource_name') == 'sample-computer'
    assert _list({'messageResponse':[row]}, 'messageResponse') == [row]


def test_per_computer_software_response_dotted_keys():
    row = {'invsw.software_name':'Sample Software','invsw.software_version':'1.2.3',
           'invmanufacturer.manufacturer_name':'Sample Vendor'}
    assert _value(row,'invsw.software_name') == 'Sample Software'
    assert _list({'data':[row]},'data') == [row]


def test_fail_closed_when_expected_array_missing():
    with pytest.raises(ValueError):
        _list({'unknown_payload':[]}, 'messageResponse')


def test_https_mandatory():
    with pytest.raises(ValueError):
        ReadOnlyClient('http://endpoint.example.com')


def test_client_has_no_mutating_methods():
    client = ReadOnlyClient('https://example.com')
    assert callable(client.get)
    for name in ('post','put','patch','delete'):
        assert not hasattr(client, name)


def test_scan_pagination(monkeypatch):
    instance = object.__new__(ManageEngineCollector)
    instance.max_pages, instance.max_assets = 10, 100
    instance.client = Mock()
    instance.client.get.side_effect = [
        {'messageResponse':[{'resource_id':'1'}], 'totalPages':2},
        {'messageResponse':[{'resource_id':'2'}], 'totalPages':2},
    ]
    assert len(instance._scan()) == 2
    assert instance.client.get.call_count == 2
