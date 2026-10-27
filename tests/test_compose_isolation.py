from scripts.check_compose_isolation import isolation_errors, main
import json


def sample(name, port, root):
    return {
        'name': name,
        'volumes': {'postgres_data': {'name': name + '_postgres_data'}},
        'networks': {'backend': {'name': name + '_backend'}},
        'services': {
            'postgres': {'volumes': [{'type': 'volume', 'source': name + '_postgres_data'}]},
            'nginx': {'ports': [{'host_ip': '127.0.0.1', 'published': str(port), 'target': 443, 'protocol': 'tcp'}],
                      'volumes': [{'type': 'bind', 'source': root + '/secrets/tls/tls.crt'}]},
        },
    }


def test_isolated_default_names_and_ports():
    assert isolation_errors(sample('assetvuln-monitor', 8443, '/opt/v01'),
                            sample('assetvuln-monitor-v03', 8445, '/opt/v03')) == []


def test_fails_when_same_project():
    errors = isolation_errors(sample('assetvuln-monitor', 8443, '/opt/v01'),
                              sample('assetvuln-monitor', 8444, '/opt/v02'))
    assert any('project names' in x for x in errors)
    assert any('volumes' in x for x in errors)
    assert any('networks' in x for x in errors)


def test_fails_when_ports_collide_or_bind_sources_overlap():
    errors = isolation_errors(sample('assetvuln-monitor', 8443, '/opt/shared'),
                              sample('other', 8443, '/opt/shared'))
    assert any('host ports' in x for x in errors)
    assert any('mount' in x for x in errors)


def test_wildcard_host_ip_conflicts_with_loopback():
    left = sample('assetvuln-monitor', 8443, '/opt/v01')
    left['services']['nginx']['ports'][0]['host_ip'] = '0.0.0.0'
    assert any('host ports' in x for x in isolation_errors(left, sample('other', 8443, '/opt/v02')))


def test_cli_json_offline(tmp_path):
    old = tmp_path / 'old.json'
    new = tmp_path / 'new.json'
    old.write_text(json.dumps(sample('assetvuln-monitor', 8443, '/opt/v01')))
    new.write_text(json.dumps(sample('assetvuln-monitor-v03', 8445, '/opt/v03')))
    assert main(['--baseline-json', str(old), '--candidate-json', str(new)]) == 0
    new.write_text(json.dumps(sample('assetvuln-monitor', 8443, '/opt/v01')))
    assert main(['--baseline-json', str(old), '--candidate-json', str(new)]) == 1
