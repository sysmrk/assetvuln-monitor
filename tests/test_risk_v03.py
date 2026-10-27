from types import SimpleNamespace
import pytest

from avm.risk import (priority_score, fixed_version_candidates, evidence_packet,
                      remediation_plan, scenario_summary)


def test_risk_kev_floor_is_explainable():
    result = priority_score(cvss=4, epss=.01, kev=True,
                            criticality='unknown', internet_facing=None)
    assert result['score'] == 75
    assert result['priority'] == 'P1'
    assert result['kev_floor_applied']
    assert set(result['missing_signals']) == {'asset_criticality', 'internet_exposure'}
    assert 'method' in result


def test_risk_missing_input_not_fabricated():
    result = priority_score()
    assert result['score'] == 0
    assert 'cvss' in result['missing_signals']
    assert 'epss' in result['missing_signals']
    assert 'internet_exposure' in result['missing_signals']


def test_criticality_and_internet_exposure_increase_rank_without_guessing():
    unknown = priority_score(cvss=7, epss=.2, criticality='unknown', internet_facing=None)
    elevated = priority_score(cvss=7, epss=.2, criticality='critical', internet_facing=True)
    assert elevated['score'] > unknown['score']
    assert 0 <= elevated['score'] <= 100
    for values in ({'cvss': 11}, {'epss': -1}, {'criticality': 'supercritical'},
                   {'internet_facing': 'yes'}):
        with pytest.raises(ValueError):
            priority_score(**values)


def test_fix_candidates_must_come_from_explicit_fixed_events():
    specs = [
        {'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '2.4.0'}]}]},
        {'ranges': [{'type': 'GIT', 'events': [{'fixed': 'sha123'}]}]},
        {'versions': ['1.0.1']},
        {'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '2.8.0'}]}]},
    ]
    assert fixed_version_candidates(specs) == ['2.4.0', '2.8.0']


def test_evidence_and_remediation_are_snapshots_not_confirmations():
    asset = SimpleNamespace(source_id='301', hostname='DEMO-SERVER')
    software = SimpleNamespace(vendor='Example Vendor', name='Example Product',
                               ecosystem='pypi', package_name='example-package')
    install = SimpleNamespace(version='1.0.0')
    vuln = SimpleNamespace(id='CVE-DEMO-001')
    spec = {'ranges': [{'type':'SEMVER', 'events':[{'introduced':'0'}, {'fixed':'1.1.0'}]}]}
    evidence = evidence_packet(asset=asset, software=software, installation=install,
                               vulnerability=vuln, affected_specs=[spec])
    assert evidence['schema_version'] == 1
    assert evidence['approved_package']['name'] == 'example-package'
    assert evidence['candidate_fixed_versions'] == ['1.1.0']
    assert 'not proof' in evidence['limitations'][0]
    remediation = remediation_plan(evidence=evidence)
    assert remediation['classification'] == 'requires_vendor_verification'
    assert remediation['required_action_from_kev'] is None


def test_simulation_is_read_only_and_nonpredictive():
    items = [(1, 80), (2, 40), (3, 20), (1, 80)]
    top = scenario_summary(items, max_items=1)
    assert top['before_score_sum'] == 140
    assert top['after_score_sum'] == 60
    assert top['simulated_removals'] == 1
    assert 'not a guaranteed' in top['notice']
    kev = scenario_summary(items, remove_ids=[1, 3, 999])
    assert kev['after_score_sum'] == 40
    assert scenario_summary([], max_items=10)['modeled_score_reduction_pct'] == 0
