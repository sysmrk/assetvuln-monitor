from avm.matching import is_affected, extract_affected
from avm.demo import vulnerabilities


def test_range_lower_bound_inclusive_upper_exclusive():
    spec = {'ranges':[{'type':'SEMVER','events':[{'introduced':'1.0.0'},{'fixed':'2.0.0'}]}]}
    assert is_affected('1.0.0', spec) is True
    assert is_affected('1.5.1', spec) is True
    assert is_affected('2.0.0', spec) is False
    assert is_affected('2.1.0', spec) is False


def test_unknown_versions_are_never_positive():
    assert is_affected('vendor-patched-release', {'versions':['1.2.3']}) is None
    assert is_affected('1.0.0', {'ranges':[{'type':'GIT','events':[{'introduced':'0'}]}]}) is None
    assert is_affected('1.0.0', {}) is None


def test_exact_affected_versions():
    assert is_affected('0.4.0', {'versions':['0.4.0']}) is True
    assert is_affected('0.5.0', {'versions':['0.4.0']}) is False


def test_demo_synthetic_and_structured():
    demo = vulnerabilities()
    assert all(e['synthetic'] for e in demo)
    assert all(e['id'].startswith('CVE-DEMO-') for e in demo)
    assert len(extract_affected(demo[0])) == 1
    assert is_affected('1.4.0', extract_affected(demo[0])[0]['spec']) is True
    assert is_affected('2.0.0', extract_affected(demo[0])[0]['spec']) is False


def test_no_match_from_text_description():
    entry = {'id':'CVE-EXAMPLE','description':'Tomcat before 9.0.90 is vulnerable'}
    assert extract_affected(entry) == []
