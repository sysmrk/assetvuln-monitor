from avm.dashboards import DASHBOARDS
from avm.models import VIEWS, Asset, Software, Installation, Vulnerability, AffectedPackage, Finding, SyncRun


def test_six_complete_dashboards():
    assert len(DASHBOARDS) == 6
    assert sum(len(cards) for cards in DASHBOARDS.values()) >= 25
    for cards in DASHBOARDS.values():
        assert cards
        for name, display, query, width in cards:
            assert width in (6, 12, 18, 24)
            assert 'reporting.' in query
            assert query.lstrip().upper().startswith('SELECT')
            assert not any(word in query.upper() for word in ('DELETE FROM','UPDATE ','INSERT INTO','DROP TABLE'))


def test_reporting_views_and_tables():
    assert len(VIEWS) >= 9
    assert {x.__tablename__ for x in (Asset,Software,Installation,Vulnerability,AffectedPackage,Finding,SyncRun)} == {
        'assets','software','installations','vulnerabilities','affected_packages','findings','sync_runs'}
