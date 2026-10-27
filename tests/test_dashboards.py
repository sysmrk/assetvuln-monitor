from avm.dashboards import DASHBOARDS
from avm.models import VIEWS, Asset, Software, Installation, Vulnerability, AffectedPackage, Finding, SyncRun


def test_seven_complete_dashboards():
    assert len(DASHBOARDS) == 7
    assert sum(len(cards) for cards in DASHBOARDS.values()) >= 40
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


def test_mapping_review_reporting_is_read_only_and_denominators_are_explicit():
    from avm.models import MappingReview, MappingDecision, ApprovedSoftwareMapping
    assert {x.__tablename__ for x in (MappingReview, MappingDecision, ApprovedSoftwareMapping)} == {
        'mapping_reviews', 'mapping_decisions', 'approved_software_mappings'}
    required = {
        'data_quality_overview', 'data_quality_products', 'data_quality_by_vendor',
        'data_quality_by_os', 'data_quality_by_domain', 'mapping_review_queue',
        'mapping_review_audit', 'data_quality_sync_freshness'}
    assert required.issubset(VIEWS)
    dashboard = DASHBOARDS['07 · Mapping Quality & Review']
    titles = {spec[0] for spec in dashboard}
    assert {'Pending Mapping Reviews', 'Mapping Review Queue', 'Mapping Decision Audit',
            'Verified Mapping Coverage %', 'Source Sync Freshness'}.issubset(titles)
    for name in required:
        view = VIEWS[name].upper().lstrip()
        assert view.startswith(('SELECT', 'WITH'))
        assert not any(term in view for term in (
            'DELETE FROM', 'INSERT INTO', 'UPDATE ', 'DROP TABLE', 'ALTER TABLE'))
    overview = VIEWS['data_quality_overview']
    assert 'i.active AND a.active' in overview
    assert 'nullif(count(*), 0)' in overview
    assert 'count(*)' in overview
