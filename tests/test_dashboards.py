from avm.dashboards import DASHBOARDS
from avm.models import VIEWS, Asset, Software, Installation, Vulnerability, AffectedPackage, Finding, SyncRun


def test_nine_complete_dashboards():
    assert len(DASHBOARDS) == 9
    assert sum(len(cards) for cards in DASHBOARDS.values()) >= 65
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


def test_v03_risk_intelligence_queries_are_read_only():
    from avm.models import FindingEvent, RiskSnapshot
    assert {FindingEvent.__tablename__, RiskSnapshot.__tablename__} == {'finding_events', 'risk_snapshots'}
    required = {'risk_overview', 'risk_queue', 'finding_evidence', 'finding_lifecycle',
                'finding_event_history', 'risk_trend', 'risk_by_service',
                'risk_by_owner', 'asset_context_quality'}
    assert required.issubset(VIEWS.keys())
    board = DASHBOARDS['08 · Risk Intelligence & Remediation']
    labels = {card[0] for card in board}
    assert {'Risk-Based Remediation Queue', 'Finding Evidence & Candidate Remediation',
            'Risk Acceptance & Lifecycle', 'Daily Priority Trend'}.issubset(labels)
    assert all(card[2].lstrip().upper().startswith('SELECT') for card in board)
    for view in required:
        sql = VIEWS[view].upper().lstrip()
        assert sql.startswith(('SELECT', 'WITH'))
        assert not any(token in sql for token in ('DELETE FROM', 'INSERT INTO', 'UPDATE ', 'DROP TABLE'))



def test_ninth_dashboard_provenance_and_read_only_sources():
    from avm.models import AdvisoryObservation, OsvPackageCheck, FeedCheckpoint
    assert {cls.__tablename__ for cls in (AdvisoryObservation, OsvPackageCheck, FeedCheckpoint)} == {
        'advisory_observations', 'osv_package_checks', 'feed_checkpoints'}
    required = {'source_coverage', 'source_advisories', 'source_evidence',
                'finding_source_details', 'source_sync_health', 'source_cursor_status', 'source_retractions', 'source_conflicts', 'osv_cache_coverage'}
    assert required.issubset(VIEWS)
    board = DASHBOARDS['09 · Source Intelligence & Coverage']
    assert len(board) >= 10
    assert all(query.startswith('SELECT') for name, display, query, width in board)
    for name in required:
        sql = VIEWS[name].upper().lstrip()
        assert sql.startswith('SELECT')
        assert not any(verb in sql for verb in ('DELETE FROM', 'UPDATE ', 'ALTER TABLE'))
