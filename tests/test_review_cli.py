"""Operator CLI integration tests: explicit approvals, audit, no automatic trust."""
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from avm.models import Base
from avm import review_cli


def test_review_cli_manual_two_person_process(tmp_path, monkeypatch, capsys):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'review.sqlite'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(review_cli, 'session_factory', lambda: (engine, factory))
    file = tmp_path / 'approved.yaml'
    file.write_text('products: []\n')
    monkeypatch.setattr(review_cli, 'config',
                        lambda: {'matching': {'mappings_file': str(file)}})

    propose = [
        'propose', '--vendor', 'Acme Corp', '--name', 'Secure Endpoint',
        '--ecosystem', 'PyPI', '--package', 'acme-endpoint',
        '--actor', 'proposer_a', '--evidence',
        'Reviewed the software name and advisory identity in documentation.']
    assert review_cli.main(propose) == 0
    record = capsys.readouterr().out
    assert 'Created review ID 1' in record
    assert review_cli.main(['list']) == 0
    line = capsys.readouterr().out.splitlines()[0]
    listing = json.loads(line)
    assert listing['status'] == 'pending'
    assert listing['package'] == 'acme-endpoint'

    denied = ['approve', '--id', '1', '--actor', 'proposer_a', '--reason',
              'Reviewed the advisory and vendor confirmation for this package.']
    assert review_cli.main(denied) == 2
    assert 'different' in capsys.readouterr().err

    approve = ['approve', '--id', '1', '--actor', 'reviewer_b', '--reason',
               'Verified the product identity and advisories independently.']
    assert review_cli.main(approve) == 0
    assert 'next inventory sync' in capsys.readouterr().out

    assert review_cli.main(['history', '--review-id', '1']) == 0
    lines = capsys.readouterr().out.splitlines()
    events = [json.loads(item) for item in lines]
    assert [item['action'] for item in events] == ['proposed', 'approved']

    assert review_cli.main(['approve', '--id', '1', '--actor', 'reviewer_c',
                            '--reason', 'Attempting a second decision must be rejected.']) == 2
    capsys.readouterr()
    assert review_cli.main(['list', '--status', 'approved']) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[0])['status'] == 'approved'
    engine.dispose()
