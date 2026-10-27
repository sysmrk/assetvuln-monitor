"""Privileged operator CLI for manually reviewed software mapping identities.

Run in the existing worker container with docker compose exec worker python -m avm.review_cli ...
No HTTP write calls. Database writes are limited to review/approval/audit records.
"""
import argparse
import json
import sys

import yaml
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from avm.mapping_review import ReviewError, propose_manual, review_decision
from avm.models import MappingDecision, MappingReview, session_factory
from avm.settings import config


def _operator_rows(cfg):
    path = cfg['matching']['mappings_file']
    with open(path, encoding='utf-8') as stream:
        parsed = yaml.safe_load(stream) or {}
    if not isinstance(parsed, dict) or not isinstance(parsed.get('products'), list):
        raise ReviewError('Mapping config requires products: [...]')
    return parsed['products']


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)

    queue = sub.add_parser('list', help='List mapping proposals (no changes)')
    queue.add_argument('--status', choices=('pending', 'approved', 'rejected', 'all'),
                       default='pending')
    queue.add_argument('--limit', type=int, default=100)

    history = sub.add_parser('history', help='Read review history (no changes)')
    history.add_argument('--review-id', type=int, required=True)

    stage = sub.add_parser('propose', help='Stage manual proposal; requires separate reviewer')
    for key in ('vendor', 'name', 'ecosystem', 'package', 'actor', 'evidence'):
        stage.add_argument('--' + key, required=True)

    for command in ('approve', 'reject'):
        action = sub.add_parser(command, help=f'{command} one pending proposal')
        action.add_argument('--id', type=int, required=True)
        action.add_argument('--actor', required=True)
        action.add_argument('--reason', required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    engine = None
    try:
        engine, factory = session_factory()
        cfg = config()
        with factory() as session:
            if args.command == 'list':
                if not 1 <= args.limit <= 500:
                    raise ReviewError('--limit must be between 1 and 500')
                stmt = select(MappingReview)
                if args.status != 'all':
                    stmt = stmt.where(MappingReview.status == args.status)
                records = session.scalars(stmt.order_by(MappingReview.id.desc()).limit(args.limit)).all()
                for entry in records:
                    print(json.dumps({
                        'id': entry.id, 'status': entry.status, 'origin': entry.origin,
                        'vendor': entry.vendor, 'name': entry.name,
                        'ecosystem': entry.ecosystem, 'package': entry.package_name,
                        'similarity': entry.similarity, 'proposed_by': entry.proposed_by,
                        'reviewed_by': entry.reviewed_by,
                    }, ensure_ascii=False))
                print(f'Returned {len(records)} review record(s).')
                return 0
            if args.command == 'history':
                records = session.scalars(
                    select(MappingDecision).where(MappingDecision.review_id == args.review_id)
                    .order_by(MappingDecision.id)).all()
                if not records:
                    raise ReviewError('No audit records for this review')
                for entry in records:
                    print(json.dumps({'event_id': entry.id, 'review_id': entry.review_id,
                                      'action': entry.action, 'actor': entry.actor,
                                      'reason': entry.reason,
                                      'created_at': entry.created_at.isoformat()},
                                     ensure_ascii=False))
                return 0

            rows = _operator_rows(cfg)
            if args.command == 'propose':
                item, created = propose_manual(
                    session, vendor=args.vendor, name=args.name,
                    ecosystem=args.ecosystem, package=args.package,
                    actor=args.actor, evidence=args.evidence, operator_rows=rows)
                session.commit()
                print(f'{"Created" if created else "Existing"} review ID {item.id} ({item.status}).')
                return 0 if created or item.status == 'pending' else 1

            status = 'approved' if args.command == 'approve' else 'rejected'
            item = review_decision(session, review_id=args.id, action=status,
                                   actor=args.actor, reason=args.reason,
                                   operator_rows=rows)
            session.commit()
            print(f'Review {item.id} {status} by {item.reviewed_by}.')
            if status == 'approved':
                print('Approved identity is applied by the worker on its next inventory sync.')
            return 0
    except (ReviewError, ValueError, KeyError, OSError, yaml.YAMLError,
            IntegrityError, SQLAlchemyError) as exc:
        # Do not print DB connection URLs or SQL driver parameters (can contain secrets).
        if isinstance(exc, (IntegrityError, SQLAlchemyError)):
            print('ERROR: Database operation failed. Changes were rolled back.', file=sys.stderr)
        else:
            print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
