"""Small privileged v0.3 operations CLI; no web UI, no additional services.

Read-only queue and what-if simulation are the default. Explicit risk
acceptance is the only write action; it never mutates Endpoint Central.
"""
import argparse
from datetime import date, datetime, timedelta, timezone
import json
import sys

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from avm.models import Asset, Finding, FindingEvent, Installation, Vulnerability, session_factory
from avm.risk import scenario_summary


def _parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='operation', required=True)
    queue = sub.add_parser('queue', help='Display active potential findings by priority')
    queue.add_argument('--limit', type=int, default=20)

    sim = sub.add_parser('simulate', help='Model hypothetical removal of finding scores (read only)')
    group = sim.add_mutually_exclusive_group(required=True)
    group.add_argument('--top', type=int, help='Top N highest-scoring findings')
    group.add_argument('--kev', action='store_true', help='Findings with a CISA KEV signal')

    accept = sub.add_parser('accept', help='Time-limited risk acceptance (database change)')
    accept.add_argument('--finding-id', type=int, required=True)
    accept.add_argument('--actor', required=True)
    accept.add_argument('--reason', required=True)
    accept.add_argument('--until', required=True, help='YYYY-MM-DD; at most 180 days')

    release = sub.add_parser('release', help='Revoke an active risk acceptance')
    release.add_argument('--finding-id', type=int, required=True)
    release.add_argument('--actor', required=True)
    release.add_argument('--reason', required=True)
    return p


def _actor(text):
    if not isinstance(text, str) or not 2 <= len(text.strip()) <= 120 or '\n' in text:
        raise ValueError('Actor identifier must be 2..120 characters')
    return text.strip()


def _reason(text):
    if not isinstance(text, str) or not 12 <= len(text.strip()) <= 2000:
        raise ValueError('Document an evidence-backed reason of 12..2000 characters')
    return text.strip()


def _rows(session):
    return session.execute(
        select(Finding, Asset, Vulnerability)
        .join(Installation, Installation.id == Finding.installation_id)
        .join(Asset, Asset.id == Installation.asset_id)
        .join(Vulnerability, Vulnerability.id == Finding.vulnerability_id)
        .where(Finding.active.is_(True), Installation.active.is_(True),
               Asset.active.is_(True))).all()


def main(argv=None):
    args = _parser().parse_args(argv)
    engine = None
    try:
        engine, factory = session_factory()
        with factory() as session:
            if args.operation in ('queue', 'simulate'):
                findings = _rows(session)
                scored = [(f.id, float(f.risk_score))
                          for f, asset, v in findings if f.risk_score is not None]
                if args.operation == 'simulate':
                    if args.kev:
                        ids = [f.id for f, asset, v in findings if bool(v.kev_verified) or (v.synthetic and v.kev)]
                        result = scenario_summary(scored, remove_ids=ids)
                        result['scenario'] = 'all_current_kev_matches'
                    else:
                        result = scenario_summary(scored, max_items=args.top)
                        result['scenario'] = 'top_ranked_potential_findings'
                    print(json.dumps(result, indent=2))
                    return 0
                if not 1 <= args.limit <= 500:
                    raise ValueError('--limit must be 1..500')
                for finding, asset, vuln in sorted(
                        findings, key=lambda x: (-(float(x[0].risk_score) if x[0].risk_score is not None else -1),
                                                 x[0].id))[:args.limit]:
                    print(json.dumps({
                        'finding_id': finding.id, 'asset': asset.hostname, 'cve': vuln.id,
                        'risk_score': float(finding.risk_score) if finding.risk_score is not None else None,
                        'priority': finding.priority,
                        'reporting_sources': (finding.evidence_packet or {}).get('reporting_sources', []),
                        'state': finding.workflow_state,
                        'accepted_until': finding.accepted_until.isoformat()
                        if finding.accepted_until else None,
                    }))
                return 0
            actor = _actor(args.actor)
            reason = _reason(args.reason)
            finding = session.scalar(select(Finding).where(Finding.id == args.finding_id)
                                     .with_for_update())
            if finding is None or not finding.active:
                raise ValueError('Only an existing active Finding may be reviewed')
            instant = datetime.now(timezone.utc)
            if args.operation == 'accept':
                until = date.fromisoformat(args.until)
                if not instant.date() < until <= instant.date() + timedelta(days=180):
                    raise ValueError('Acceptance expiry must be in 1..180 days')
                finding.workflow_state = 'accepted'
                finding.accepted_until = datetime.combine(
                    until + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
                finding.accepted_by = actor
                finding.acceptance_reason = reason
                action = 'risk_accepted'
            else:
                if finding.workflow_state != 'accepted':
                    raise ValueError('Finding is not under an active risk acceptance')
                finding.workflow_state = 'open'
                finding.accepted_until = None
                finding.accepted_by = None
                finding.acceptance_reason = None
                action = 'acceptance_released'
            finding.state_updated_at = instant
            session.add(FindingEvent(finding_id=finding.id, actor=actor,
                                     action=action, reason=reason))
            session.commit()
            print(f'Finding {finding.id}: {finding.workflow_state} (recorded in audit).')
            return 0
    except (ValueError, SQLAlchemyError) as exc:
        # DBAPI error strings may contain SQL or credentials, so keep them hidden.
        print('ERROR: Invalid operation or database failure.' if isinstance(exc, SQLAlchemyError)
              else f'ERROR: {exc}', file=sys.stderr)
        return 2
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == '__main__':
    raise SystemExit(main())
