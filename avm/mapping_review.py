"""Audited mapping review with explicit human approval; no automatic promotion.

Only an operator with application DB access can run the mutating review CLI.
This module does not contact Endpoint Central or write to managed assets.
"""
from datetime import datetime, timezone

from sqlalchemy import select

from avm.models import (ApprovedSoftwareMapping, Installation, MappingDecision,
                        MappingReview, Software, Asset)
from avm.normalization import (approved_index, normalized_label, runtime_lookup,
                               suggest_candidates)


class ReviewError(ValueError):
    """A review action violated a validation or workflow gate."""


def _actor(actor):
    if (not isinstance(actor, str) or not 2 <= len(actor) <= 120
            or not actor.strip() or '\n' in actor or '\r' in actor):
        raise ReviewError('Specify a stable 2–120-character reviewer/actor identifier')
    return actor.strip()


def _reason(reason):
    if (not isinstance(reason, str) or not 12 <= len(reason.strip()) <= 2000
            or '\x00' in reason):
        raise ReviewError('Provide an explicit 12–2000-character evidence/decision reason')
    return reason.strip()


def _field(value, label, max_chars):
    if (not isinstance(value, str) or not value.strip()
            or len(value.strip()) > max_chars or '\x00' in value):
        raise ReviewError(f'{label} requires a non-empty string <= {max_chars} characters')
    return value.strip()


def _approved_rows(session, operator_rows):
    """Merge only verified YAML and previously approved SQL records; fail on conflict."""
    rows = list(operator_rows)
    for record in session.scalars(select(ApprovedSoftwareMapping)):
        rows.append({'vendor': record.vendor, 'name': record.name,
                     'ecosystem': record.ecosystem, 'package': record.package_name})
    return rows


def approved_runtime_lookup(session, operator_rows):
    # approved_index rejects conflicting normalized vendor/name identities.
    return runtime_lookup(_approved_rows(session, operator_rows))


def _record_proposal(session, *, vendor, name, ecosystem, package, origin,
                     actor, evidence, similarity=None):
    vendor = _field(vendor, 'vendor', 500)
    name = _field(name, 'name', 500)
    ecosystem = _field(ecosystem, 'ecosystem', 100)
    package = _field(package, 'package', 500)
    actor = _actor(actor)
    normalized_vendor = normalized_label(vendor)
    normalized_name = normalized_label(name)
    normalized_ecosystem = normalized_label(ecosystem)
    normalized_package = normalized_label(package)
    if origin not in ('auto', 'manual'):
        raise ReviewError('Unknown proposal source')
    if similarity is not None and not 0 <= similarity <= 1:
        raise ReviewError('Invalid similarity score')
    existing = session.scalar(select(MappingReview).where(
        MappingReview.normalized_vendor == normalized_vendor,
        MappingReview.normalized_name == normalized_name,
        MappingReview.ecosystem == normalized_ecosystem,
        MappingReview.package_name == normalized_package).with_for_update())
    if existing:
        if existing.status == 'pending' and origin == 'auto':
            existing.last_seen = datetime.now(timezone.utc)
        return existing, False
    item = MappingReview(
        vendor=vendor, name=name, normalized_vendor=normalized_vendor,
        normalized_name=normalized_name, ecosystem=normalized_ecosystem,
        package_name=normalized_package, similarity=similarity, origin=origin,
        proposed_by=actor, evidence=evidence, status='pending')
    session.add(item)
    session.flush()
    session.add(MappingDecision(review_id=item.id, action='proposed', actor=actor,
                                reason='Automatic similarity candidate; requires review'
                                if origin == 'auto' else evidence['justification']))
    return item, True


def propose_manual(session, *, vendor, name, ecosystem, package, actor, evidence,
                   operator_rows=()):
    """Stage an explicitly identified package; do not approve or update matching."""
    actor = _actor(actor)
    evidence = _reason(evidence)
    approved = approved_index(_approved_rows(session, operator_rows))
    key = (normalized_label(vendor), normalized_label(name))
    if key in approved:
        raise ReviewError('This software identity already has an approved mapping')
    return _record_proposal(session, vendor=vendor, name=name, ecosystem=ecosystem,
                            package=package, origin='manual', actor=actor,
                            evidence={'justification': evidence})


def review_decision(session, *, review_id, action, actor, reason,
                    operator_rows=()):
    """Transition pending review to approved/rejected with append-only event."""
    if action not in ('approved', 'rejected'):
        raise ReviewError('Decision must be approved or rejected')
    actor = _actor(actor)
    reason = _reason(reason)
    item = session.scalar(select(MappingReview).where(
        MappingReview.id == review_id).with_for_update())
    if item is None:
        raise ReviewError('Mapping review does not exist')
    if item.status != 'pending':
        raise ReviewError('Only pending mapping reviews may be decided')
    if item.origin == 'manual' and actor.casefold() == item.proposed_by.casefold():
        raise ReviewError('Manual proposal requires a different approver/reviewer')
    if action == 'approved':
        approved = approved_index(_approved_rows(session, operator_rows))
        key = (item.normalized_vendor, item.normalized_name)
        if key in approved:
            raise ReviewError('Already-approved product identity conflicts with this decision')
        session.add(ApprovedSoftwareMapping(
            vendor=item.vendor, name=item.name,
            normalized_vendor=item.normalized_vendor,
            normalized_name=item.normalized_name, ecosystem=item.ecosystem,
            package_name=item.package_name, review_id=item.id, approved_by=actor))
    item.status = action
    item.reviewed_by = actor
    item.review_reason = reason
    item.reviewed_at = datetime.now(timezone.utc)
    session.add(MappingDecision(review_id=item.id, action=action, actor=actor, reason=reason))
    session.flush()
    return item


def refresh_review_queue(session, operator_rows, *, min_similarity=0.88, max_candidates=1):
    """Stage unapproved suggestions after an atomic successful inventory upsert.

    Auto proposals are deliberately bounded to one candidate per unique product
    per sync. Rejected/approved decisions are not re-opened by later syncs.
    """
    approved = approved_index(_approved_rows(session, operator_rows))
    active_software = session.scalars(
        select(Software).join(Installation, Installation.software_id == Software.id)
        .join(Asset, Asset.id == Installation.asset_id)
        .where(Installation.active.is_(True), Asset.active.is_(True)).distinct()
    ).all()
    seen = 0
    for software in active_software:
        vendor = software.vendor
        name = software.name
        if (not vendor or normalized_label(vendor) in ('unknown', 'n/a', 'none')
                or (normalized_label(vendor), normalized_label(name)) in approved):
            continue
        for candidate in suggest_candidates(vendor, name, approved,
                                             min_similarity=min_similarity,
                                             limit=max_candidates):
            target = candidate['mapping']
            _, created = _record_proposal(
                session, vendor=vendor, name=name,
                ecosystem=target['ecosystem'], package=target['package'],
                origin='auto', actor='system:normalizer',
                evidence={'source': 'approved_catalog', 'matched_vendor': target['vendor'],
                          'matched_name': target['name'],
                          'name_similarity': candidate['name_similarity']},
                similarity=candidate['name_similarity'])
            seen += int(created)
    return seen
