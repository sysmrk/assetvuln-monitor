"""Conservative software identity normalization and *review-only* suggestions.

Suggestions are derived exclusively from already-approved product mappings.
Similarity is a string score, NOT a probability of product identity. Nothing
in this module approves a mapping or produces a vulnerability finding.
"""

from difflib import SequenceMatcher
from unicodedata import normalize as unicode_normalize
import re


def normalized_label(value):
    """Canonical label for identity comparison; never strip version tokens."""
    if not isinstance(value, str):
        raise ValueError('Software identity fields must be strings')
    return re.sub(r'\s+', ' ', unicode_normalize('NFKC', value).casefold()).strip()


def normalize_software(vendor, name, version=''):
    """Retain raw values alongside cautious case/whitespace-normalized labels."""
    if not all(isinstance(x, str) for x in (vendor, name, version)):
        raise ValueError('Vendor, name and version must be strings')
    return {
        'vendor': vendor,
        'name': name,
        'version': version,
        'normalized_vendor': normalized_label(vendor),
        'normalized_name': normalized_label(name),
        'normalized_version': unicode_normalize('NFKC', version).strip(),
    }


def approved_index(rows):
    """Validate four-field operator-approved catalogue; reject ambiguity."""
    if not isinstance(rows, list):
        raise ValueError('Mappings products must be a list')
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Mapping entry must be an object')
        fields = ('vendor', 'name', 'ecosystem', 'package')
        if any(not isinstance(row.get(key), str) or not row[key].strip() for key in fields):
            raise ValueError('Mapping entry requires non-empty vendor, name, ecosystem and package')
        key = (normalized_label(row['vendor']), normalized_label(row['name']))
        if key in result:
            raise ValueError(f'Duplicate approved software identity: {key!r}')
        result[key] = {field: row[field].strip() for field in fields}
    return result


def suggest_candidates(vendor, name, approved, min_similarity=0.88, limit=3):
    """Find review-only candidates with exactly matching vendor and similar name.

    'approved' is the result of approved_index, never an untrusted CVE feed.
    Exact name+vendor identities are already approved and yield no suggestions.
    """
    if not 0.0 <= min_similarity <= 1.0 or limit < 1:
        raise ValueError('Invalid similarity threshold or candidate limit')
    source_vendor = normalized_label(vendor)
    source_name = normalized_label(name)
    if not source_vendor or not source_name or len(source_name) > 256:
        return []
    if (source_vendor, source_name) in approved:
        return []
    candidates = []
    for (target_vendor, target_name), mapping in approved.items():
        if target_vendor != source_vendor or len(target_name) > 256:
            continue
        similarity = SequenceMatcher(None, source_name, target_name, autojunk=False).ratio()
        if similarity < min_similarity:
            continue
        candidates.append({
            'status': 'review_required',
            'mapping': dict(mapping),
            'name_similarity': round(similarity, 4),
            'evidence': ['exact_normalized_vendor', 'similar_normalized_product_name', 'candidate_from_approved_catalog'],
        })
    candidates.sort(key=lambda c: (-c['name_similarity'], normalized_label(c['mapping']['name'])))
    return candidates[:limit]


def mapping_report(installed, approved, min_similarity=0.88, limit=3):
    """Summarize unique products; only explicit existing mappings count as approved."""
    products = {}
    installation_count = 0
    for item in installed:
        if not isinstance(item, dict):
            raise ValueError('Inventory rows must be objects')
        vendor = item.get('vendor', '')
        name = item.get('name', '')
        version = item.get('version', '')
        identity = normalize_software(vendor, name, version)
        if not identity['normalized_name']:
            continue
        installation_count += 1
        key = (identity['normalized_vendor'], identity['normalized_name'])
        if key not in products:
            products[key] = identity
    matched = 0
    proposals = []
    for (vendor, name), identity in sorted(products.items()):
        if (vendor, name) in approved:
            matched += 1
            continue
        candidates = suggest_candidates(identity['vendor'], identity['name'], approved,
                                        min_similarity=min_similarity, limit=limit)
        proposals.append({
            'software': {'vendor': identity['vendor'], 'name': identity['name']},
            'normalized': {'vendor': vendor, 'name': name},
            'status': 'review_required' if candidates else 'unmapped',
            'candidates': candidates,
        })
    return {
        'metrics': {
            'installation_rows': installation_count,
            'unique_products': len(products),
            'approved_products': matched,
            'unmapped_products': len(products) - matched,
            'products_with_candidates': sum(bool(p['candidates']) for p in proposals),
        },
        'suggestions': proposals,
        'warning': 'Name similarity is not product identity; all candidates require human review. No mappings are written.',
    }
