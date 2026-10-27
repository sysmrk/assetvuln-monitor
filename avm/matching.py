"""Conservative advisory matching. No fuzzy product equality and no guesswork."""
from packaging.version import Version, InvalidVersion


def version(v):
    try:
        return Version(str(v).strip().lstrip('v'))
    except (InvalidVersion, TypeError):
        return None


def is_affected(installed, spec):
    """OSV-style affected. None indicates unsupported/unverifiable version data."""
    v = version(installed)
    if v is None or not isinstance(spec, dict):
        return None
    explicit = spec.get('versions') or []
    if explicit and any(version(item) == v for item in explicit if version(item) is not None):
        return True
    intervals = spec.get('ranges') or []
    examined = False
    for interval in intervals:
        if not isinstance(interval, dict) or interval.get('type', '').upper() not in ('ECOSYSTEM','SEMVER'):
            continue
        events = interval.get('events', [])
        low, open_range = None, False
        for event in events:
            if not isinstance(event, dict):
                continue
            if 'introduced' in event:
                low = version(event['introduced'])
                open_range = low is not None
            if 'fixed' in event or 'last_affected' in event or 'limit' in event:
                kind = 'fixed' if 'fixed' in event else ('last_affected' if 'last_affected' in event else 'limit')
                high = version(event[kind])
                if low is None or high is None:
                    return None
                examined = True
                if open_range and v >= low and (v < high if kind in ('fixed','limit') else v <= high):
                    return True
                open_range = False
        if open_range and low is not None:
            examined = True
            if v >= low:
                return True
    if examined or explicit:
        return False
    return None


def extract_affected(entry):
    """Only accept explicit package ecosystem/name and machine-readable ranges."""
    rows = entry.get('affected') or entry.get('affectedPackages') or []
    output = []
    if not isinstance(rows, list):
        return output
    for item in rows:
        if not isinstance(item, dict):
            continue
        pkg = item.get('package', {})
        if not isinstance(pkg, dict):
            continue
        eco = pkg.get('ecosystem')
        name = pkg.get('name')
        if isinstance(eco, str) and isinstance(name, str) and eco.strip() and name.strip() and (item.get('ranges') or item.get('versions')):
            output.append({'ecosystem': eco, 'name': name, 'spec': {'ranges': item.get('ranges', []), 'versions': item.get('versions', [])}})
    return output
