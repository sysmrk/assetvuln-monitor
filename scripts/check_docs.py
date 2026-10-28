#!/usr/bin/env python3
"""Validate local Markdown navigation in the V3 GitHub documentation.

No network, Docker, source edits or third-party dependencies. External links
are not fetched; only relative Markdown target paths/heading anchors are
verified. This is a lightweight safety net, not a complete Markdown renderer.
"""
import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'\]\(([^)\s]+)(?:\s+["\'][^)]*)?\)')
HEADING = re.compile(r'^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$')
REQUIRED = [
    'README.md',
    'docs/INSTALLATION.md',
    'docs/USER-GUIDE.md',
    'docs/COMMANDS.md',
    'docs/CONFIGURATION.md',
    'docs/MAPPING-REVIEW.md',
    'docs/SECURITY.md',
    'docs/TROUBLESHOOTING.md',
    'docs/V03-MULTISOURCE.md',
    'docs/V03-OPERATIONS.md',
    'docs/fa/START-HERE.md',
]


def slug(title):
    # GitHub-style heading slug for the simple headings used by AVM docs.
    title = re.sub(r'<[^>]+>', '', title)
    title = title.replace('**', '').replace('__', '').replace(chr(96), '')
    title = re.sub(r'[^\w\- ]', '', title.lower(), flags=re.UNICODE)
    return title.replace(' ', '-')


def anchors(markdown):
    names = set()
    seen = {}
    for line in markdown.splitlines():
        match = HEADING.match(line)
        if match:
            key = slug(match.group(1))
            occurrence = seen.get(key, 0)
            seen[key] = occurrence + 1
            names.add(key if occurrence == 0 else f'{key}-{occurrence}')
    return names


def check():
    errors = []
    docs = [ROOT / p for p in REQUIRED]
    for path in docs:
        if not path.is_file():
            errors.append(f'Missing required documentation: {path.relative_to(ROOT)}')
    if errors:
        return errors

    all_markdown = [ROOT / 'README.md'] + sorted((ROOT / 'docs').rglob('*.md'))
    for path in all_markdown:
        body = path.read_text(encoding='utf-8')
        inside_code = False
        for lineno, line in enumerate(body.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith('~~~') or stripped.startswith(chr(96) * 3):
                inside_code = not inside_code
                continue
            if inside_code:
                continue
            for raw in LINK.findall(line):
                if raw.startswith(('http://', 'https://', 'mailto:', '#', 'data:')):
                    if raw.startswith('#'):
                        target_path = path
                        fragment = raw[1:]
                    else:
                        continue
                else:
                    ref, separator, fragment = raw.partition('#')
                    ref = unquote(ref)
                    target_path = (path.parent / ref).resolve()
                    if not target_path.is_relative_to(ROOT):
                        errors.append(f'{path.relative_to(ROOT)}:{lineno}: path leaves repository: {raw}')
                        continue
                    if not target_path.is_file():
                        errors.append(f'{path.relative_to(ROOT)}:{lineno}: broken path: {raw}')
                        continue
                if fragment and target_path.suffix.lower() == '.md':
                    if unquote(fragment).lower() not in anchors(
                            target_path.read_text(encoding='utf-8')):
                        errors.append(
                            f'{path.relative_to(ROOT)}:{lineno}: missing heading '
                            f'{fragment} in {target_path.relative_to(ROOT)}'
                        )
    return errors


if __name__ == '__main__':
    failures = check()
    if failures:
        for failure in failures:
            print('DOC ERROR:', failure, file=sys.stderr)
        raise SystemExit(1)
    print('Documentation navigation: PASS (local paths and headings verified)')
