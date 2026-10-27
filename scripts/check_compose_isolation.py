#!/usr/bin/env python3
"""Read-only comparison of resolved Docker Compose configs from two different checkouts.

Runs 'docker compose config --format json', never starts/stops containers.
No secret/environment values are emitted. Can consume saved JSON for unit tests.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def _resource_names(config, kind):
    entries = config.get(kind, {})
    return {entry.get('name', key) for key, entry in entries.items()}


def _published_ports(config):
    ports = []
    for service in config.get('services', {}).values():
        for port in service.get('ports', []):
            published = port.get('published')
            if published is not None:
                ports.append((str(port.get('host_ip', '0.0.0.0')),
                              str(published), port.get('protocol', 'tcp')))
    return ports


def _conflicts(left, right):
    host_left, port_left, protocol_left = left
    host_right, port_right, protocol_right = right
    if port_left != port_right or protocol_left != protocol_right:
        return False
    wildcard = {'', '0.0.0.0', '::', '[::]'}
    return host_left == host_right or host_left in wildcard or host_right in wildcard


def _bind_sources(config):
    return {
        mount.get('source')
        for svc in config.get('services', {}).values()
        for mount in svc.get('volumes', [])
        if mount.get('type') == 'bind' and mount.get('source')
    }


def isolation_errors(baseline, candidate):
    """Return actionable isolation violations; never echo credential values."""
    errors = []
    baseline_name = baseline.get('name')
    candidate_name = candidate.get('name')
    if not baseline_name or not candidate_name or baseline_name == candidate_name:
        errors.append('Compose project names must be non-empty and different')
    if candidate_name in ('assetvuln-monitor', 'assetvuln-monitor-v02'):
        errors.append('v0.3 must not reuse a v0.1/v0.2 Compose project name')
    for kind in ('volumes', 'networks'):
        shared = _resource_names(baseline, kind) & _resource_names(candidate, kind)
        if shared:
            errors.append(f'Overlapping {kind}: {sorted(shared)}')
    old_containers = {svc['container_name'] for svc in baseline.get('services', {}).values()
                      if svc.get('container_name')}
    new_containers = {svc['container_name'] for svc in candidate.get('services', {}).values()
                      if svc.get('container_name')}
    if old_containers & new_containers:
        errors.append('Overlapping explicitly named containers')
    overlapping_ports = [(a, b) for a in _published_ports(baseline)
                         for b in _published_ports(candidate) if _conflicts(a, b)]
    if overlapping_ports:
        errors.append('Overlapping published host ports')
    if _bind_sources(baseline) & _bind_sources(candidate):
        errors.append('Both environments mount some of the same host files/directories')
    return errors


def _resolve(directory):
    try:
        result = subprocess.run(
            ['docker', 'compose', 'config', '--format', 'json'],
            cwd=directory, capture_output=True, text=True, timeout=30, check=True)
        return json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError) as exc:
        # Avoid echoing subprocess stderr, which could contain expanded secrets.
        raise ValueError(f'Cannot resolve Docker Compose in {directory}: {type(exc).__name__}') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-dir', type=Path, help='Previously deployed baseline checkout directory')
    parser.add_argument('--candidate-dir', type=Path, default=Path('.'), help='Candidate checkout directory')
    parser.add_argument('--baseline-json', type=Path, help='Pre-resolved baseline Compose JSON')
    parser.add_argument('--candidate-json', type=Path, help='Pre-resolved candidate Compose JSON')
    args = parser.parse_args(argv)
    if (args.baseline_dir is None) == (args.baseline_json is None):
        parser.error('provide exactly one of --baseline-dir or --baseline-json')
    if args.candidate_json is not None and args.candidate_dir != Path('.'):
        parser.error('use either --candidate-json or --candidate-dir')
    try:
        left = json.loads(args.baseline_json.read_text()) if args.baseline_json else _resolve(args.baseline_dir)
        right = json.loads(args.candidate_json.read_text()) if args.candidate_json else _resolve(args.candidate_dir)
        errors = isolation_errors(left, right)
        print(f'Baseline Compose project: {left.get("name", "(missing)")}')
        print(f'Candidate Compose project: {right.get("name", "(missing)")}')
        if errors:
            for error in errors:
                print(f'[FAIL] {error}')
            return 1
        print('[PASS] Separate project names, volumes, networks, published ports, bind sources and named containers')
        print('This validates Compose configuration only, not runtime container behavior.')
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
