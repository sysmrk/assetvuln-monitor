#!/usr/bin/env python3
"""Independent, read-only smoke test of the two ManageEngine APIs used by AVM.

No Docker, database, third-party Python packages or application imports needed.
Only GET requests; never prints token or full response bodies.
"""
import argparse
import json
import re
import ssl
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

ENDPOINTS = (
    ("Inventory: scan computers", "/dcapi/inventory/viewData/scanComputers"),
    ("Inventory: computer software", "/dcapi/inventory/computers/{resource_id}/softwareInfo"),
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def settings_from_yaml(path):
    """Read the small set of flat manageengine YAML scalars without PyYAML."""
    values = {}
    active = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            active = line.strip() == "manageengine:"
            continue
        if not active:
            continue
        match = re.match(r"^\s{2}([a-z_]+):\s*(.*?)\s*(?:#.*)?$", line)
        if match:
            values[match.group(1)] = match.group(2).strip().strip('"\'')
    return values


def rows_from(payload, keys):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object or array")
    for key in keys:
        if isinstance(payload.get(key), list):
            return payload[key]
    for container in ("message_response", "messageResponse", "data", "result"):
        inner = payload.get(container)
        if isinstance(inner, dict):
            for key in keys:
                if isinstance(inner.get(key), list):
                    return inner[key]
    raise ValueError("Expected list not found in response (schema mismatch)")


def request_json(opener, base, path, params, token, timeout):
    url = base + path + "?" + urlencode(params)
    req = Request(url, headers={
        "Authorization": token,
        "Accept": "application/InventoryMobileAPI.v1+json",
        "User-Agent": "assetvuln-monitor-api-smoke-test/1.0",
    }, method="GET")
    start = time.monotonic()
    with opener.open(req, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}")
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise ValueError("Response exceeds 2 MB safety cap")
        return json.loads(body), round((time.monotonic() - start) * 1000)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default="config/application.yaml", help="Application YAML (default: config/application.yaml)")
    p.add_argument("--url", help="Override ManageEngine HTTPS base URL")
    p.add_argument("--token-file", help="Override token file (default: secrets/manageengine_token)")
    p.add_argument("--ca-bundle", help="Trusted CA PEM for internal TLS")
    p.add_argument("--resource-id", help="Numeric resource ID to test software API without relying on scan results")
    p.add_argument("--timeout", type=float, default=20)
    args = p.parse_args()
    print("ManageEngine independent API test (GET only; no data modifications)")
    print(f"API endpoints to test: {len(ENDPOINTS)}")
    for index, (label, path) in enumerate(ENDPOINTS, 1):
        print(f"  {index}. GET {path} — {label}")
    print()
    try:
        cfg = settings_from_yaml(Path(args.config)) if Path(args.config).is_file() else {}
        base = (args.url or cfg.get("url") or "").rstrip("/")
        parts = urlsplit(base)
        if parts.scheme != "https" or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("A valid HTTPS base URL without embedded credentials is required")
        token_path = Path(args.token_file or "secrets/manageengine_token")
        token = token_path.read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("API token file is empty")
        ca = args.ca_bundle or cfg.get("ca_bundle") or None
        context = ssl.create_default_context(cafile=ca)
        opener = build_opener(HTTPSHandler(context=context), NoRedirect())
        if args.resource_id and not re.fullmatch(r"[0-9]+", args.resource_id):
            raise ValueError("--resource-id must contain digits only")
    except (OSError, ValueError) as exc:
        print(f"SETUP FAILED: {exc}", file=sys.stderr)
        return 2

    failures = 0
    resource_id = args.resource_id
    try:
        payload, elapsed = request_json(opener, base, ENDPOINTS[0][1], {"page": 1}, token, args.timeout)
        records = rows_from(payload, ("messageResponse", "computers"))
        if not all(isinstance(item, dict) for item in records):
            raise ValueError("Computer list contains non-object entries")
        if not resource_id:
            for item in records:
                candidate = str(item.get("resource_id") or item.get("resourceID") or "")
                if re.fullmatch(r"[0-9]+", candidate):
                    resource_id = candidate
                    break
        print(f"[PASS] 1/2 scanComputers: HTTP 200, JSON list, {len(records)} records on page 1, {elapsed} ms")
    except (HTTPError, URLError, OSError, ValueError, json.JSONDecodeError) as exc:
        failures += 1
        print(f"[FAIL] 1/2 scanComputers: {type(exc).__name__}: {exc}")

    if resource_id is None:
        print("[SKIP] 2/2 softwareInfo: no numeric resource ID available; pass --resource-id ID")
    else:
        path = ENDPOINTS[1][1].format(resource_id=resource_id)
        try:
            payload, elapsed = request_json(opener, base, path, {"offset": 1, "limit": 100}, token, args.timeout)
            records = rows_from(payload, ("data", "messageResponse"))
            if not all(isinstance(item, dict) for item in records):
                raise ValueError("Software list contains non-object entries")
            print(f"[PASS] 2/2 softwareInfo: HTTP 200, JSON list, {len(records)} records, {elapsed} ms (resource_id={resource_id})")
        except (HTTPError, URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            failures += 1
            print(f"[FAIL] 2/2 softwareInfo: {type(exc).__name__}: {exc}")
    print(f"Result: {2 - failures - (resource_id is None)} passed, {failures} failed, {int(resource_id is None)} skipped")
    return 1 if failures or resource_id is None else 0


if __name__ == "__main__":
    sys.exit(main())
