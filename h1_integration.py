#!/usr/bin/env python3
"""
Bono Bug Bounty — HackerOne integration.

Pulls the *official, structured scope* for a program directly from the
HackerOne API, so scanning only ever targets assets HackerOne itself
lists as eligible for submission. This is safer than a human copying
domains by hand.

Auth: HackerOne API uses HTTP Basic auth with your H1 username + a
personal API token (generate one from your HackerOne account
settings -> API Token). Needs the `H1_USERNAME` and `H1_API_TOKEN`
secrets set in the GitHub repo.

Docs: https://api.hackerone.com/docs/v1
"""

import os
import requests

H1_USERNAME = os.environ.get("H1_USERNAME", "")
H1_API_TOKEN = os.environ.get("H1_API_TOKEN", "")
H1_BASE = "https://api.hackerone.com/v1/hackers"

# Asset types we can actually feed into subfinder/httpx/nuclei.
SCANNABLE_TYPES = {"URL", "WILDCARD", "CIDR"}


def _auth():
    if not H1_USERNAME or not H1_API_TOKEN:
        raise RuntimeError("H1_USERNAME / H1_API_TOKEN not configured")
    return (H1_USERNAME, H1_API_TOKEN)


def fetch_structured_scope(handle: str):
    """
    Returns a dict:
      {
        "scannable": [domains/wildcards suitable for subfinder/httpx/nuclei],
        "other_in_scope": [(identifier, asset_type) for in-scope but non-scannable assets, e.g. source code, mobile apps],
        "out_of_scope": [identifiers explicitly marked NOT eligible for submission],
      }
    Raises requests.HTTPError if the program handle is wrong or the API call fails.
    """
    url = f"{H1_BASE}/programs/{handle}/structured_scopes"
    scannable, other_in_scope, out_of_scope = [], [], []
    page_url = url

    while page_url:
        resp = requests.get(page_url, auth=_auth(), timeout=30)
        resp.raise_for_status()
        payload = resp.json()

        for item in payload.get("data", []):
            attrs = item.get("attributes", {})
            identifier = attrs.get("asset_identifier", "")
            asset_type = attrs.get("asset_type", "")
            eligible = attrs.get("eligible_for_submission", False)
            instruction = attrs.get("instruction", "")

            if not eligible:
                out_of_scope.append(identifier)
                continue

            if asset_type in SCANNABLE_TYPES:
                # Wildcards like *.example.com -> strip the leading *.
                clean = identifier.lstrip("*.")
                scannable.append(clean)
            else:
                other_in_scope.append((identifier, asset_type, instruction))

        page_url = (payload.get("links") or {}).get("next")

    return {
        "scannable": sorted(set(scannable)),
        "other_in_scope": other_in_scope,
        "out_of_scope": sorted(set(out_of_scope)),
    }


def format_scope_message(handle: str, scope: dict) -> str:
    lines = [f"📋 Scope بتاع برنامج: {handle}\n"]
    lines.append(f"✅ Scannable assets ({len(scope['scannable'])}):")
    lines.extend(f"  - {d}" for d in scope["scannable"][:40])
    if len(scope["scannable"]) > 40:
        lines.append(f"  ... و {len(scope['scannable']) - 40} إضافيين")

    if scope["other_in_scope"]:
        lines.append(f"\nℹ️ In-scope بس مش قابل للـ auto-scan ({len(scope['other_in_scope'])}):")
        for ident, atype, _ in scope["other_in_scope"][:20]:
            lines.append(f"  - {ident} ({atype})")

    if scope["out_of_scope"]:
        lines.append(f"\n🚫 Out of scope صراحة ({len(scope['out_of_scope'])}) — هيتم تجاهلها تمامًا.")

    return "\n".join(lines)
