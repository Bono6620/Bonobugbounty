#!/usr/bin/env python3
"""
Bono Bug Bounty — triage/signals module.

Everything here produces *candidates for manual verification*, not
confirmed, exploited vulnerabilities. Nothing in this file attempts to
actually exploit a target (no data exfiltration, no auth bypass, no
writing to another user's resource, no chained payloads).

- XSS: sends a single benign, inert marker string as each discovered
  query parameter's value and checks whether it comes back unescaped
  in the response. This is the same class of check every reputable
  web scanner does; the marker itself has no executable payload.
- SQLi: relies entirely on nuclei's community `sqli` tagged templates
  (error-based / time-based signatures), same tool used for the rest
  of recon.
- IDOR: purely pattern-based. Flags URLs that contain what looks like
  a sequential/numeric object identifier so a human can go test
  authorization manually. Does NOT attempt to swap IDs or access
  another account's data automatically.
"""

import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import requests

MARKER = "bonoProbe9f3a"
REQUEST_TIMEOUT = 8
MAX_URLS_TO_PROBE = 300  # keep runtime bounded

IDOR_ID_PATTERN = re.compile(r"(/(?:user|users|account|accounts|order|orders|invoice|"
                              r"file|files|doc|docs|id|profile|item|items)/)(\d{2,})",
                              re.IGNORECASE)
IDOR_PARAM_NAMES = {"id", "user_id", "uid", "account_id", "order_id", "invoice_id", "doc_id"}


def run(cmd, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def discover_urls(hosts_file: Path, workdir: Path) -> Path:
    """Crawl for URLs (incl. querystrings) using katana. Passive/light crawl only."""
    urls_file = workdir / "urls.txt"
    run(["katana", "-list", str(hosts_file), "-silent", "-jc",
         "-o", str(urls_file)], timeout=1200)
    return urls_file


def _urls_with_params(urls_file: Path):
    if not urls_file.exists():
        return []
    out = []
    for line in urls_file.open():
        line = line.strip()
        if "?" in line:
            out.append(line)
    return out[:MAX_URLS_TO_PROBE]


def probe_reflected_xss(urls_file: Path):
    """Return list of (url, param) where our inert marker reflected unescaped."""
    candidates = []
    for url in _urls_with_params(urls_file):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            continue
        for param in params:
            test_params = {k: (MARKER if k == param else v[0]) for k, v in params.items()}
            test_url = url.split("?")[0] + "?" + "&".join(f"{k}={v}" for k, v in test_params.items())
            try:
                resp = requests.get(test_url, timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue
            if MARKER in resp.text:
                candidates.append((url, param))
    return candidates


def flag_idor_candidates(urls_file: Path):
    """Pattern-only candidates: URLs whose path or query looks like it carries
    a raw object id. No requests are modified/replayed against other IDs."""
    if not urls_file.exists():
        return []
    seen = set()
    candidates = []
    for line in urls_file.open():
        url = line.strip()
        if not url:
            continue
        if IDOR_ID_PATTERN.search(url):
            if url not in seen:
                seen.add(url)
                candidates.append(url)
            continue
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if any(p.lower() in IDOR_PARAM_NAMES for p in params) and url not in seen:
            seen.add(url)
            candidates.append(url)
    return candidates


def run_nuclei_category(hosts_file: Path, workdir: Path, tags: str, out_name: str, rate_limit=100):
    out_file = workdir / out_name
    run(["nuclei", "-l", str(hosts_file), "-silent",
         "-tags", tags, "-rl", str(rate_limit),
         "-o", str(out_file)], timeout=2400)
    return out_file
