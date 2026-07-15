#!/usr/bin/env python3
"""
Bono Bug Bounty — Telegram recon bot.

Runs once per invocation (designed to be triggered on a schedule by
GitHub Actions). Each run:
  1. Fetches new Telegram updates since the last seen update_id.
  2. Parses any /scan commands from authorized users.
  3. Runs the recon pipeline (subfinder -> httpx -> nuclei).
  4. Sends the results back to the chat as a file.
  5. Persists state (last_update_id) to state.json for the next run.

IMPORTANT — SCOPE OF USE
-------------------------
This bot only automates *reconnaissance* using well-known, publicly
available tools (subfinder, httpx, nuclei with community templates).
It does not contain or generate exploit code. Only ever point it at
targets you are explicitly authorized to test (your own assets, or
assets explicitly in-scope for a bug bounty / pentest engagement you
are contracted for). Running recon/scans against domains you are not
authorized to test is illegal in most jurisdictions and against the
ToS of every bug bounty platform.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import requests

import triage
import h1_integration
from report_generator import build_report

BOT_TOKEN = os.environ["BOT_TOKEN"]
# Comma-separated list of Telegram numeric user IDs allowed to use the bot.
ALLOWED_USERS = {u.strip() for u in os.environ.get("ALLOWED_USERS", "").split(",") if u.strip()}

API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"
STATE_FILE = Path(__file__).parent / "state.json"
WORKDIR = Path("/tmp/bono_scan")

# Safety caps so a single run stays inside the Actions time budget.
MAX_DOMAINS_PER_SCAN = 15
NUCLEI_SEVERITY = "medium,high,critical"
NUCLEI_RATE_LIMIT = 100  # requests/sec, keep polite


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"last_update_id": 0}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def tg_get_updates(offset):
    r = requests.get(f"{API_URL}/getUpdates", params={"offset": offset, "timeout": 0}, timeout=30)
    r.raise_for_status()
    return r.json().get("result", [])


def tg_send_message(chat_id, text):
    requests.post(f"{API_URL}/sendMessage", data={"chat_id": chat_id, "text": text}, timeout=30)


def tg_send_document(chat_id, file_path, caption=""):
    with open(file_path, "rb") as f:
        requests.post(
            f"{API_URL}/sendDocument",
            data={"chat_id": chat_id, "caption": caption},
            files={"document": f},
            timeout=120,
        )


def is_authorized(user_id):
    if not ALLOWED_USERS:
        # Fail safe: if no allow-list is configured, nobody is authorized.
        return False
    return str(user_id) in ALLOWED_USERS


def parse_scope(text):
    """Extract domains from a /scan command. Accepts comma or whitespace separated list."""
    body = text.split(None, 1)[1] if " " in text else ""
    raw = re.split(r"[,\s]+", body.strip())
    domains = []
    for item in raw:
        if not item:
            continue
        item = re.sub(r"^https?://", "", item).strip("/")
        item = item.split("/")[0]  # strip any path
        if re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", item):
            domains.append(item)
    return domains[:MAX_DOMAINS_PER_SCAN]


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.pop("timeout", 1800), **kwargs)


def recon_pipeline(domains, workdir):
    workdir.mkdir(parents=True, exist_ok=True)
    domains_file = workdir / "scope.txt"
    domains_file.write_text("\n".join(domains))

    subs_file = workdir / "subdomains.txt"
    alive_file = workdir / "alive.txt"
    findings_file = workdir / "findings.txt"

    # 1. Subdomain enumeration
    run(["subfinder", "-dL", str(domains_file), "-silent", "-o", str(subs_file)])
    # Make sure the root domains themselves are included even if subfinder finds nothing
    with subs_file.open("a") as f:
        for d in domains:
            f.write(d + "\n")

    # 2. Probe for alive hosts + basic tech/status info
    run(
        ["httpx", "-l", str(subs_file), "-silent", "-status-code", "-title",
         "-tech-detect", "-o", str(alive_file)],
    )

    # Build a clean host list (first column) for nuclei
    hosts_only = workdir / "alive_hosts.txt"
    with alive_file.open() as inp, hosts_only.open("w") as out:
        for line in inp:
            host = line.split()[0] if line.strip() else ""
            if host:
                out.write(host + "\n")

    # 3. General vulnerability / misconfig detection via nuclei community templates
    #    (excludes sqli -- that gets its own categorized pass below)
    run(
        ["nuclei", "-l", str(hosts_only), "-silent",
         "-severity", NUCLEI_SEVERITY,
         "-etags", "sqli",
         "-rl", str(NUCLEI_RATE_LIMIT),
         "-o", str(findings_file)],
        timeout=3000,
    )

    # 4. Categorized signal pass: SQLi (nuclei tags -- detection templates only)
    sqli_file = triage.run_nuclei_category(hosts_only, workdir, "sqli", "sqli_findings.txt",
                                            rate_limit=NUCLEI_RATE_LIMIT)

    # 5. URL discovery for param-based checks (XSS reflection / IDOR patterns)
    urls_file = triage.discover_urls(hosts_only, workdir)
    xss_candidates = triage.probe_reflected_xss(urls_file)
    idor_candidates = triage.flag_idor_candidates(urls_file)

    return subs_file, alive_file, findings_file, sqli_file, xss_candidates, idor_candidates


def handle_scan(chat_id, domains):
    tg_send_message(
        chat_id,
        f"🔍 بدأت الـ recon على {len(domains)} target(s):\n" + "\n".join(domains) +
        "\n\nهياخد شوية وقت (subfinder → httpx → nuclei)...",
    )

    run_dir = WORKDIR / str(int(time.time()))
    try:
        (subs_file, alive_file, findings_file,
         sqli_file, xss_candidates, idor_candidates) = recon_pipeline(domains, run_dir)
    except subprocess.TimeoutExpired:
        tg_send_message(chat_id, "⏱️ الـ scan خد وقت أطول من المسموح وتوقف. جرب تقلل عدد الدومينات.")
        return

    n_subs = sum(1 for _ in subs_file.open()) if subs_file.exists() else 0
    n_alive = sum(1 for _ in alive_file.open()) if alive_file.exists() else 0

    tg_send_message(
        chat_id,
        f"✅ خلصت الـ recon والـ triage\n"
        f"Subdomains: {n_subs} | Alive hosts: {n_alive}\n"
        f"XSS candidates: {len(xss_candidates)} | SQLi signals: "
        f"{sum(1 for _ in sqli_file.open()) if sqli_file.exists() else 0} | "
        f"IDOR candidates: {len(idor_candidates)}\n\n"
        "📝 بجهز التقرير الكامل...",
    )

    report_path = run_dir / "report.md"
    build_report(
        report_path, domains, subs_file, alive_file, findings_file,
        xss_candidates, sqli_file, idor_candidates,
    )
    tg_send_document(chat_id, report_path, "Bono Bug Bounty — Full Report")


def handle_h1scope(chat_id, handle):
    try:
        scope = h1_integration.fetch_structured_scope(handle)
    except RuntimeError:
        tg_send_message(chat_id, "⚠️ H1_USERNAME / H1_API_TOKEN مش متظبطين في الـ secrets.")
        return
    except requests.HTTPError as e:
        tg_send_message(chat_id, f"❌ مقدرتش أجيب الـ scope لـ '{handle}': {e}")
        return
    tg_send_message(chat_id, h1_integration.format_scope_message(handle, scope))


def handle_h1scan(chat_id, handle):
    try:
        scope = h1_integration.fetch_structured_scope(handle)
    except RuntimeError:
        tg_send_message(chat_id, "⚠️ H1_USERNAME / H1_API_TOKEN مش متظبطين في الـ secrets.")
        return
    except requests.HTTPError as e:
        tg_send_message(chat_id, f"❌ مقدرتش أجيب الـ scope لـ '{handle}': {e}")
        return

    domains = scope["scannable"][:MAX_DOMAINS_PER_SCAN]
    if not domains:
        tg_send_message(chat_id, f"مفيش scannable assets واضحة في scope '{handle}'. جرب /h1scope الأول تشوف التفاصيل.")
        return

    tg_send_message(
        chat_id,
        f"📋 هستخدم الـ scope الرسمي بتاع '{handle}' (بس الـ assets الـ eligible_for_submission):\n" +
        "\n".join(domains) +
        (f"\n\n(في {len(scope['scannable']) - len(domains)} أصول إضافية تجاوزت الحد الأقصى "
         f"{MAX_DOMAINS_PER_SCAN} — شغّل /h1scan تاني أو قسّمهم يدوي)" if len(scope["scannable"]) > len(domains) else "")
    )
    handle_scan(chat_id, domains)


def main():
    state = load_state()
    updates = tg_get_updates(state["last_update_id"] + 1)

    for update in updates:
        state["last_update_id"] = update["update_id"]
        message = update.get("message") or {}
        text = message.get("text", "")
        chat_id = message.get("chat", {}).get("id")
        user_id = message.get("from", {}).get("id")

        if not text or chat_id is None:
            continue

        if not is_authorized(user_id):
            tg_send_message(chat_id, "🚫 مش مصرح لك تستخدم البوت ده.")
            continue

        if text.startswith("/start"):
            tg_send_message(
                chat_id,
                "Bono Bug Bounty 🐛\n\n"
                "/scan domain1.com domain2.com — recon يدوي على دومينات تديها\n"
                "/h1scope <program-handle> — تعرض scope رسمي من HackerOne\n"
                "/h1scan <program-handle> — تجيب الـ scope الرسمي وتشغّل الـ scan عليه تلقائي\n\n"
                "استخدمه بس على scope مصرح لك تختبره."
            )
        elif text.startswith("/h1scope"):
            handle = text.split(None, 1)[1].strip() if " " in text else ""
            if not handle:
                tg_send_message(chat_id, "استخدم: /h1scope <program-handle>\nمثال: /h1scope shopify")
                continue
            handle_h1scope(chat_id, handle)
        elif text.startswith("/h1scan"):
            handle = text.split(None, 1)[1].strip() if " " in text else ""
            if not handle:
                tg_send_message(chat_id, "استخدم: /h1scan <program-handle>\nمثال: /h1scan shopify")
                continue
            handle_h1scan(chat_id, handle)
        elif text.startswith("/scan"):
            domains = parse_scope(text)
            if not domains:
                tg_send_message(chat_id, "محتاج تبعت دومين صحيح بعد /scan. مثال:\n/scan example.com")
                continue
            handle_scan(chat_id, domains)
        else:
            tg_send_message(chat_id, "الأوامر المتاحة: /scan <domain(s)>")

    save_state(state)


if __name__ == "__main__":
    sys.exit(main())
