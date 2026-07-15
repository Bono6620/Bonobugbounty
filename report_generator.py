#!/usr/bin/env python3
"""
Bono Bug Bounty — report generator.

Takes the outputs of recon_pipeline() + triage.py and produces one
markdown report: scope, recon summary, categorized signals (severity
is *estimated*, not confirmed), remediation text per category, and
manual verification steps. This report is a starting point for your
own manual PoC work and submission — not a replacement for it.
"""

from datetime import datetime, timezone
from pathlib import Path

from remediation import REMEDIATION, MANUAL_VERIFICATION_STEPS

SEVERITY_BY_CATEGORY = {
    "sqli": "High (estimate — confirm manually)",
    "xss": "Medium (estimate — confirm manually)",
    "idor": "Medium/High depending on data exposed (confirm manually)",
    "misconfig": "Low/Medium (confirm manually)",
    "exposure": "Medium (confirm manually)",
    "cve": "See CVE/CVSS score in the finding",
}


def _count_lines(path: Path) -> int:
    return sum(1 for _ in path.open()) if path.exists() else 0


def build_report(
    output_path: Path,
    domains: list[str],
    subs_file: Path,
    alive_file: Path,
    nuclei_general_file: Path,
    xss_candidates: list,
    sqli_file: Path,
    idor_candidates: list,
):
    lines = []
    lines.append("# Bono Bug Bounty — Recon & Triage Report\n")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
    lines.append(f"**Scope (as provided):** {', '.join(domains)}\n")
    lines.append(
        "\n> ⚠️ كل الـ findings هنا هي *مؤشرات* من recon/light probing أوتوماتيكي. "
        "الـ severity تقديري. لازم تتأكد وتعمل PoC يدوي قبل أي تقديم رسمي.\n"
    )

    lines.append("## 1. Recon Summary\n")
    lines.append(f"- Subdomains discovered: **{_count_lines(subs_file)}**")
    lines.append(f"- Alive hosts probed: **{_count_lines(alive_file)}**")
    lines.append(f"- General nuclei findings (misconfig/exposure/cve/etc.): **{_count_lines(nuclei_general_file)}**")
    lines.append(f"- SQLi signal hits (nuclei): **{_count_lines(sqli_file)}**")
    lines.append(f"- XSS reflection candidates: **{len(xss_candidates)}**")
    lines.append(f"- IDOR pattern candidates: **{len(idor_candidates)}**\n")

    def category_block(title, key, items_desc, verify_steps_key=None):
        cat, rem_text = REMEDIATION[key]
        block = [f"## {title}\n", f"**Estimated severity:** {SEVERITY_BY_CATEGORY.get(key, 'N/A')}\n"]
        block.append(items_desc)
        block.append("\n**Manual verification steps:**\n")
        block.append(MANUAL_VERIFICATION_STEPS.get(verify_steps_key or key, "راجع يدوي."))
        block.append("\n**Remediation:**\n")
        block.append(rem_text)
        block.append("\n---\n")
        return "\n".join(block)

    # XSS
    if xss_candidates:
        items = "\n".join(f"- `{url}` — parameter: `{param}`" for url, param in xss_candidates[:50])
        lines.append(category_block("2. Cross-Site Scripting (XSS) — Candidates", "xss", items))
    else:
        lines.append("## 2. Cross-Site Scripting (XSS)\nمفيش candidates اتلقت.\n\n---\n")

    # SQLi
    if sqli_file.exists() and _count_lines(sqli_file) > 0:
        items = "```\n" + sqli_file.read_text()[:4000] + "\n```"
        lines.append(category_block("3. SQL Injection — nuclei signals", "sqli", items))
    else:
        lines.append("## 3. SQL Injection\nمفيش signals من nuclei في الـ hosts دي.\n\n---\n")

    # IDOR
    if idor_candidates:
        items = "\n".join(f"- `{url}`" for url in idor_candidates[:50])
        lines.append(category_block("4. IDOR — Pattern Candidates", "idor", items))
    else:
        lines.append("## 4. IDOR\nمفيش URL patterns واضحة اتلقت.\n\n---\n")

    # General nuclei (misconfig/exposure/cve mixed)
    lines.append("## 5. Other Findings (misconfig / exposure / known CVEs)\n")
    if nuclei_general_file.exists() and _count_lines(nuclei_general_file) > 0:
        lines.append("```\n" + nuclei_general_file.read_text()[:6000] + "\n```\n")
        lines.append("راجع كل finding وحدد الفئة بتاعته (misconfig/exposure/cve) من اسم الـ template، "
                      "وطبّق الـ remediation المناسب:\n")
        for key in ("misconfig", "exposure", "cve"):
            _, rem_text = REMEDIATION[key]
            lines.append(f"\n**{REMEDIATION[key][0]}:**\n{rem_text}\n")
    else:
        lines.append("مفيش findings إضافية.\n")

    lines.append("\n---\n## 6. Next Steps\n")
    lines.append(
        "- راجع كل candidate يدوي واعمل PoC حقيقي قبل ما تقدم.\n"
        "- خد screenshots/HTTP requests-responses كدليل لكل finding مؤكد.\n"
        "- اتأكد إن كل target فعلاً جوه الـ scope الرسمي للبرنامج قبل التقديم.\n"
        "- استخدم صيغة تقرير HackerOne (Summary / Steps to Reproduce / Impact / "
        "Remediation) لما تجهز تقدم كل finding مؤكد.\n"
    )

    output_path.write_text("\n".join(lines))
    return output_path
