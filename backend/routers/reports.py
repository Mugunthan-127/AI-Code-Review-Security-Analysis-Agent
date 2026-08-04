from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, Finding
from datetime import datetime
import json

router = APIRouter()

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
}

import uuid

@router.get("/{scan_id}/export/markdown")
def export_markdown(scan_id: str, db: Session = Depends(get_db)):
    """Export a scan's findings as a markdown report."""
    scan_uuid = uuid.UUID(scan_id)
    scan = db.query(Scan).filter(Scan.scan_id == scan_uuid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_uuid).all()

    # Group findings by agent source
    sec_findings     = [f for f in findings if f.agent_source == "security_vulnerability"]
    quality_findings = [f for f in findings if f.agent_source == "code_analysis"]
    other_findings   = [f for f in findings if f.agent_source not in ("security_vulnerability", "code_analysis")]

    lines = []
    lines.append(f"# 🔍 Code Review & Security Scan Report")
    lines.append(f"")
    lines.append(f"**Scan ID:** `{scan_id}`  ")
    lines.append(f"**Language:** {scan.language.value.title() if scan.language else 'Unknown'}  ")
    lines.append(f"**Status:** {scan.status.value.upper() if scan.status else 'Unknown'}  ")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append(f"")

    # Summary stats
    high_count = sum(1 for f in findings if str(f.severity).lower() in ('critical', 'high'))
    med_count  = sum(1 for f in findings if str(f.severity).lower() == 'medium')
    low_count  = sum(1 for f in findings if str(f.severity).lower() == 'low')

    lines.append(f"## 📊 Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total Findings | {len(findings)} |")
    lines.append(f"| 🔒 Security Issues | {len(sec_findings)} |")
    lines.append(f"| 🔍 Code Quality Issues | {len(quality_findings)} |")
    lines.append(f"| 🔴🟠 High+ Severity | {high_count} |")
    lines.append(f"| 🟡 Medium Severity | {med_count} |")
    lines.append(f"| 🔵 Low Severity | {low_count} |")
    lines.append(f"")

    # PR Summary — parse JSON from pr_summary_node and render as readable markdown
    lines.append(f"## 📝 PR Review Summary")
    lines.append(f"")
    raw_summary = scan.summary_text or ""
    try:
        parsed = json.loads(raw_summary)
        overview = parsed.get("executive_overview", "")
        if overview:
            lines.append(f"**Executive Overview:** {overview}")
            lines.append(f"")
        sev_breakdown = parsed.get("severity_breakdown", {})
        if sev_breakdown:
            sev_parts = ", ".join(f"{k.capitalize()}: {v}" for k, v in sev_breakdown.items() if v)
            if sev_parts:
                lines.append(f"**Severity Breakdown:** {sev_parts}")
                lines.append(f"")
        pf = parsed.get("prioritized_findings", [])
        if pf:
            lines.append(f"**Top Priorities:**")
            for item in pf:
                lines.append(f"- [{item.get('severity','').upper()}] **{item.get('title','')}** — {item.get('recommendation','')}")
            lines.append(f"")
    except (json.JSONDecodeError, TypeError):
        # Fallback: render raw text if it's not JSON
        if raw_summary:
            lines.append(raw_summary)
        else:
            lines.append("_No summary generated._")
    lines.append(f"")

    # Security findings section
    if sec_findings:
        lines.append(f"---")
        lines.append(f"")
        lines.append(f"## 🔒 Security Vulnerability Findings ({len(sec_findings)})")
        lines.append(f"")
        for f in sorted(sec_findings, key=lambda x: (x.severity or 'low'), reverse=True):
            sev_emoji = SEVERITY_EMOJI.get(str(f.severity).lower(), '⚪')
            lines.append(f"### {sev_emoji} {f.title or 'Finding'} ({str(f.severity).upper()})")
            lines.append(f"")
            if f.owasp_type:
                lines.append(f"- **OWASP Type:** {f.owasp_type}")
            if f.cwe_id:
                lines.append(f"- **CWE:** [{f.cwe_id}](https://cwe.mitre.org/data/definitions/{f.cwe_id.replace('CWE-','')}.html)")
            if f.line:
                lines.append(f"- **Location:** Line {f.line}{f', Col ' + str(f.column_num) if f.column_num else ''}")
            if f.tool:
                lines.append(f"- **Detected by:** `{f.tool.upper()}`")
            if f.rule_id:
                lines.append(f"- **Rule:** `{f.rule_id}`")
            if f.grounding_source:
                lines.append(f"- **KB Reference:** {f.grounding_source.replace('.md','').replace('_',' ')}")
            lines.append(f"")
            if f.explanation:
                lines.append(f"**Explanation:**")
                lines.append(f"{f.explanation}")
                lines.append(f"")
            if f.suggested_fix:
                lines.append(f"**Suggested Fix:**")
                lines.append(f"```")
                lines.append(f.suggested_fix)
                lines.append(f"```")
                lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

    # Code quality findings section
    if quality_findings:
        lines.append(f"## 🔍 Code Quality Findings ({len(quality_findings)})")
        lines.append(f"")
        for f in sorted(quality_findings, key=lambda x: (x.severity or 'low'), reverse=True):
            sev_emoji = SEVERITY_EMOJI.get(str(f.severity).lower(), '⚪')
            lines.append(f"### {sev_emoji} {f.title or 'Finding'} ({str(f.severity).upper()})")
            lines.append(f"")
            if f.line:
                lines.append(f"- **Location:** Line {f.line}{f', Col ' + str(f.column_num) if f.column_num else ''}")
            if f.tool:
                lines.append(f"- **Detected by:** `{f.tool.upper()}`")
            if f.rule_id:
                lines.append(f"- **Rule:** `{f.rule_id}`")
            lines.append(f"")
            if f.explanation:
                lines.append(f"**Explanation:**")
                lines.append(f"{f.explanation}")
                lines.append(f"")
            if f.suggested_fix:
                lines.append(f"**Suggested Fix:**")
                lines.append(f"```")
                lines.append(f.suggested_fix)
                lines.append(f"```")
                lines.append(f"")
            lines.append(f"---")
            lines.append(f"")

    if not findings:
        lines.append(f"✅ **No issues found.** The code passed all security and quality checks.")

    md_content = "\n".join(lines)
    return PlainTextResponse(
        md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id[:8]}_report.md"}
    )
