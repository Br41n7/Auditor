from collections import defaultdict

def render_markdown(report: dict) -> str:
    lines = ["# Auditor Report", "", f"**Findings:** {report['summary']['total']}", ""]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = [f for f in report["findings"] if f["severity"] == sev]
        if not items: continue
        lines += [f"## {sev}", ""]
        for f in items:
            lines += [f"### {f['check_id']} — {f['title']}", f"- **Category:** {f['category']}", f"- **Confidence:** {f['confidence']}", f"- **URL:** `{f['url'] or 'n/a'}`", f"- **Evidence:** {f['evidence']}", f"- **Recommendation:** {f['recommendation']}", ""]
    return "\n".join(lines)
