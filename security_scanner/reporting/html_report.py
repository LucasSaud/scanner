from __future__ import annotations

from pathlib import Path

from security_scanner.models import ScanResult, SEVERITY_SORT_PRIORITY
from security_scanner.reporting.report import ReportGenerator


SEVERITY_COLORS = {
    "CRITICAL": "#FF3B30",
    "HIGH": "#FF9500",
    "MEDIUM": "#FFCC00",
    "LOW": "#8E8E93",
    "INFO": "#5AC8FA",
}


def _escape_html(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


class HTMLReport(ReportGenerator):
    extension = "html"

    def generate(self, result: ScanResult) -> str:
        sc = result.severity_counts
        severity_rows = ""
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = getattr(sc, sev.lower(), 0) if sc else 0
            color = SEVERITY_COLORS.get(sev, "#999")
            severity_rows += (
                f"<tr><td style='color:{color};font-weight:bold'>{sev}</td>"
                f"<td>{count}</td></tr>\n"
            )

        corr_section = ""
        if result.correlations:
            corr_items = ""
            for ev in result.correlations:
                c = SEVERITY_COLORS.get(ev.get("severity", ""), "#999")
                corr_items += (
                    f"<div class='corr-item' style='border-left:4px solid {c}'>"
                    f"<strong>{_escape_html(ev.get('name',''))}</strong> "
                    f"<span class='sev-badge' style='background:{c}'>{ev.get('severity','')}</span>"
                    f"<p>{_escape_html(ev.get('description',''))}</p>"
                    f"</div>\n"
                )
            corr_section = f"<h2>Correlations ({len(result.correlations)})</h2>{corr_items}"

        finding_rows = ""
        for i, f in enumerate(
            sorted(result.findings, key=lambda x: SEVERITY_SORT_PRIORITY.get(x.severity, 9)), 1
        ):
            color = SEVERITY_COLORS.get(f.severity, "#999")
            terms = ", ".join(f"<code>{_escape_html(t)}</code>" for t in f.detected_terms) if f.detected_terms else ""
            evidence = f"<pre>{_escape_html(f.evidence[:300])}</pre>" if f.evidence else ""
            finding_rows += (
                f"<div class='finding' style='border-left:4px solid {color}'>"
                f"<h3>#{i} <span class='sev-badge' style='background:{color}'>{f.severity}</span> "
                f"{_escape_html(f.description)}</h3>"
                f"<p><strong>Score:</strong> {f.score:.1f} &nbsp; "
                f"<strong>File:</strong> <code>{_escape_html(str(f.file_path))}</code>"
                f"{f' &nbsp; <strong>Line:</strong> {f.line}' if f.line else ''}"
                f" &nbsp; <strong>Category:</strong> {f.category}</p>"
                f"{f'<p><strong>Terms:</strong> {terms}</p>' if terms else ''}"
                f"{evidence}"
                f"{f'<p><strong>Fix:</strong> {_escape_html(f.recommendation)}</p>' if f.recommendation else ''}"
                f"</div>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {_escape_html(str(result.target))}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f5f5f7; color:#1c1c1e; padding:20px; }}
.container {{ max-width:960px; margin:0 auto; background:#fff; border-radius:12px; padding:32px; box-shadow:0 2px 8px rgba(0,0,0,.08); }}
h1 {{ font-size:24px; margin-bottom:8px; }}
.meta {{ color:#666; font-size:14px; margin-bottom:24px; }}
.meta span {{ margin-right:16px; }}
h2 {{ font-size:18px; margin:24px 0 12px; padding-bottom:6px; border-bottom:1px solid #e5e5ea; }}
table {{ width:auto; border-collapse:collapse; margin-bottom:16px; }}
td {{ padding:4px 16px 4px 0; }}
.sev-badge {{ display:inline-block; color:#fff; font-size:11px; font-weight:600; padding:2px 8px; border-radius:4px; vertical-align:middle; }}
.finding, .corr-item {{ padding:12px 16px; margin-bottom:12px; background:#fafafa; border-radius:6px; }}
.finding h3 {{ font-size:15px; margin-bottom:6px; }}
.finding p {{ font-size:13px; color:#555; margin:4px 0; }}
.finding pre {{ background:#1c1c1e; color:#e5e5ea; padding:8px 12px; border-radius:4px; font-size:12px; overflow-x:auto; margin-top:6px; }}
code {{ background:#e5e5ea; padding:1px 5px; border-radius:3px; font-size:12px; }}
.footer {{ text-align:center; color:#999; font-size:12px; margin-top:24px; }}
</style>
</head>
<body>
<div class="container">
<h1>Security Scan Report — <code>{_escape_html(str(result.target))}</code></h1>
<div class="meta">
<span>Scan: {result.scan_id}</span>
<span>Duration: {result.duration_ms}ms</span>
<span>Files: {result.total_files}</span>
<span>Findings: {result.total_findings}</span>
<span>Risk: {result.risk_score:.1f}</span>
</div>

<h2>Severity Breakdown</h2>
<table>{severity_rows}</table>

{corr_section}

<h2>Findings ({result.total_findings})</h2>
{finding_rows}

<div class="footer">Report generated by VSCode Security Scanner</div>
</div>
</body>
</html>"""
