from __future__ import annotations

from pathlib import Path

from security_scanner.models import ScanResult, SEVERITY_SORT_PRIORITY
from security_scanner.reporting.report import ReportGenerator

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        PageBreak,
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


SEVERITY_COLORS_RGB = {
    "CRITICAL": colors.HexColor("#FF3B30"),
    "HIGH": colors.HexColor("#FF9500"),
    "MEDIUM": colors.HexColor("#FFCC00"),
    "LOW": colors.HexColor("#8E8E93"),
    "INFO": colors.HexColor("#5AC8FA"),
}


class PDFReport(ReportGenerator):
    extension = "pdf"

    def generate(self, result: ScanResult) -> str:
        raise NotImplementedError("PDFReport.generate() returns bytes, use save() or generate_bytes()")

    def generate_bytes(self, result: ScanResult) -> bytes:
        if not HAS_REPORTLAB:
            raise ImportError("reportlab is required for PDF reports: uv sync")
        from io import BytesIO
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18, spaceAfter=12)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14, spaceBefore=16, spaceAfter=8)
        normal = styles["Normal"]
        code_style = ParagraphStyle("Code", parent=normal, fontName="Courier", fontSize=8, leading=10)

        story: list = []
        story.append(Paragraph(f"Security Scan Report — {result.target}", title_style))
        meta = (
            f"Scan: {result.scan_id} | Duration: {result.duration_ms}ms | "
            f"Files: {result.total_files} | Findings: {result.total_findings} | "
            f"Risk: {result.risk_score:.1f}"
        )
        story.append(Paragraph(meta, normal))
        story.append(Spacer(1, 12))

        sc = result.severity_counts
        if sc:
            story.append(Paragraph("Severity Breakdown", h2_style))
            data = [["Severity", "Count"]]
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = getattr(sc, sev.lower(), 0)
                if count:
                    data.append([sev, str(count)])
            t = Table(data, colWidths=[80, 60])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f5f5f7")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1c1c1e")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e5ea")),
            ]))
            story.append(t)

        if result.correlations:
            story.append(Paragraph(f"Correlations ({len(result.correlations)})", h2_style))
            for ev in result.correlations:
                c = SEVERITY_COLORS_RGB.get(ev.get("severity", ""), colors.grey)
                story.append(Paragraph(
                    f"<b>{ev.get('name', '')}</b> &nbsp; "
                    f"<font color='{c.hexval()}'>{ev.get('severity', '')}</font>",
                    normal))
                story.append(Paragraph(ev.get("description", ""), normal))
                story.append(Spacer(1, 6))

        if result.findings:
            story.append(Paragraph(f"Findings ({result.total_findings})", h2_style))
            sorted_f = sorted(result.findings,
                              key=lambda f: SEVERITY_SORT_PRIORITY.get(f.severity, 9))
            for i, f in enumerate(sorted_f, 1):
                color = SEVERITY_COLORS_RGB.get(f.severity, colors.grey)
                title = f"#{i} <font color='{color.hexval()}'><b>[{f.severity}]</b></font> {f.description}"
                story.append(Paragraph(title, normal))
                detail = (
                    f"Score: {f.score:.1f} | File: {f.file_path}"
                    f"{' | Line: ' + str(f.line) if f.line else ''}"
                    f" | Category: {f.category}"
                )
                story.append(Paragraph(detail, normal))
                if f.detected_terms:
                    story.append(Paragraph(f"Terms: {', '.join(f.detected_terms)}", code_style))
                if f.evidence:
                    story.append(Paragraph(f"Evidence: {f.evidence[:200]}", code_style))
                if f.recommendation:
                    story.append(Paragraph(f"Fix: {f.recommendation}", normal))
                story.append(Spacer(1, 8))

        doc.build(story)
        return buf.getvalue()

    def save(self, result: ScanResult, output_path: Path) -> Path:
        data = self.generate_bytes(result)
        if not output_path.suffix:
            output_path = output_path.with_suffix(".pdf")
        output_path.write_bytes(data)
        return output_path
