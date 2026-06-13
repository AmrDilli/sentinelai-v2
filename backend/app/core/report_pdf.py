"""Server-side PDF incident report (ReportLab).

Renders a Report (as produced by the pipeline) into a branded, multi-section
PDF an analyst can attach to a ticket or hand to management: cover band with
risk score, narrative, findings with MITRE + remediation, the ATT&CK summary,
the investigation playbook, and the SOAR action log — with a running header,
page numbers, and severity colour-coding.

ReportLab is an optional dependency: `is_available()` lets the API return a
clean 501 instead of crashing if it isn't installed.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
except Exception:  # pragma: no cover - exercised only when reportlab missing
    colors = None

try:
    from reportlab.platypus import (
        BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable, KeepTogether,
    )
    _HAVE_REPORTLAB = True
except Exception:  # pragma: no cover
    _HAVE_REPORTLAB = False


# Brand + severity palette (kept close to the dashboard's dark UI accents).
BRAND = "#0891b2"
SEV_HEX = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#0284c7", "info": "#64748b",
}


def is_available() -> bool:
    return _HAVE_REPORTLAB


def _c(hex_str: str):
    return colors.HexColor(hex_str)


def _styles():
    base = getSampleStyleSheet()
    styles = {
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=16,
                             textColor=_c("#0f172a"), spaceBefore=14, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12,
                             textColor=_c(BRAND), spaceBefore=12, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9.5,
                               leading=14, alignment=TA_LEFT, textColor=_c("#1e293b")),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontSize=8,
                                leading=11, textColor=_c("#475569")),
        "mono": ParagraphStyle("mono", parent=base["BodyText"], fontName="Courier",
                               fontSize=8, leading=11, textColor=_c(BRAND)),
        "find_title": ParagraphStyle("find_title", parent=base["Heading3"], fontSize=10.5,
                                     textColor=_c("#0f172a"), spaceAfter=2),
    }
    return styles


def _meta_table(report: dict, S: dict):
    usage = report.get("usage") or {}
    rows = [
        ["Artifact", report.get("source_file", "—"), "Module", (report.get("module") or "").upper()],
        ["Engine", report.get("ai_provider", "mock") + (" (cached)" if report.get("cached") else ""),
         "Generated", (report.get("generated_at") or "").replace("T", " ")[:19]],
        ["Findings", str(len(report.get("findings", []))),
         "AI cost", f"${usage.get('cost_usd', 0):.4f}" if usage.get("cost_usd") else "—"],
    ]
    data = [[Paragraph(f"<b>{a}</b>", S["small"]), Paragraph(str(b), S["small"]),
             Paragraph(f"<b>{c}</b>", S["small"]), Paragraph(str(d), S["small"])]
            for a, b, c, d in rows]
    t = Table(data, colWidths=[0.9 * inch, 2.5 * inch, 0.9 * inch, 2.1 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, _c("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, _c("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _score_band(report: dict, S: dict):
    sev = report.get("severity", "info")
    score = report.get("score", 0)
    col = _c(SEV_HEX.get(sev, SEV_HEX["info"]))
    cell = Table(
        [[Paragraph(f'<font size=26 color="white"><b>{score}</b></font>'
                    f'<font size=11 color="white">/100</font>', S["body"]),
          Paragraph(f'<font size=13 color="white"><b>{sev.upper()}</b></font><br/>'
                    f'<font size=8 color="white">overall risk</font>', S["body"])]],
        colWidths=[1.5 * inch, 5.9 * inch])
    cell.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), col),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
    ]))
    return cell


def _finding_block(f: dict, S: dict):
    sev = f.get("severity", "info")
    col = SEV_HEX.get(sev, SEV_HEX["info"])
    conf = int(round(float(f.get("confidence", 0)) * 100))
    parts = [
        Paragraph(f'<font color="{col}"><b>[{sev.upper()}]</b></font> '
                  f'{_esc(f.get("title", "Untitled"))} '
                  f'<font color="#94a3b8" size=8>conf {conf}%</font>', S["find_title"]),
        Paragraph(_esc(f.get("description", "")), S["body"]),
    ]
    if f.get("mitre_techniques"):
        parts.append(Paragraph("MITRE: " + ", ".join(f["mitre_techniques"]), S["mono"]))
    for r in f.get("remediation", []):
        parts.append(Paragraph(f"• {_esc(r)}", S["small"]))
    parts.append(Spacer(1, 6))
    # Severity-coloured left rule via a 1-cell table border.
    block = Table([[parts]], colWidths=[7.4 * inch])
    block.setStyle(TableStyle([
        ("LINEBEFORE", (0, 0), (0, -1), 3, _c(col)),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return KeepTogether(block)


def _esc(s) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def build_report_pdf(report: dict) -> bytes:
    """Render a report dict to PDF bytes. Raises RuntimeError if ReportLab
    is unavailable (callers should check is_available() first)."""
    if not _HAVE_REPORTLAB:
        raise RuntimeError("reportlab is not installed")

    S = _styles()
    buf = io.BytesIO()
    title = f"SentinelAI Report — {report.get('source_file', '')}"

    def _decorate(canvas, doc):
        canvas.saveState()
        w, h = LETTER
        # Top brand bar
        canvas.setFillColor(_c("#0f172a"))
        canvas.rect(0, h - 0.55 * inch, w, 0.55 * inch, fill=1, stroke=0)
        canvas.setFillColor(_c(BRAND))
        canvas.rect(0, h - 0.58 * inch, w, 0.03 * inch, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(0.6 * inch, h - 0.38 * inch, "SentinelAI v2")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_c("#94a3b8"))
        canvas.drawRightString(w - 0.6 * inch, h - 0.38 * inch, "Incident Analysis Report")
        # Footer
        canvas.setStrokeColor(_c("#e2e8f0"))
        canvas.line(0.6 * inch, 0.55 * inch, w - 0.6 * inch, 0.55 * inch)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(_c("#94a3b8"))
        canvas.drawString(0.6 * inch, 0.4 * inch,
                          f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawRightString(w - 0.6 * inch, 0.4 * inch, f"Page {doc.page}")
        canvas.restoreState()

    frame = Frame(0.6 * inch, 0.65 * inch, LETTER[0] - 1.2 * inch,
                  LETTER[1] - 1.35 * inch, id="main")
    doc = BaseDocTemplate(buf, pagesize=LETTER, title=title,
                          author="SentinelAI v2", topMargin=0.7 * inch)
    doc.addPageTemplates([PageTemplate(id="branded", frames=[frame], onPage=_decorate)])

    story = []
    story.append(Paragraph("Analysis Report", S["h1"]))
    story.append(_meta_table(report, S))
    story.append(Spacer(1, 10))
    story.append(_score_band(report, S))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Executive Summary", S["h2"]))
    story.append(Paragraph(_esc(report.get("narrative", "")) or "No narrative.", S["body"]))

    findings = report.get("findings", [])
    story.append(Paragraph(f"Findings ({len(findings)})", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_c("#e2e8f0"),
                            spaceBefore=2, spaceAfter=6))
    if findings:
        for f in findings:
            story.append(_finding_block(f, S))
    else:
        story.append(Paragraph("No findings.", S["small"]))

    matrix = report.get("mitre", [])
    if matrix:
        story.append(Paragraph("MITRE ATT&CK Coverage", S["h2"]))
        for tac in matrix:
            techs = ", ".join(f'{t["id"]} {t["name"]}' for t in tac.get("techniques", []))
            story.append(Paragraph(
                f'<b>{_esc(tac.get("tactic_name", tac.get("tactic_id")))}</b> — {_esc(techs)}',
                S["small"]))

    playbook = report.get("playbook", [])
    if playbook:
        story.append(Paragraph("Investigation Playbook", S["h2"]))
        for s in playbook:
            blk = [Paragraph(f'<b>{s.get("step", "?")}. {_esc(s.get("title", ""))}</b> '
                             f'<font color="#94a3b8" size=8>({_esc(s.get("phase", ""))})</font>',
                             S["body"]),
                   Paragraph(_esc(s.get("instructions", "")), S["small"])]
            if s.get("expected_outcome"):
                blk.append(Paragraph(f'<i>Expected: {_esc(s["expected_outcome"])}</i>', S["small"]))
            blk.append(Spacer(1, 4))
            story.append(KeepTogether(blk))

    soar = report.get("soar_actions", [])
    if soar:
        story.append(Paragraph("Automated Response (SOAR)", S["h2"]))
        data = [[Paragraph("<b>Action</b>", S["small"]), Paragraph("<b>Target</b>", S["small"]),
                 Paragraph("<b>Status</b>", S["small"])]]
        for a in soar:
            data.append([
                Paragraph(_esc((a.get("action", "")).replace("_", " ")), S["small"]),
                Paragraph(_esc(a.get("target", "")), S["mono"]),
                Paragraph(_esc(a.get("status", "")), S["small"]),
            ])
        t = Table(data, colWidths=[2.4 * inch, 2.6 * inch, 2.4 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _c("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _c("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.5, _c("#cbd5e1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, _c("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)

    doc.build(story)
    return buf.getvalue()
