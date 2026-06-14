"""Formal, industry-standard Incident Response report (ReportLab).

Renders a pipeline Report into the kind of document a SOC / IR team actually
delivers: a TLP-marked, multi-section incident report aligned with
NIST SP 800-61r3 (Detect → Respond → Recover) and MITRE ATT&CK.

Sections: cover page, document control + distribution, executive summary,
incident overview, severity assessment, timeline of events, technical findings,
ATT&CK mapping, indicators of compromise, threat-intel matches, containment /
eradication / recovery, recommendations (tactical + strategic), analyst
conclusion, and an appendix. A TLP:AMBER classification marking appears on every
page, as it would on a real handling-restricted report.

ReportLab is optional: is_available() lets the API return 501 if it's missing.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table,
        TableStyle, HRFlowable, KeepTogether, PageBreak, LongTable,
    )
    _HAVE_REPORTLAB = True
except Exception:  # pragma: no cover - exercised only when reportlab missing
    colors = None
    _HAVE_REPORTLAB = False

# ---- palette ----------------------------------------------------------------
INK = "#0f172a"        # near-black headings
SLATE = "#334155"
MUTE = "#64748b"
LINE = "#cbd5e1"
LINE_SOFT = "#e2e8f0"
BRAND = "#0e7490"      # teal accent (print-friendly)
SEV_HEX = {
    "critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207",
    "low": "#0369a1", "info": "#475569",
}
# FIRST TLP 2.0 marking colours (label colour on black).
TLP_AMBER = "#FFC000"

# Score thresholds mirror app/core/scoring.level_for_score.
RATING_SCALE = [
    ("Critical", 85, 100, "Confirmed or highly likely active compromise. Immediate response required."),
    ("High", 65, 84, "Strong indicators of malicious activity. Urgent investigation required."),
    ("Medium", 40, 64, "Suspicious activity warranting prompt analyst review."),
    ("Low", 15, 39, "Low-confidence or low-impact indicators. Routine review."),
    ("Informational", 0, 14, "No significant threat identified."),
]

# Map ATT&CK tactics to strategic, control-level recommendations.
_STRATEGIC = [
    (("TA0011", "TA0010"),
     "Command-and-control / exfiltration: enforce egress filtering and DNS "
     "monitoring, deploy or validate EDR coverage on all endpoints, and block "
     "the listed indicators at the perimeter and on the proxy."),
    (("TA0006",),
     "Credential access: enforce phishing-resistant MFA on all remote and "
     "privileged access, and review password and lockout policy."),
    (("TA0003", "TA0004"),
     "Persistence / privilege escalation: establish and continuously monitor a "
     "configuration baseline (services, scheduled tasks, autoruns) and restrict "
     "local-administrator rights."),
    (("TA0005",),
     "Defense evasion: forward all security and audit logs to a tamper-resistant "
     "SIEM and alert on log clearing and security-tool tampering."),
    (("TA0008",),
     "Lateral movement: segment the network, restrict RDP/SMB between "
     "workstations, and monitor for anomalous internal authentication."),
    (("TA0040",),
     "Impact: validate offline, tested backups and implement application "
     "allowlisting on critical systems."),
]


def is_available() -> bool:
    return _HAVE_REPORTLAB


def _c(hex_str):
    return colors.HexColor(hex_str)


def _esc(s) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("ct", parent=base["Title"], fontSize=26,
                                      textColor=_c(INK), leading=30, spaceAfter=6),
        "cover_sub": ParagraphStyle("cs", parent=base["Normal"], fontSize=12,
                                    textColor=_c(MUTE), leading=16),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=14,
                             textColor=_c(INK), spaceBefore=4, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=11,
                             textColor=_c(BRAND), spaceBefore=10, spaceAfter=3),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9.5,
                               leading=14, alignment=TA_JUSTIFY, textColor=_c(SLATE)),
        "body_l": ParagraphStyle("bl", parent=base["BodyText"], fontSize=9.5,
                                 leading=14, alignment=TA_LEFT, textColor=_c(SLATE)),
        "small": ParagraphStyle("sm", parent=base["BodyText"], fontSize=8.5,
                                leading=12, textColor=_c(SLATE)),
        "cell": ParagraphStyle("cell", parent=base["BodyText"], fontSize=8.5,
                               leading=11, textColor=_c(SLATE)),
        "cell_b": ParagraphStyle("cellb", parent=base["BodyText"], fontSize=8.5,
                                 leading=11, textColor=_c(INK)),
        "mono": ParagraphStyle("mono", parent=base["BodyText"], fontName="Courier",
                               fontSize=8, leading=11, textColor=_c(INK)),
        "th": ParagraphStyle("th", parent=base["BodyText"], fontSize=8.5,
                             leading=11, textColor=colors.white),
        "sectnum": ParagraphStyle("sn", parent=base["Heading1"], fontSize=14,
                                  textColor=_c(BRAND)),
    }


# ---- small builders ---------------------------------------------------------
def _kv_table(rows, S, label_w=1.5, val_w=4.4):
    data = [[Paragraph(f"<b>{_esc(k)}</b>", S["cell_b"]), Paragraph(_esc(v), S["cell"])]
            for k, v in rows]
    t = Table(data, colWidths=[label_w * inch, val_w * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _c("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, _c(LINE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, _c(LINE_SOFT)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _data_table(header, rows, col_w, S, zebra=True):
    data = [[Paragraph(f"<b>{_esc(h)}</b>", S["th"]) for h in header]]
    for r in rows:
        data.append([cell if hasattr(cell, "wrap") else Paragraph(_esc(cell), S["cell"])
                     for cell in r])
    t = LongTable(data, colWidths=[w * inch for w in col_w], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _c(INK)),
        ("BOX", (0, 0), (-1, -1), 0.5, _c(LINE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, _c(LINE_SOFT)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    if zebra:
        style.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _c("#f8fafc")]))
    t.setStyle(TableStyle(style))
    return t


def _section(num, title, S):
    return Paragraph(f'<font color="{BRAND}">{num}.</font>&nbsp;&nbsp;{_esc(title)}', S["h1"])


# ---- derived content --------------------------------------------------------
def _report_id(report: dict) -> str:
    aid = (report.get("analysis_id") or "00000000")[:8].upper()
    date = (report.get("generated_at") or "")[:10].replace("-", "")
    return f"SAI-{date}-{aid}" if date else f"SAI-{aid}"


def _avg_confidence(findings) -> int:
    sig = [f for f in findings if f.get("severity") in ("low", "medium", "high", "critical")]
    pool = sig or findings
    if not pool:
        return 0
    return int(round(sum(float(f.get("confidence", 0)) for f in pool) / len(pool) * 100))


def _present_tactics(report: dict) -> set:
    return {t.get("tactic_id") for t in report.get("mitre", [])}


def _recommendations(report: dict):
    seen, immediate = set(), []
    for f in report.get("findings", []):
        if f.get("severity") in ("medium", "high", "critical"):
            for r in f.get("remediation", []):
                if r not in seen:
                    seen.add(r)
                    immediate.append(r)
    if not immediate:
        immediate = ["Confirm whether the observed activity was authorized, then "
                     "archive the case if benign."]
    tactics = _present_tactics(report)
    strategic = [text for keys, text in _STRATEGIC if tactics.intersection(keys)]
    strategic.append("Conduct a post-incident review (NIST SP 800-61r3, Improve), "
                     "and update detection content and the IR runbook based on this case.")
    return immediate[:10], strategic


def _business_impact(severity: str) -> str:
    return {
        "critical": "Potential for significant operational disruption, data loss, or "
                    "unauthorized access to sensitive systems. Executive notification warranted.",
        "high": "Credible risk to confidentiality, integrity, or availability of affected "
                "assets if the activity is not contained promptly.",
        "medium": "Limited but real risk; could escalate if corroborated by further activity.",
        "low": "Minimal expected business impact; recorded for situational awareness.",
        "info": "No material business impact identified.",
    }.get(severity, "Impact to be determined by the responding analyst.")


# ---- page furniture (classification marking on every page) ------------------
def _decorate(report_id):
    def draw(canvas, doc):
        canvas.saveState()
        w, h = LETTER
        # Brand bar
        canvas.setFillColor(_c(INK))
        canvas.rect(0, h - 0.5 * inch, w, 0.5 * inch, fill=1, stroke=0)
        canvas.setFillColor(_c(BRAND))
        canvas.rect(0, h - 0.53 * inch, w, 0.03 * inch, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(0.6 * inch, h - 0.33 * inch, "SentinelAI v2  |  Incident Response Report")
        # TLP marking (top-right): amber on black chip
        canvas.setFillColor(colors.black)
        canvas.rect(w - 1.7 * inch, h - 0.43 * inch, 1.1 * inch, 0.22 * inch, fill=1, stroke=0)
        canvas.setFillColor(_c(TLP_AMBER))
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawCentredString(w - 1.15 * inch, h - 0.34 * inch, "TLP:AMBER")
        # Footer: classification + report id + page
        canvas.setStrokeColor(_c(LINE_SOFT))
        canvas.line(0.6 * inch, 0.52 * inch, w - 0.6 * inch, 0.52 * inch)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.setFillColor(_c("#92400e"))
        canvas.drawString(0.6 * inch, 0.38 * inch, "TLP:AMBER")
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(_c(MUTE))
        canvas.drawCentredString(w / 2, 0.38 * inch, f"{report_id}  —  Limited disclosure, recipient organization only")
        canvas.drawRightString(w - 0.6 * inch, 0.38 * inch, f"Page {doc.page}")
        canvas.restoreState()
    return draw


# ---- main -------------------------------------------------------------------
def build_report_pdf(report: dict) -> bytes:
    if not _HAVE_REPORTLAB:
        raise RuntimeError("reportlab is not installed")

    S = _styles()
    buf = io.BytesIO()
    rid = _report_id(report)
    findings = report.get("findings", [])
    summary = report.get("summary", {}) or {}
    sev = report.get("severity", "info")
    score = report.get("score", 0)
    module = (report.get("module") or "").upper()

    frame = Frame(0.6 * inch, 0.62 * inch, LETTER[0] - 1.2 * inch,
                  LETTER[1] - 1.3 * inch, id="main")
    doc = BaseDocTemplate(buf, pagesize=LETTER,
                          title=f"Incident Response Report — {report.get('source_file', '')}",
                          author="SentinelAI v2", topMargin=0.7 * inch)
    doc.addPageTemplates([PageTemplate(id="ir", frames=[frame], onPage=_decorate(rid))])

    story = []

    # ---------------- Cover page ----------------
    story.append(Spacer(1, 0.5 * inch))
    # TLP banner (single cell so the label never wraps)
    tlp = Table([[Paragraph(
        '<font color="#FFC000" size=13><b>TLP:AMBER</b></font>'
        '<font color="white" size=8>&nbsp;&nbsp;&nbsp;Limited disclosure. Recipients may share '
        'only within their organization and with clients on a need-to-know basis.</font>',
        S["body_l"])]], colWidths=[7.4 * inch])
    tlp.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.black),
                             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                             ("TOPPADDING", (0, 0), (-1, -1), 9),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                             ("LEFTPADDING", (0, 0), (-1, -1), 14)]))
    story.append(tlp)
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph("Security Incident Analysis Report", S["cover_title"]))
    story.append(HRFlowable(width="100%", thickness=2, color=_c(BRAND), spaceBefore=2, spaceAfter=10))
    story.append(Paragraph(f"Automated triage and analysis of artifact "
                           f"<b>{_esc(report.get('source_file', ''))}</b>", S["cover_sub"]))
    story.append(Spacer(1, 0.4 * inch))
    story.append(_score_band(report, S))
    story.append(Spacer(1, 0.4 * inch))
    cover_meta = [
        ("Report ID", rid),
        ("Classification", "TLP:AMBER"),
        ("Analysis type", f"{module} module (automated)"),
        ("Overall severity", f"{sev.upper()}  (risk score {score}/100)"),
        ("Analysis confidence", f"{_avg_confidence(findings)}%"),
        ("Date issued", (report.get("generated_at") or "").replace("T", " ")[:19] + " UTC"),
        ("Prepared by", f"SentinelAI v2 Automated Analysis Engine ({report.get('ai_provider', 'mock')})"),
        ("Status", "Closed — analysis complete"),
    ]
    story.append(_kv_table(cover_meta, S))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "<b>Confidentiality notice.</b> This report contains sensitive security "
        "information and is classified TLP:AMBER under the FIRST Traffic Light "
        "Protocol v2.0. Distribution is restricted to the recipient organization "
        "and its clients on a need-to-know basis. Do not release publicly.", S["small"]))
    story.append(PageBreak())

    # ---------------- Document control & distribution ----------------
    story.append(_section("1", "Document Control & Distribution", S))
    story.append(Paragraph("Version history", S["h2"]))
    story.append(_data_table(
        ["Version", "Date", "Author", "Description"],
        [["1.0", (report.get("generated_at") or "")[:10],
          "SentinelAI Engine", "Initial automated analysis and report generation."]],
        [0.9, 1.3, 1.9, 3.3], S))
    story.append(Paragraph("Distribution list", S["h2"]))
    story.append(_data_table(
        ["Recipient", "Role", "Handling"],
        [["SOC Operations", "Detection & triage", "TLP:AMBER"],
         ["Incident Response Team", "Investigation & containment", "TLP:AMBER"],
         ["CISO Office", "Risk oversight", "TLP:AMBER"]],
        [2.4, 3.0, 2.0], S))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Prepared by SentinelAI v2 (automated). Findings should be validated and "
        "this report reviewed and signed off by a qualified analyst before action.",
        S["small"]))
    story.append(Spacer(1, 10))
    signoff = Table([
        [Paragraph("<b>Prepared by</b>", S["cell_b"]), Paragraph("<b>Reviewed by</b>", S["cell_b"])],
        [Paragraph(f"SentinelAI v2 ({report.get('ai_provider', 'mock')} engine)", S["cell"]),
         Paragraph("________________________", S["cell"])],
        [Paragraph((report.get("generated_at") or "")[:10], S["cell"]),
         Paragraph("Analyst name / date", S["small"])],
    ], colWidths=[3.7 * inch, 3.7 * inch])
    signoff.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, _c(LINE)),
                                 ("INNERGRID", (0, 0), (-1, -1), 0.4, _c(LINE_SOFT)),
                                 ("TOPPADDING", (0, 0), (-1, -1), 6),
                                 ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story.append(signoff)
    story.append(PageBreak())

    # ---------------- Executive summary ----------------
    story.append(_section("2", "Executive Summary", S))
    story.append(Paragraph(_esc(report.get("narrative", "")) or
                           "No narrative was produced for this analysis.", S["body"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"This case was assessed at <b>{sev.upper()}</b> severity (risk score "
        f"{score}/100, analysis confidence {_avg_confidence(findings)}%). "
        f"{_business_impact(sev)}", S["body"]))
    dist = report.get("severity_distribution", {}) or {}
    sig_findings = [f for f in findings if f.get("severity") in ("high", "critical")]
    if sig_findings:
        story.append(Paragraph("Key findings", S["h2"]))
        kf = "".join(f"<br/>• <b>[{f['severity'].upper()}]</b> {_esc(f.get('title',''))}"
                     for f in sig_findings[:6])
        story.append(Paragraph(kf.lstrip("<br/>"), S["body_l"]))
    story.append(Paragraph("Findings by severity", S["h2"]))
    story.append(_data_table(
        ["Critical", "High", "Medium", "Low", "Info"],
        [[str(dist.get(k, 0)) for k in ("critical", "high", "medium", "low", "info")]],
        [1.48, 1.48, 1.48, 1.48, 1.48], S, zebra=False))
    story.append(PageBreak())

    # ---------------- Incident overview ----------------
    story.append(_section("3", "Incident Overview", S))
    stats = summary.get("stats", {})
    ov = [
        ("Report ID", rid),
        ("Artifact analyzed", report.get("source_file", "—")),
        ("Analysis module", module),
        ("Detection source", "SentinelAI automated pre-processing + AI analysis"),
        ("Analysis engine", f"{report.get('ai_provider', 'mock')}"
                            + (" (response cached)" if report.get("cached") else "")),
        ("Date / time (UTC)", (report.get("generated_at") or "").replace("T", " ")[:19]),
        ("Total findings", str(len(findings))),
        ("Overall severity", sev.upper()),
        ("Risk score", f"{score} / 100"),
        ("Current status", "Closed — pending analyst validation"),
    ]
    story.append(_kv_table(ov, S))

    # ---------------- Severity assessment ----------------
    story.append(_section("4", "Severity & Risk Assessment", S))
    story.append(Paragraph(
        "The risk score (0–100) is computed from the severity and confidence of "
        "all findings, with a corroboration weighting so that multiple related "
        "findings escalate the score above any single alert. It maps to the "
        "rating scale below.", S["body"]))
    story.append(Spacer(1, 4))
    rating_rows = []
    for name, lo, hi, desc in RATING_SCALE:
        marker = "►" if name.lower().startswith(sev[:4]) else ""
        rating_rows.append([f"{marker} {name}", f"{lo}–{hi}", desc])
    story.append(_data_table(["Rating", "Score", "Definition"], rating_rows,
                             [1.3, 0.9, 5.2], S))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"<b>Assessed rating: {sev.upper()} ({score}/100).</b> {_business_impact(sev)}",
        S["body"]))
    story.append(PageBreak())

    # ---------------- Timeline ----------------
    timeline = summary.get("timeline", [])
    story.append(_section("5", "Timeline of Events", S))
    if timeline:
        rows = [[(t.get("timestamp") or "").replace("T", " ")[:19],
                 t.get("event", ""), _esc(t.get("detail", ""))[:140]]
                for t in timeline[:40]]
        story.append(_data_table(["Timestamp (UTC)", "Event", "Detail"], rows,
                                 [1.5, 1.5, 4.4], S))
    else:
        story.append(Paragraph("No discrete timeline events were reconstructed.", S["small"]))

    # ---------------- Technical findings ----------------
    story.append(_section("6", "Technical Findings", S))
    if findings:
        for i, f in enumerate(findings, 1):
            story.append(_finding_block(i, f, S))
    else:
        story.append(Paragraph("No findings were produced.", S["small"]))

    # ---------------- MITRE ATT&CK ----------------
    matrix = report.get("mitre", [])
    if matrix:
        story.append(_section("7", "MITRE ATT&CK Mapping", S))
        rows = []
        for tac in matrix:
            techs = "<br/>".join(f'{_esc(t["id"])} — {_esc(t["name"])}'
                                 for t in tac.get("techniques", []))
            rows.append([f'{_esc(tac.get("tactic_name", ""))}',
                         _esc(tac.get("tactic_id", "")),
                         Paragraph(techs, S["cell"])])
        story.append(_data_table(["Tactic", "ID", "Techniques observed"], rows,
                                 [1.9, 0.9, 4.6], S))

    # ---------------- IOCs ----------------
    iocs = summary.get("iocs", {}) or {}
    enr = summary.get("enrichment", {}) or {}
    ioc_rows = _ioc_rows(iocs, enr)
    story.append(_section("8", "Indicators of Compromise (IOCs)", S))
    if ioc_rows:
        story.append(Paragraph("The following indicators were extracted and may be used "
                               "for blocking, hunting, and detection-content updates.", S["body"]))
        story.append(Spacer(1, 4))
        story.append(_data_table(["Indicator", "Type", "Context"], ioc_rows,
                                 [2.9, 1.0, 3.5], S))
    else:
        story.append(Paragraph("No indicators of compromise were extracted.", S["small"]))

    # ---------------- Containment / Eradication / Recovery ----------------
    story.append(_section("9", "Containment, Eradication & Recovery", S))
    story.append(Paragraph(
        "The investigation steps below follow the NIST SP 800-61r3 response "
        "lifecycle. Automated response actions taken by the platform (SOAR) are "
        "listed thereafter.", S["body"]))
    playbook = report.get("playbook", [])
    if playbook:
        story.append(Paragraph("Investigation playbook", S["h2"]))
        for s in playbook:
            blk = [Paragraph(f'<b>Step {s.get("step", "?")} — {_esc(s.get("title", ""))}</b> '
                             f'<font color="{MUTE}" size=8>[{_esc(s.get("phase", ""))}]</font>',
                             S["body_l"]),
                   Paragraph(_esc(s.get("instructions", "")), S["small"])]
            if s.get("expected_outcome"):
                blk.append(Paragraph(f'<i>Expected outcome: {_esc(s["expected_outcome"])}</i>',
                                     S["small"]))
            blk.append(Spacer(1, 4))
            story.append(KeepTogether(blk))
    soar = report.get("soar_actions", [])
    if soar:
        story.append(Paragraph("Automated response actions (SOAR)", S["h2"]))
        rows = [[_esc(a.get("action", "").replace("_", " ")), a.get("target", ""),
                 _esc(a.get("tier", "").replace("_", " ")), _esc(a.get("status", ""))]
                for a in soar]
        story.append(_data_table(["Action", "Target", "Tier", "Status"], rows,
                                 [1.9, 2.0, 1.3, 2.2], S))

    # ---------------- Recommendations ----------------
    immediate, strategic = _recommendations(report)
    story.append(_section("10", "Recommendations", S))
    story.append(Paragraph("Immediate (tactical)", S["h2"]))
    story.append(Paragraph("".join(f"• {_esc(r)}<br/>" for r in immediate), S["body_l"]))
    story.append(Paragraph("Strategic (control improvements)", S["h2"]))
    story.append(Paragraph("".join(f"• {_esc(r)}<br/>" for r in strategic), S["body_l"]))

    # ---------------- Conclusion ----------------
    story.append(_section("11", "Analyst Conclusion", S))
    story.append(Paragraph(_conclusion(report), S["body"]))

    # ---------------- Appendix ----------------
    story.append(_section("A", "Appendix — Methodology & Metadata", S))
    usage = report.get("usage", {}) or {}
    appendix = [
        ("Analysis pipeline", "Raw artifact → deterministic pre-processor → AI analysis → "
                              "scoring → MITRE mapping → playbook → SOAR"),
        ("Frameworks", "NIST SP 800-61r3 (CSF 2.0: Detect, Respond, Recover); MITRE ATT&CK; "
                       "FIRST TLP v2.0"),
        ("AI engine", report.get("ai_provider", "mock")),
        ("Tokens (in / out)", f"{usage.get('prompt_tokens', 0)} / {usage.get('completion_tokens', 0)}"),
        ("Estimated AI cost", f"${usage.get('cost_usd', 0):.4f}"),
        ("Packets / events analyzed", str(stats.get("packets") or stats.get("events") or "n/a")),
        ("Report generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
    ]
    story.append(_kv_table(appendix, S, label_w=1.8, val_w=4.1))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<i>This report was generated by SentinelAI v2, an automated triage and "
        "response platform. Automated findings should be validated by a qualified "
        "analyst before operational action is taken.</i>", S["small"]))

    doc.build(story)
    return buf.getvalue()


# ---- section helpers that need module-level reuse ---------------------------
def _score_band(report: dict, S: dict):
    sev = report.get("severity", "info")
    score = report.get("score", 0)
    col = _c(SEV_HEX.get(sev, SEV_HEX["info"]))
    cell = Table(
        [[Paragraph(f'<font size=30 color="white"><b>{score}</b></font>'
                    f'<font size=12 color="white">/100</font>', S["body_l"]),
          Paragraph(f'<font size=15 color="white"><b>{sev.upper()}</b></font><br/>'
                    f'<font size=8 color="white">OVERALL RISK RATING</font>', S["body_l"])]],
        colWidths=[1.7 * inch, 5.7 * inch])
    cell.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), col),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
    ]))
    return cell


def _finding_block(num: int, f: dict, S: dict):
    sev = f.get("severity", "info")
    col = SEV_HEX.get(sev, SEV_HEX["info"])
    conf = int(round(float(f.get("confidence", 0)) * 100))
    techs = ", ".join(f.get("mitre_techniques", []) or []) or "—"
    evidence = ", ".join(f.get("evidence", []) or []) or "—"
    parts = [
        Paragraph(f'<font color="{col}"><b>F-{num:03d}  [{sev.upper()}]</b></font>&nbsp;&nbsp;'
                  f'<b>{_esc(f.get("title", "Untitled"))}</b>', S["body_l"]),
        Paragraph(f'<font color="{MUTE}" size=8>Confidence {conf}%&nbsp;&nbsp;|&nbsp;&nbsp;'
                  f'MITRE: {_esc(techs)}&nbsp;&nbsp;|&nbsp;&nbsp;Evidence: {_esc(evidence)}</font>',
                  S["small"]),
        Spacer(1, 2),
        Paragraph(_esc(f.get("description", "")), S["body_l"]),
    ]
    rem = f.get("remediation", []) or []
    if rem:
        parts.append(Paragraph("<b>Recommended remediation:</b>", S["small"]))
        parts.append(Paragraph("".join(f"• {_esc(r)}<br/>" for r in rem), S["small"]))
    parts.append(Spacer(1, 8))
    block = Table([[parts]], colWidths=[7.4 * inch])
    block.setStyle(TableStyle([
        ("LINEBEFORE", (0, 0), (0, -1), 3, _c(col)),
        ("BACKGROUND", (0, 0), (-1, -1), _c("#fbfcfe")),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return KeepTogether(block)


def _ioc_rows(iocs: dict, enr: dict):
    from app.core import threatintel
    rep = (enr.get("ip_reputation") or {}) if isinstance(enr, dict) else {}
    geo = (enr.get("ip_geolocation") or {}) if isinstance(enr, dict) else {}
    rows = []
    for ip in (iocs.get("ips") or [])[:30]:
        ctx = []
        intel = threatintel.ip_label(ip)
        if intel:
            ctx.append(intel)
        conf = (rep.get(ip) or {}).get("abuse_confidence")
        if conf:
            ctx.append(f"AbuseIPDB {conf}%")
        g = geo.get(ip) or {}
        if g.get("country"):
            ctx.append(g["country"])
        rows.append([ip, "IPv4", ", ".join(ctx) or "External host"])
    for d in (iocs.get("domains") or [])[:25]:
        intel = threatintel.domain_label(d)
        rows.append([d, "Domain", intel or "Observed in traffic"])
    for u in (iocs.get("urls") or [])[:15]:
        rows.append([u[:80], "URL", "Observed HTTP request"])
    for h in (iocs.get("hashes") or [])[:15]:
        rows.append([h, "Hash", "File artifact"])
    for acct in (iocs.get("accounts") or [])[:15]:
        rows.append([acct, "Account", "Implicated in events"])
    return rows


def _conclusion(report: dict) -> str:
    sev = report.get("severity", "info")
    n = len(report.get("findings", []))
    high = sum(1 for f in report.get("findings", []) if f.get("severity") in ("high", "critical"))
    if sev in ("high", "critical"):
        verdict = ("the evidence supports an active or highly likely security incident "
                   "requiring prompt response.")
    elif sev == "medium":
        verdict = "the evidence is suspicious and warrants analyst validation before closure."
    else:
        verdict = "no significant threat was identified, though the indicators are recorded."
    return (f"Across {n} finding(s), including {high} of high or critical severity, "
            f"{verdict} The recommendations in Section 10 should be actioned according "
            f"to their priority, and this report retained for the case record under its "
            f"TLP:AMBER handling restriction.")
