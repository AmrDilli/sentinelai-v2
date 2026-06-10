"""The pipeline orchestrator — wires every stage together.

    Raw File -> Parser -> Pre-processor -> Enrichment -> AI Analysis
             -> Scoring -> Playbook -> SOAR -> Report

Each stage consumes the previous stage's defined output, so stages can be
developed, tested, and swapped independently. `run_analysis` is synchronous
on purpose: the API layer decides whether to run it in a background task
(file-upload mode today, an incremental scheduler in live mode later).
"""
from __future__ import annotations

import traceback
import uuid
from pathlib import Path

from app.core.schema import Summary, Report
from app.core.scoring import score_findings
from app.core.mitre import build_matrix
from app.core import soar
from app.ai.analyzer import analyze
from app.ai.playbook import generate_playbook

PCAP_EXTS = {".pcap", ".cap", ".pcapng"}
LOG_EXTS = {".evtx", ".xml", ".jsonl", ".json"}


def detect_module(path: str) -> str:
    """Route a file to the right module by extension (malware is the fallback —
    any unknown binary is treated as a suspicious file)."""
    suffix = Path(path).suffix.lower()
    if suffix in PCAP_EXTS:
        return "network"
    if suffix in LOG_EXTS:
        return "forensics"
    return "malware"


def build_summary(path: str, module: str, enable_enrichment: bool = True) -> Summary:
    """Stages 1+2 (+enrichment): raw file -> standard Summary."""
    name = Path(path).name
    if module == "network":
        from app.modules.network import parser, preprocessor, enrich
        packets = parser.parse_pcap(path)
        summary = preprocessor.preprocess(packets, name)
        if enable_enrichment:
            summary = enrich.enrich(summary)
    elif module == "forensics":
        from app.modules.forensics import parser, preprocessor
        events = parser.parse_log(path)
        summary = preprocessor.preprocess(events, name)
    elif module == "malware":
        from app.modules.malware import parser, preprocessor, enrich
        artifacts = parser.analyze_file(path)
        summary = preprocessor.preprocess(artifacts, name)
        if enable_enrichment:
            summary = enrich.enrich(summary)
    else:
        raise ValueError(f"Unknown module: {module}")
    return summary


def run_analysis(path: str, module: str | None = None,
                 enable_enrichment: bool = True) -> Report:
    """Full pipeline for one file."""
    module = module or detect_module(path)
    analysis_id = uuid.uuid4().hex[:12]

    # Stages 1-2: parse + pre-process (+ threat intel)
    summary = build_summary(path, module, enable_enrichment)

    # Stage 3: AI reads the SUMMARY, never the raw file
    ai_result = analyze(summary)
    findings = ai_result["findings"]

    # Stage 4: scoring
    score, severity, distribution = score_findings(findings)

    # Stage 5: playbook (single-module here; /correlate does cross-module)
    playbook = generate_playbook([{
        "module": module, "findings": findings, "narrative": ai_result["narrative"],
    }])

    # Stage 6: tiered response actions
    actions = soar.generate_actions(findings, summary.to_dict()["iocs"], score)

    return Report(
        analysis_id=analysis_id,
        module=module,
        source_file=summary.source_file,
        summary=summary.to_dict(),
        findings=findings,
        narrative=ai_result["narrative"],
        score=score,
        severity=severity,
        severity_distribution=distribution,
        mitre=build_matrix(findings),
        playbook=playbook,
        soar_actions=actions,
        ai_provider=ai_result["ai_provider"],
    )


def correlate(reports: list[Report]) -> dict:
    """Cross-module correlation: one unified playbook + combined score across
    multiple completed analyses (e.g. PCAP beaconing + EVTX account creation)."""
    all_findings = [f for r in reports for f in r.findings]
    score, severity, distribution = score_findings(all_findings)
    playbook = generate_playbook([
        {"module": r.module, "findings": r.findings, "narrative": r.narrative}
        for r in reports
    ])
    combined_iocs: dict[str, list] = {"ips": [], "domains": [], "urls": [],
                                      "hashes": [], "accounts": []}
    for r in reports:
        for key in combined_iocs:
            for v in r.summary.get("iocs", {}).get(key, []):
                if v not in combined_iocs[key]:
                    combined_iocs[key].append(v)
    return {
        "modules": [r.module for r in reports],
        "source_files": [r.source_file for r in reports],
        "score": score,
        "severity": severity,
        "severity_distribution": distribution,
        "mitre": build_matrix(all_findings),
        "playbook": playbook,
        "soar_actions": soar.generate_actions(all_findings, combined_iocs, score),
        "narratives": {r.module: r.narrative for r in reports},
    }


def safe_run(path: str, module: str | None = None) -> dict:
    """Wrapper that converts failures into an error report dict (API-friendly)."""
    try:
        return {"status": "completed", "report": run_analysis(path, module).to_dict()}
    except Exception as exc:
        return {"status": "failed", "error": str(exc),
                "traceback": traceback.format_exc(limit=3)}
