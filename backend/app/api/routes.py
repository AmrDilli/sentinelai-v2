"""REST API.

POST /api/analyze            — upload a file, analysis runs in the background
GET  /api/analyses           — list all analyses (id, status, severity, score)
GET  /api/analyses/{id}      — full report for one analysis
POST /api/correlate          — unified cross-module playbook over several analyses
POST /api/soar/{id}/approve  — analyst approves a pending SOAR action
GET  /api/health             — provider/key status
"""
from __future__ import annotations

import shutil
import threading
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, File, Form

from app.config import settings
from app.pipeline import orchestrator
from app.core.schema import Report

router = APIRouter()

# In-memory store (a bootcamp-appropriate simplification; swap for SQLite/Postgres
# by replacing these two dicts with a small repository class).
ANALYSES: dict[str, dict] = {}
_LOCK = threading.Lock()


def _run_pipeline_job(job_id: str, file_path: str, module: str | None):
    result = orchestrator.safe_run(file_path, module)
    with _LOCK:
        ANALYSES[job_id].update(result)


@router.post("/analyze")
async def analyze(background: BackgroundTasks,
                  file: UploadFile = File(...),
                  module: str | None = Form(default=None)):
    """Upload a PCAP / EVTX / XML / JSONL log / suspicious file."""
    if module not in (None, "", "network", "forensics", "malware"):
        raise HTTPException(400, "module must be network, forensics, or malware")

    job_id = uuid.uuid4().hex[:12]
    dest = settings.UPLOAD_DIR / f"{job_id}_{Path(file.filename or 'upload').name}"
    size = 0
    with dest.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.MAX_UPLOAD_MB * 1024 * 1024:
                out.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_MB} MB limit")
            out.write(chunk)

    detected = module or orchestrator.detect_module(str(dest))
    with _LOCK:
        ANALYSES[job_id] = {
            "id": job_id, "filename": file.filename, "module": detected,
            "status": "running",
        }
    background.add_task(_run_pipeline_job, job_id, str(dest), module or None)
    return {"id": job_id, "module": detected, "status": "running"}


@router.get("/analyses")
def list_analyses():
    with _LOCK:
        items = []
        for a in ANALYSES.values():
            report = a.get("report", {})
            items.append({
                "id": a["id"], "filename": a.get("filename"),
                "module": a.get("module"), "status": a["status"],
                "score": report.get("score"), "severity": report.get("severity"),
                "generated_at": report.get("generated_at"),
                "error": a.get("error"),
            })
    return {"analyses": items}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str):
    with _LOCK:
        a = ANALYSES.get(analysis_id)
    if not a:
        raise HTTPException(404, "Analysis not found")
    return a


@router.post("/correlate")
def correlate(ids: list[str]):
    """Body: JSON array of analysis ids. Returns unified cross-module view."""
    reports = []
    with _LOCK:
        for analysis_id in ids:
            a = ANALYSES.get(analysis_id)
            if not a or a.get("status") != "completed":
                raise HTTPException(400, f"Analysis {analysis_id} not found or incomplete")
            r = a["report"]
            reports.append(Report(**r))
    if len(reports) < 2:
        raise HTTPException(400, "Correlation needs at least 2 completed analyses")
    return orchestrator.correlate(reports)


@router.post("/soar/{analysis_id}/approve")
def approve_action(analysis_id: str, action_index: int):
    """Analyst approves one pending SOAR action (medium tier)."""
    with _LOCK:
        a = ANALYSES.get(analysis_id)
        if not a or "report" not in a:
            raise HTTPException(404, "Analysis not found")
        actions = a["report"].get("soar_actions", [])
        if not 0 <= action_index < len(actions):
            raise HTTPException(400, "Invalid action index")
        action = actions[action_index]
        if action["status"] != "pending approval":
            raise HTTPException(400, f"Action is '{action['status']}', not pending")
        action["status"] = "executed (simulated, analyst-approved)"
    return {"ok": True, "action": action}


@router.get("/health")
def health():
    from app.ai.provider import get_provider
    return {
        "status": "ok",
        "ai_provider": get_provider().name,
        "enrichment": {
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        },
    }
