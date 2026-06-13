"""REST API (with per-user accounts).

Auth:
  POST /api/auth/register   — create an account
  POST /api/auth/login      — get a session token
  POST /api/auth/logout     — revoke the current token
  GET  /api/auth/me         — current user

Analyses (all scoped to the authenticated user via Authorization: Bearer <token>):
  POST   /api/analyze
  GET    /api/analyses
  GET    /api/analyses/{id}
  DELETE /api/analyses/{id}
  POST   /api/correlate
  POST   /api/soar/{id}/approve
  GET    /api/health
"""
from __future__ import annotations

import threading
import uuid
from pathlib import Path

from fastapi import (APIRouter, BackgroundTasks, HTTPException, UploadFile, File,
                     Form, Header, Body, Depends)

from app.config import settings
from app.pipeline import orchestrator
from app.core import store, auth
from app.core.schema import Report

router = APIRouter()
_LOCK = threading.Lock()


# --------------------------------------------------------------------- auth ---
def current_user(authorization: str | None = Header(default=None)) -> dict:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    user = auth.user_for_token(token)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


@router.post("/auth/register")
def register(body: dict = Body(...)):
    try:
        auth.register(body.get("username", ""), body.get("password", ""))
        return auth.login(body.get("username", ""), body.get("password", ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/auth/login")
def login(body: dict = Body(...)):
    try:
        return auth.login(body.get("username", ""), body.get("password", ""))
    except ValueError as exc:
        raise HTTPException(401, str(exc))


@router.post("/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.lower().startswith("bearer "):
        auth.logout(authorization[7:])
    return {"ok": True}


@router.get("/auth/me")
def me(user: dict = Depends(current_user)):
    return user


# --------------------------------------------------------------- pipeline jobs ---
def _set_progress(job_id: str, pct: int, stage: str):
    with _LOCK:
        rec = store.get(job_id)
        if rec:
            rec["progress"] = pct
            rec["stage"] = stage
            store.upsert(rec)


def _run_pipeline_job(job_id: str, file_path: str, module: str | None):
    def cb(pct, stage):
        _set_progress(job_id, pct, stage)

    result = orchestrator.safe_run(file_path, module, progress_cb=cb, analysis_id=job_id)
    with _LOCK:
        rec = store.get(job_id) or {"id": job_id}
        rec.update(result)
        store.upsert(rec)
    Path(file_path).unlink(missing_ok=True)


@router.post("/analyze")
async def analyze(background: BackgroundTasks,
                  file: UploadFile = File(...),
                  module: str | None = Form(default=None),
                  user: dict = Depends(current_user)):
    if module not in (None, "", "network", "forensics", "malware"):
        raise HTTPException(400, "module must be network, forensics, or malware")

    job_id = uuid.uuid4().hex[:12]
    dest = settings.UPLOAD_DIR / f"{job_id}_{Path(file.filename or 'upload').name}"
    size = 0
    with dest.open("wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.MAX_UPLOAD_MB * 1024 * 1024:
                out.close(); dest.unlink(missing_ok=True)
                raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_MB} MB limit")
            out.write(chunk)
    if size == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "Uploaded file is empty")

    detected = module or orchestrator.detect_module(str(dest))
    with _LOCK:
        store.upsert({
            "id": job_id, "user_id": user["id"], "filename": file.filename,
            "module": detected, "status": "running", "progress": 0, "stage": "Queued",
        })
    background.add_task(_run_pipeline_job, job_id, str(dest), module or None)
    return {"id": job_id, "module": detected, "status": "running"}


@router.get("/analyses")
def list_analyses(user: dict = Depends(current_user)):
    items = []
    for a in store.list_all(user["id"]):
        report = a.get("report", {})
        items.append({
            "id": a["id"], "filename": a.get("filename"), "module": a.get("module"),
            "status": a["status"], "progress": a.get("progress", 0), "stage": a.get("stage"),
            "score": report.get("score"), "severity": report.get("severity"),
            "generated_at": report.get("generated_at"), "error": a.get("error"),
            # Embed the full report for completed cases so the aggregate views
            # (Dashboard, Alerts, Trends, Reports) can render without an extra
            # round-trip per case. Running/failed cases carry no report yet.
            "report": report or None,
        })
    return {"analyses": items}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, user: dict = Depends(current_user)):
    a = store.get(analysis_id, user["id"])
    if not a:
        raise HTTPException(404, "Analysis not found")
    return a


@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: str, user: dict = Depends(current_user)):
    if not store.delete(analysis_id, user["id"]):
        raise HTTPException(404, "Analysis not found")
    return {"ok": True}


@router.post("/correlate")
def correlate(ids: list[str] = Body(...), user: dict = Depends(current_user)):
    reports = []
    for analysis_id in ids:
        a = store.get(analysis_id, user["id"])
        if not a or a.get("status") != "completed":
            raise HTTPException(400, f"Analysis {analysis_id} not found or incomplete")
        reports.append(Report(**a["report"]))
    if len(reports) < 2:
        raise HTTPException(400, "Correlation needs at least 2 completed analyses")
    return orchestrator.correlate(reports)


@router.post("/soar/{analysis_id}/approve")
def approve_action(analysis_id: str, action_index: int, user: dict = Depends(current_user)):
    with _LOCK:
        a = store.get(analysis_id, user["id"])
        if not a or "report" not in a:
            raise HTTPException(404, "Analysis not found")
        actions = a["report"].get("soar_actions", [])
        if not 0 <= action_index < len(actions):
            raise HTTPException(400, "Invalid action index")
        action = actions[action_index]
        if action["status"] != "pending approval":
            raise HTTPException(400, f"Action is '{action['status']}', not pending")
        action["status"] = "executed (simulated, analyst-approved)"
        store.upsert(a)
    return {"ok": True, "action": action}


@router.get("/health")
def health():
    from app.ai.provider import get_provider
    return {
        "status": "ok",
        "ai_provider": get_provider().name,
        "self_verify": settings.AI_SELF_VERIFY,
        "cache": settings.AI_CACHE,
        "enrichment": {
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        },
    }
