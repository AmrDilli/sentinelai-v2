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

import asyncio
import json
import threading
import uuid
from pathlib import Path

from fastapi import (APIRouter, BackgroundTasks, HTTPException, UploadFile, File,
                     Form, Header, Body, Depends, WebSocket, WebSocketDisconnect)
from fastapi.responses import Response

from app.config import settings
from app.pipeline import orchestrator
from app.core import store, auth, report_pdf, threatintel
from app.core.schema import Report
from app.live import session as live

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

    # Allow-list the file type — reject anything not a supported artifact.
    if not orchestrator.is_allowed(file.filename):
        ext = Path(file.filename or "").suffix.lower() or "(none)"
        raise HTTPException(
            415, f"File type '{ext}' is not supported. Allowed: PCAP captures, "
                 "Windows event logs (.evtx/.xml/.jsonl), and common file types "
                 "for static analysis (.exe/.dll/.bin/.ps1/.doc/.pdf, …).")

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
        case_number = _next_case_number(user["id"], detected)
        store.upsert({
            "id": job_id, "user_id": user["id"], "filename": file.filename,
            "module": detected, "status": "running", "progress": 0, "stage": "Queued",
            "case_number": case_number,
        })
    background.add_task(_run_pipeline_job, job_id, str(dest), module or None)
    return {"id": job_id, "module": detected, "status": "running", "case_number": case_number}


# Bundled, inert demo artifacts so the app can be explored with zero setup.
# Each runs through the identical pipeline a real upload would.
DEMO_DIR = Path(__file__).resolve().parents[3] / "samples" / "demo"
DEMO_SAMPLES = [
    ("demo_c2_beacon.pcap", "network", "C2 beaconing capture"),
    ("demo_host_compromise.xml", "forensics", "Host compromise event log"),
    ("demo_ransomware.bin", "malware", "Ransomware binary"),
]


@router.post("/analyze/sample")
async def analyze_sample(background: BackgroundTasks, user: dict = Depends(current_user)):
    """Ingest the bundled demo artifacts so a first-time visitor sees a populated
    SOC console without having to upload anything. Same pipeline as /analyze."""
    created = []
    for fname, module, label in DEMO_SAMPLES:
        src = DEMO_DIR / fname
        if not src.exists():
            continue
        job_id = uuid.uuid4().hex[:12]
        dest = settings.UPLOAD_DIR / f"{job_id}_{fname}"
        dest.write_bytes(src.read_bytes())
        detected = module or orchestrator.detect_module(str(dest))
        with _LOCK:
            case_number = _next_case_number(user["id"], detected)
            store.upsert({
                "id": job_id, "user_id": user["id"], "filename": f"[SAMPLE] {label}",
                "module": detected, "status": "running", "progress": 0, "stage": "Queued",
                "case_number": case_number, "demo": True,
            })
        background.add_task(_run_pipeline_job, job_id, str(dest), module)
        created.append({"id": job_id, "module": detected, "case_number": case_number})
    if not created:
        raise HTTPException(500, "Demo samples are not available on the server.")
    return {"created": created, "count": len(created)}


def _next_case_number(user_id: str, module: str) -> str:
    """Human case id: <N|F|M><year>-<seq>, e.g. N2026-001. Sequence runs per
    user/module/year. Call inside _LOCK."""
    from datetime import datetime, timezone
    prefix = {"network": "N", "forensics": "F", "malware": "M"}.get(module, "X")
    year = datetime.now(timezone.utc).year
    stem = f"{prefix}{year}-"
    used = [str(a.get("case_number", "")) for a in store.list_all(user_id)]
    seq = sum(1 for c in used if c.startswith(stem)) + 1
    while f"{stem}{seq:03d}" in used:        # guard against gaps from deletes
        seq += 1
    return f"{stem}{seq:03d}"


def _serialize_analyses(user_id: str) -> list[dict]:
    """Shape store records into the list payload the dashboard consumes. Shared
    by the REST list endpoint and the WebSocket live-progress stream."""
    items = []
    for a in store.list_all(user_id):
        report = a.get("report", {})
        items.append({
            "id": a["id"], "filename": a.get("filename"), "module": a.get("module"),
            "case_number": a.get("case_number"),
            "status": a["status"], "progress": a.get("progress", 0), "stage": a.get("stage"),
            "score": report.get("score"), "severity": report.get("severity"),
            "generated_at": report.get("generated_at"), "error": a.get("error"),
            # Embed the full report for completed cases so the aggregate views
            # (Dashboard, Alerts, Trends, Reports) can render without an extra
            # round-trip per case. Running/failed cases carry no report yet.
            "report": report or None,
            # Per-finding triage state: {"<finding_index>": "acknowledged"|...}.
            "triage": a.get("triage", {}),
        })
    return items


TRIAGE_STATES = {"new", "acknowledged", "dismissed", "escalated"}


@router.post("/analyses/{analysis_id}/triage")
def set_triage(analysis_id: str, body: dict = Body(...), user: dict = Depends(current_user)):
    """Set a finding's triage state (new / acknowledged / dismissed / escalated).
    'new' clears any prior state. Lets analysts work the alert queue."""
    status = str(body.get("status", "new"))
    if status not in TRIAGE_STATES:
        raise HTTPException(400, f"status must be one of {sorted(TRIAGE_STATES)}")
    try:
        index = int(body.get("finding_index", -1))
    except (TypeError, ValueError):
        raise HTTPException(400, "finding_index must be an integer")
    with _LOCK:
        a = store.get(analysis_id, user["id"])
        if not a or "report" not in a:
            raise HTTPException(404, "Completed analysis not found")
        if not 0 <= index < len(a["report"].get("findings", [])):
            raise HTTPException(400, "finding_index out of range")
        triage = dict(a.get("triage") or {})
        if status == "new":
            triage.pop(str(index), None)
        else:
            triage[str(index)] = status
        a["triage"] = triage
        store.upsert(a)
    return {"ok": True, "triage": triage}


@router.get("/analyses")
def list_analyses(user: dict = Depends(current_user)):
    return {"analyses": _serialize_analyses(user["id"])}


@router.websocket("/ws/analyses")
async def ws_analyses(websocket: WebSocket, token: str = ""):
    """Live progress stream. The client connects with ?token=<session token>
    and receives a fresh {analyses: [...]} push whenever anything changes
    (status, progress %, a new case) — no polling required. Auth is via query
    param because browsers can't set headers on a WebSocket handshake."""
    user = auth.user_for_token(token)
    if not user:
        await websocket.close(code=1008)  # policy violation / unauthenticated
        return
    await websocket.accept()
    last_payload = None
    try:
        while True:
            # Run the sync SQLite read off the event loop.
            items = await asyncio.to_thread(_serialize_analyses, user["id"])
            payload = json.dumps(items, sort_keys=True)
            if payload != last_payload:
                last_payload = payload
                await websocket.send_json({"analyses": items})
            await asyncio.sleep(0.8)
    except WebSocketDisconnect:
        return
    except Exception:
        # Any send failure (client gone) ends the stream cleanly.
        return


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, user: dict = Depends(current_user)):
    a = store.get(analysis_id, user["id"])
    if not a:
        raise HTTPException(404, "Analysis not found")
    return a


@router.get("/analyses/{analysis_id}/report.pdf")
def report_pdf_download(analysis_id: str, user: dict = Depends(current_user)):
    """Server-rendered, branded incident-report PDF for a completed analysis."""
    a = store.get(analysis_id, user["id"])
    if not a or a.get("status") != "completed" or "report" not in a:
        raise HTTPException(404, "Completed analysis not found")
    if not report_pdf.is_available():
        raise HTTPException(501, "PDF generation unavailable (install reportlab)")
    report = a["report"]
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_"
                        for c in str(report.get("source_file", "report")))
    filename = f"sentinelai_{report.get('module', 'report')}_{safe_name}.pdf"
    return Response(
        content=report_pdf.build_report_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: str, user: dict = Depends(current_user)):
    if not store.delete(analysis_id, user["id"]):
        raise HTTPException(404, "Analysis not found")
    return {"ok": True}


@router.post("/analyses/{analysis_id}/explain")
def explain_finding(analysis_id: str, body: dict = Body(...),
                    user: dict = Depends(current_user)):
    """Expand one finding into an analyst-grade drill-down explanation."""
    from app.ai.explain import explain_finding as _explain
    a = store.get(analysis_id, user["id"])
    if not a or a.get("status") != "completed" or "report" not in a:
        raise HTTPException(404, "Completed analysis not found")
    try:
        index = int(body.get("finding_index", -1))
    except (TypeError, ValueError):
        raise HTTPException(400, "finding_index must be an integer")
    try:
        return _explain(a["report"], index)
    except IndexError:
        raise HTTPException(400, "finding_index out of range")


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
        "pdf_reports": report_pdf.is_available(),
        "threat_intel": threatintel.stats(),
        "enrichment": {
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        },
    }


def _settings_status() -> dict:
    from app.ai.provider import get_provider
    return {
        "ai_provider": settings.AI_PROVIDER,        # what the user selected
        "active_provider": get_provider().name,     # what's actually in use (mock if no key)
        "self_verify": settings.AI_SELF_VERIFY,
        "cache": settings.AI_CACHE,
        "keys": {                                   # only whether set — never the values
            "deepseek": bool(settings.DEEPSEEK_API_KEY),
            "anthropic": bool(settings.ANTHROPIC_API_KEY),
            "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        },
    }


@router.get("/settings")
def get_settings(user: dict = Depends(current_user)):
    return _settings_status()


@router.post("/settings/keys")
def update_settings(body: dict = Body(...), user: dict = Depends(current_user)):
    """Set AI provider / API keys live from the Settings UI (persisted, no
    restart needed). Only fields present in the body are changed."""
    field_to_attr = {
        "ai_provider": "AI_PROVIDER", "deepseek_api_key": "DEEPSEEK_API_KEY",
        "anthropic_api_key": "ANTHROPIC_API_KEY", "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
        "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    }
    updates = {}
    for field, attr in field_to_attr.items():
        if field in body and body[field] is not None:
            val = str(body[field]).strip()
            if field == "ai_provider" and val not in ("mock", "deepseek", "claude"):
                raise HTTPException(400, "ai_provider must be mock, deepseek, or claude")
            updates[attr] = val
    # Boolean toggles
    for field, attr in {"self_verify": "AI_SELF_VERIFY", "cache": "AI_CACHE"}.items():
        if field in body and body[field] is not None:
            updates[attr] = bool(body[field])
    settings.update_keys(updates)
    return _settings_status()


@router.post("/threatintel/refresh")
def threatintel_refresh(user: dict = Depends(current_user)):
    """Pull a fresh indicator set from abuse.ch and merge it over the bundled
    snapshot. Best-effort: returns ok=False (not an HTTP error) if offline."""
    return threatintel.refresh_from_feeds()


# ------------------------------------------------------------- live capture ---
@router.get("/live/scenarios")
def live_scenarios(user: dict = Depends(current_user)):
    return {"scenarios": live.list_scenarios()}


@router.post("/live/start")
def live_start(body: dict = Body(...), user: dict = Depends(current_user)):
    try:
        sess = live.start_session(user["id"], body.get("scenario", ""))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return sess.snapshot()


@router.post("/live/stop/{session_id}")
def live_stop(session_id: str, user: dict = Depends(current_user)):
    return {"stopped": live.stop_session(session_id)}


@router.websocket("/ws/live/{session_id}")
async def ws_live(websocket: WebSocket, session_id: str, token: str = ""):
    """Stream a live-capture session's state. Pushes the rolling tick snapshot
    (~2x/sec) until the replay finishes or the client disconnects."""
    user = auth.user_for_token(token)
    if not user:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    last = None
    try:
        while True:
            sess = live.get_session(session_id)
            if not sess:
                await websocket.send_json({"error": "session not found"})
                return
            state = sess.snapshot()
            payload = json.dumps(state, sort_keys=True)
            if payload != last:
                last = payload
                await websocket.send_json(state)
            if state["status"] in ("finished", "stopped"):
                return
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
    except Exception:
        return
