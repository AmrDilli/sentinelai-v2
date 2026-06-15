"""Tests for the four post-polish features: PDF reports, threat-intel feed,
WebSocket progress stream, and the Explain-finding drill-down.

All offline / mock provider (set in conftest)."""
import pytest

from app.config import settings
from app.core import store, auth
from tests.conftest import SAMPLES


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "feat.db"))
    from fastapi.testclient import TestClient
    from app.main import app
    store.init_db()
    auth.init_auth()
    with TestClient(app) as c:
        yield c


def _auth(client):
    r = client.post("/api/auth/register", json={"username": "analyst", "password": "secret123"})
    return r.json()["token"], r.json()["user"]


def _seed_completed(user_id):
    from app.pipeline import orchestrator
    report = orchestrator.run_analysis(str(SAMPLES / "beaconing.pcap")).to_dict()
    store.upsert({"id": "case1", "user_id": user_id, "filename": "beaconing.pcap",
                  "module": "network", "status": "completed", "progress": 100,
                  "report": report})
    return report


# ---- Feature 1: PDF report --------------------------------------------------
def test_pdf_generation_unit():
    from app.core import report_pdf
    from app.pipeline import orchestrator
    if not report_pdf.is_available():
        pytest.skip("reportlab not installed")
    report = orchestrator.run_analysis(str(SAMPLES / "beaconing.pcap")).to_dict()
    pdf = report_pdf.build_report_pdf(report)
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 8000  # full multi-section report, not a stub
    # Verify the formal structure when a PDF text extractor is available.
    try:
        import io
        import pypdf
    except Exception:
        return
    reader = pypdf.PdfReader(io.BytesIO(pdf))
    assert len(reader.pages) >= 6
    cover = reader.pages[0].extract_text()
    assert "TLP:AMBER" in cover                       # classification marking
    assert "Security Incident Analysis Report" in cover
    all_text = " ".join(p.extract_text() for p in reader.pages)
    for section in ("Executive Summary", "Indicators of Compromise",
                    "MITRE ATT&CK", "Recommendations"):
        assert section in all_text, f"missing section: {section}"


def test_pdf_endpoint(client):
    from app.core import report_pdf
    token, user = _auth(client)
    _seed_completed(user["id"])
    r = client.get("/api/analyses/case1/report.pdf",
                   headers={"Authorization": f"Bearer {token}"})
    if not report_pdf.is_available():
        assert r.status_code == 501
        return
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"


def test_pdf_endpoint_requires_completed(client):
    token, user = _auth(client)
    store.upsert({"id": "running1", "user_id": user["id"], "filename": "x",
                  "module": "network", "status": "running"})
    r = client.get("/api/analyses/running1/report.pdf",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404


# ---- Feature 3: WebSocket live progress -------------------------------------
def test_ws_streams_analyses(client):
    token, user = _auth(client)
    _seed_completed(user["id"])
    with client.websocket_connect(f"/api/ws/analyses?token={token}") as ws:
        data = ws.receive_json()
        assert "analyses" in data
        assert any(a["id"] == "case1" for a in data["analyses"])


def test_ws_rejects_bad_token(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/api/ws/analyses?token=not-valid") as ws:
            ws.receive_json()


# ---- Feature 4: Explain drill-down ------------------------------------------
def test_explain_endpoint(client):
    token, user = _auth(client)
    _seed_completed(user["id"])
    r = client.post("/api/analyses/case1/explain", json={"finding_index": 0},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body.get("explanation"), str) and body["explanation"]
    assert body.get("finding_title")


def test_triage_set_and_clear(client):
    token, user = _auth(client)
    _seed_completed(user["id"])
    h = {"Authorization": f"Bearer {token}"}
    # set escalated on finding 0
    r = client.post("/api/analyses/case1/triage", json={"finding_index": 0, "status": "escalated"}, headers=h)
    assert r.status_code == 200 and r.json()["triage"] == {"0": "escalated"}
    # it shows up in the list payload
    items = client.get("/api/analyses", headers=h).json()["analyses"]
    assert items[0]["triage"] == {"0": "escalated"}
    # 'new' clears it
    r = client.post("/api/analyses/case1/triage", json={"finding_index": 0, "status": "new"}, headers=h)
    assert r.json()["triage"] == {}
    # bad status / index rejected
    assert client.post("/api/analyses/case1/triage", json={"finding_index": 0, "status": "bogus"}, headers=h).status_code == 400
    assert client.post("/api/analyses/case1/triage", json={"finding_index": 99, "status": "acknowledged"}, headers=h).status_code == 400


def test_explain_bad_index(client):
    token, user = _auth(client)
    _seed_completed(user["id"])
    r = client.post("/api/analyses/case1/explain", json={"finding_index": 999},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 400
