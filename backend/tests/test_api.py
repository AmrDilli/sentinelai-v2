"""API-layer tests via FastAPI's TestClient — auth gating, the upload→report
flow, and the list endpoint that powers the aggregate dashboards.

All run offline with the mock AI provider (set in conftest)."""
import pytest

from app.config import settings
from app.core import store, auth


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Isolate each test's database; _conn() reads settings.DB_PATH lazily.
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "api.db"))
    from fastapi.testclient import TestClient
    from app.main import app
    store.init_db()
    auth.init_auth()
    with TestClient(app) as c:
        yield c


def _register(client, username="analyst", password="secret123"):
    r = client.post("/api/auth/register", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    body = r.json()
    return body["token"], body["user"]


def test_health_reports_provider(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ai_provider"] == "mock"


def test_endpoints_require_auth(client):
    assert client.get("/api/analyses").status_code == 401
    assert client.get("/api/analyses/whatever").status_code == 401


def test_register_login_me_flow(client):
    token, user = _register(client)
    headers = {"Authorization": f"Bearer {token}"}
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == "analyst"
    # Login returns a working token too.
    again = client.post("/api/auth/login", json={"username": "analyst", "password": "secret123"})
    assert again.status_code == 200 and again.json()["token"]


def test_list_embeds_full_report_for_completed(client):
    """Regression guard: the aggregate views (Dashboard, Alerts, Trends,
    Reports) read `a.report` straight off the list response. The list endpoint
    must embed the full report for completed cases, not just score/severity."""
    token, user = _register(client)
    headers = {"Authorization": f"Bearer {token}"}

    # Seed a completed analysis directly in the store for this user.
    store.upsert({
        "id": "case1", "user_id": user["id"], "filename": "demo.pcap",
        "module": "network", "status": "completed", "progress": 100,
        "report": {
            "score": 82, "severity": "high", "generated_at": "2026-06-14T10:00:00+00:00",
            "findings": [{"title": "Beaconing", "severity": "high"}],
            "severity_distribution": {"info": 0, "low": 0, "medium": 0, "high": 1, "critical": 0},
        },
    })

    r = client.get("/api/analyses", headers=headers)
    assert r.status_code == 200
    items = r.json()["analyses"]
    assert len(items) == 1
    item = items[0]
    assert item["score"] == 82 and item["severity"] == "high"
    assert item["report"] is not None, "full report must be embedded in the list"
    assert item["report"]["findings"][0]["title"] == "Beaconing"


def test_analyses_are_scoped_per_user(client):
    t1, u1 = _register(client, "alice", "secret123")
    t2, u2 = _register(client, "bob", "secret123")
    store.upsert({"id": "a1", "user_id": u1["id"], "filename": "f", "module": "network",
                  "status": "running"})
    r = client.get("/api/analyses", headers={"Authorization": f"Bearer {t2}"})
    assert r.status_code == 200
    assert r.json()["analyses"] == []          # bob cannot see alice's case
    r = client.get("/api/analyses", headers={"Authorization": f"Bearer {t1}"})
    assert len(r.json()["analyses"]) == 1


def test_correlation_requires_two_completed(client):
    token, user = _register(client)
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/correlate", json=["nope"], headers=headers)
    assert r.status_code == 400


def test_upload_runs_pipeline_end_to_end(client):
    from tests.conftest import SAMPLES
    token, user = _register(client)
    headers = {"Authorization": f"Bearer {token}"}
    with open(SAMPLES / "beaconing.pcap", "rb") as fh:
        r = client.post("/api/analyze", headers=headers,
                        files={"file": ("beaconing.pcap", fh, "application/octet-stream")})
    assert r.status_code == 200
    job_id = r.json()["id"]
    # Background task runs synchronously under TestClient; fetch the report.
    rep = client.get(f"/api/analyses/{job_id}", headers=headers)
    assert rep.status_code == 200
    assert rep.json()["status"] in ("completed", "running")
