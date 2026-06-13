"""Round-3 tests: observation de-duplication, scoring/auth edges.

All run offline with the mock AI provider (set in conftest)."""
import pytest

from tests.conftest import SAMPLES
from app.config import settings
from app.core import auth
from app.core.scoring import score_findings
from app.modules.network import parser as net_parser, preprocessor as net_pre


# ---- network observation de-duplication -------------------------------------
def test_network_observations_are_deduped():
    """A beaconing host reconnects on a fresh source port each callback. After
    channel merging, detectors must fire once per destination — not once per
    reconnection — so there are no exact-duplicate observations."""
    summary = net_pre.preprocess(
        net_parser.parse_pcap(str(SAMPLES / "beaconing.pcap")), "beaconing.pcap")
    descriptions = [o.description for o in summary.observations]
    assert len(descriptions) == len(set(descriptions)), "duplicate observations leaked"
    # Repeated high-entropy reconnections collapse to a single channel finding.
    assert sum(o.type == "high_entropy_traffic" for o in summary.observations) <= 1
    # Repeated identical HTTP callbacks collapse to a single observation.
    assert sum(o.type == "tooling_user_agent" for o in summary.observations) <= 1


def test_merge_channels_collapses_reconnections():
    from app.modules.network.preprocessor import build_flows, merge_channels
    packets = net_parser.parse_pcap(str(SAMPLES / "beaconing.pcap"))
    flows = build_flows(packets)
    channels = merge_channels(flows)
    assert len(channels) <= len(flows)
    # Merged channels preserve total byte accounting.
    assert sum(c["bytes"] for c in channels.values()) == sum(f["bytes"] for f in flows.values())


def test_beaconing_reports_merged_connection_count():
    summary = net_pre.preprocess(
        net_parser.parse_pcap(str(SAMPLES / "beaconing.pcap")), "beaconing.pcap")
    beacons = [o for o in summary.observations if o.type == "beaconing"]
    assert beacons, "beaconing should still be detected after merging"
    # A beacon is either many short reconnections or one persistent keep-alive
    # connection — both are valid; the field must be present and positive.
    assert all(o.data.get("connections", 0) >= 1 for o in beacons)


# ---- scoring edges ----------------------------------------------------------
def test_scoring_empty_findings():
    score, level, dist = score_findings([])
    assert score == 0 and level == "info"
    assert sum(dist.values()) == 0


def test_scoring_caps_at_100():
    score, level, _ = score_findings([{"severity": "critical", "confidence": 1.0}] * 12)
    assert score == 100 and level == "critical"


# ---- auth edges -------------------------------------------------------------
def test_auth_rejects_dupes_and_bad_login(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "auth.db"))
    auth.init_auth()
    auth.register("analyst", "secret123")
    with pytest.raises(ValueError):
        auth.register("analyst", "other123")          # duplicate username
    with pytest.raises(ValueError):
        auth.register("ab", "secret123")              # username too short
    with pytest.raises(ValueError):
        auth.register("newuser", "123")               # password too short
    with pytest.raises(ValueError):
        auth.login("analyst", "wrongpass")            # bad password
    out = auth.login("analyst", "secret123")
    assert out["token"] and out["user"]["username"] == "analyst"


def test_session_token_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "sess.db"))
    auth.init_auth()
    auth.register("ana", "secret123")
    token = auth.login("ana", "secret123")["token"]
    assert auth.user_for_token(token)["username"] == "ana"
    auth.logout(token)
    assert auth.user_for_token(token) is None          # revoked on logout
    assert auth.user_for_token("not-a-real-token") is None
