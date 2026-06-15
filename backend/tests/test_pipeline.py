"""End-to-end and unit tests. All run offline with the mock AI provider."""
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import SAMPLES
from app.core.scoring import score_findings, level_for_score
from app.core.mitre import build_matrix, tactics_for_technique
from app.core import soar
from app.pipeline import orchestrator
from app.modules.network import parser as net_parser, preprocessor as net_pre
from app.modules.malware import parser as mal_parser, preprocessor as mal_pre
from app.modules.forensics import parser as for_parser, preprocessor as for_pre


@pytest.fixture(scope="session", autouse=True)
def ensure_samples():
    if not (SAMPLES / "beaconing.pcap").exists():
        subprocess.run([sys.executable, str(SAMPLES.parent / "generate_samples.py")], check=True)


# ---- core units --------------------------------------------------------------
def test_scoring_escalates_with_corroboration():
    one = [{"severity": "high", "confidence": 0.8}]
    many = [{"severity": "high", "confidence": 0.8}] * 4
    s1, _, _ = score_findings(one)
    s2, _, _ = score_findings(many)
    assert s2 > s1
    assert 0 <= s1 <= 100 and 0 <= s2 <= 100


def test_level_thresholds():
    assert level_for_score(90) == "critical"
    assert level_for_score(70) == "high"
    assert level_for_score(50) == "medium"
    assert level_for_score(0) == "info"


def test_mitre_mapping():
    assert "TA0011" in tactics_for_technique("T1071")
    matrix = build_matrix([{"title": "x", "mitre_techniques": ["T1071"], "mitre_tactics": []}])
    assert any(t["tactic_id"] == "TA0011" for t in matrix)


def test_soar_tiers():
    assert soar.tier_for_score(10) == soar.TIER_NOTIFY
    assert soar.tier_for_score(50) == soar.TIER_APPROVAL
    assert soar.tier_for_score(90) == soar.TIER_AUTO


# ---- network -----------------------------------------------------------------
def test_network_detects_beaconing_and_scan():
    packets = net_parser.parse_pcap(str(SAMPLES / "beaconing.pcap"))
    assert len(packets) > 0
    summary = net_pre.preprocess(packets, "beaconing.pcap")
    types = {o.type for o in summary.observations}
    assert "beaconing" in types
    assert "port_scan" in types
    assert summary.stats["packets"] == len(packets)


# ---- forensics ---------------------------------------------------------------
def test_forensics_detects_attack_story():
    events = for_parser.parse_log(str(SAMPLES / "compromise.xml"))
    assert len(events) > 0
    summary = for_pre.preprocess(events, "compromise.xml")
    types = {o.type for o in summary.observations}
    assert "brute_force_success" in types
    assert "privilege_escalation_chain" in types
    assert "log_clearing_coverup" in types


# ---- malware -----------------------------------------------------------------
def test_malware_static_analysis():
    artifacts = mal_parser.analyze_file(str(SAMPLES / "fake_malware.bin"))
    assert artifacts.pe  # recognized as PE
    assert artifacts.suspicious_apis  # found API strings
    summary = mal_pre.preprocess(artifacts, "fake_malware.bin")
    types = {o.type for o in summary.observations}
    assert "high_entropy_section" in types or "packed_file" in types
    assert "embedded_network_iocs" in types
    assert artifacts.sha256  # hashing works


# ---- full pipeline -----------------------------------------------------------
@pytest.mark.parametrize("fname,module", [
    ("beaconing.pcap", "network"),
    ("compromise.xml", "forensics"),
    ("fake_malware.bin", "malware"),
])
def test_full_pipeline(fname, module):
    report = orchestrator.run_analysis(str(SAMPLES / fname))
    assert report.module == module
    assert isinstance(report.score, int) and 0 <= report.score <= 100
    assert report.findings
    assert report.playbook
    assert report.soar_actions
    assert report.severity in ("info", "low", "medium", "high", "critical")
    # serializable for the API
    assert isinstance(report.to_dict(), dict)


def test_cross_module_correlation():
    reports = [orchestrator.run_analysis(str(SAMPLES / f))
               for f in ("beaconing.pcap", "compromise.xml")]
    result = orchestrator.correlate(reports)
    assert set(result["modules"]) == {"network", "forensics"}
    assert result["playbook"]
    assert 0 <= result["score"] <= 100


# ---- detection depth (round 2) ----------------------------------------------
def test_network_http_and_dns_tunneling():
    packets = net_parser.parse_pcap(str(SAMPLES / "beaconing.pcap"))
    assert any(p.http.get("host") for p in packets)  # HTTP request parsed
    summary = net_pre.preprocess(packets, "beaconing.pcap")
    types = {o.type for o in summary.observations}
    assert "dns_tunneling" in types
    assert "tooling_user_agent" in types or "suspicious_http" in types


def test_malware_rule_engine():
    artifacts = mal_parser.analyze_file(str(SAMPLES / "fake_malware.bin"))
    assert artifacts.rule_hits  # YARA-style rules fired
    summary = mal_pre.preprocess(artifacts, "fake_malware.bin")
    assert any(o.type == "rule_match" for o in summary.observations)


def test_forensics_extra_sequences():
    events = for_parser.parse_log(str(SAMPLES / "compromise.xml"))
    summary = for_pre.preprocess(events, "compromise.xml")
    types = {o.type for o in summary.observations}
    assert "lateral_movement" in types
    assert "persistence_stacking" in types
    assert "defense_evasion" in types


# ---- AI quality (round 2) ---------------------------------------------------
def test_ai_response_cache():
    from app.ai import analyzer
    from app.modules.malware import parser as mp, preprocessor as mpp
    art = mp.analyze_file(str(SAMPLES / "fake_malware.bin"))
    summary = mpp.preprocess(art, "fake_malware.bin")
    r1 = analyzer.analyze(summary)
    r2 = analyzer.analyze(summary)
    assert r1["cached"] is False
    assert r2["cached"] is True
    assert "usage" in r1


# ---- persistence (round 2) --------------------------------------------------
def test_sqlite_store(tmp_path, monkeypatch):
    from app.config import settings
    from app.core import store
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "t.db"))
    store.init_db()
    store.upsert({"id": "x1", "filename": "f", "module": "network", "status": "running"})
    assert store.get("x1")["status"] == "running"
    assert len(store.list_all()) == 1
    assert store.delete("x1") and store.get("x1") is None
