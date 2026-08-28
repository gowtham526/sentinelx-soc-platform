"""
Tests for core/soar_engine.py and core/response_actions.py.

Run from the project root:  pytest tests/ -v

These specifically cover the gaps found while reviewing and wiring in the
SOAR engine this round: run_playbooks() actually being called from the
pipeline, isolate_host/restore_host cleaning up exactly the rules they
created (not leaking them), and create_case() folding into an existing
case instead of creating duplicates on repeated playbook fires.
"""

import os
import sys
import json
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core import soar_engine as soar
from core import response_actions as ra
from core import alert_pipeline as ap
from core import anomaly_baseline as ab
from core import evidence_snapshot as es


@pytest.fixture
def tmp_soar_files():
    """Redirect all SOAR + case/alert file paths to a temp dir for the
    duration of a test, then restore the originals — keeps tests from
    touching real project data.

    Also redirects anomaly_baseline / evidence_snapshot: process_alert()
    calls both unconditionally now (Stage 3b / Stage 4c), and SOAR tests
    go through the real process_alert(), so without this every SOAR test
    run was leaking entries into the real data/behavior_baseline.json and
    writing real files under data/evidence_snapshots/ — caught the same
    way test-data pollution has been caught and cleaned every other time
    it's turned up in this project."""
    tmpdir = tempfile.mkdtemp()
    originals = {
        "PLAYBOOK_FILE": soar.PLAYBOOK_FILE, "RUNS_FILE": soar.RUNS_FILE,
        "APPROVALS_FILE": soar.APPROVALS_FILE,
    }
    ap_originals = {
        "ALERT_FILE": ap.ALERT_FILE, "CASE_FILE": ap.CASE_FILE,
        "INCIDENT_FILE": ap.INCIDENT_FILE, "TIMELINE_FILE": ap.TIMELINE_FILE,
    }
    detection_originals = {
        "ab_file": ab.BASELINE_FILE,
        "es_dir":  es.SNAPSHOT_DIR,
    }
    soar.PLAYBOOK_FILE  = os.path.join(tmpdir, "playbooks.json")
    soar.RUNS_FILE      = os.path.join(tmpdir, "playbook_runs.json")
    soar.APPROVALS_FILE = os.path.join(tmpdir, "pending_approvals.json")
    ap.ALERT_FILE    = os.path.join(tmpdir, "alerts.json")
    ap.CASE_FILE     = os.path.join(tmpdir, "cases.json")
    ap.INCIDENT_FILE = os.path.join(tmpdir, "incidents.json")
    ap.TIMELINE_FILE = os.path.join(tmpdir, "timeline.json")
    ab.BASELINE_FILE = os.path.join(tmpdir, "behavior_baseline.json")
    es.SNAPSHOT_DIR  = os.path.join(tmpdir, "evidence_snapshots")
    ap._save(ap.CASE_FILE, [])

    yield tmpdir

    for k, v in originals.items():
        setattr(soar, k, v)
    for k, v in ap_originals.items():
        setattr(ap, k, v)
    ab.BASELINE_FILE = detection_originals["ab_file"]
    es.SNAPSHOT_DIR  = detection_originals["es_dir"]
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestPlaybookMatching:
    def test_trigger_and_conditions_all_must_pass(self):
        playbook = {
            "trigger": {"mitre_tactic": "Credential Access", "min_severity": "HIGH"},
            "conditions": [{"field": "vt_score", "op": ">=", "value": 5}],
        }
        matching = {"severity": "CRITICAL", "mitre_tactic": "Credential Access", "vt_score": 8}
        non_matching = {"severity": "CRITICAL", "mitre_tactic": "Credential Access", "vt_score": 2}
        assert soar.test_playbook(playbook, matching)["would_match"] is True
        assert soar.test_playbook(playbook, non_matching)["would_match"] is False

    def test_severity_below_minimum_does_not_match(self):
        playbook = {"trigger": {"min_severity": "CRITICAL"}, "conditions": []}
        result = soar.test_playbook(playbook, {"severity": "HIGH"})
        assert result["would_match"] is False

    def test_not_in_condition(self):
        playbook = {"trigger": {}, "conditions": [
            {"field": "host", "op": "not_in", "value": ["dc-01"]}
        ]}
        assert soar.test_playbook(playbook, {"host": "workstation-05"})["would_match"] is True
        assert soar.test_playbook(playbook, {"host": "dc-01"})["would_match"] is False

    def test_dry_run_has_zero_side_effects(self, tmp_soar_files):
        """test_playbook() must never write anything, regardless of match."""
        playbook = {"trigger": {}, "conditions": [],
                    "actions": [{"type": "block_ip", "auto": True, "params": {"ip": "1.2.3.4"}}]}
        soar.test_playbook(playbook, {"severity": "CRITICAL"})
        assert soar._load(soar.RUNS_FILE) == []
        assert ap._load(ap.CASE_FILE) == []


class TestRunPlaybooksIntegration:
    """The actual regression test for this round's critical fix: the SOAR
    engine existed and worked standalone, but nothing called it from the
    real alert flow. This confirms process_alert() -> run_playbooks() is
    genuinely wired, not just present in the codebase."""

    def test_process_alert_triggers_matching_playbook(self, tmp_soar_files):
        pb = [{
            "playbook_id": "PB-TEST", "name": "Test Playbook", "enabled": True,
            "trigger": {"mitre_tactic": "Credential Access", "min_severity": "HIGH"},
            "conditions": [],
            "actions": [{"type": "create_case", "auto": True, "params": {"priority": "P1"}},
                        {"type": "isolate_host", "auto": False, "params": {}, "requires_approval": True}],
        }]
        soar._save(soar.PLAYBOOK_FILE, pb)

        alert = ap.process_alert({
            "event": "Credential Dumping Detected",
            "detail": "mimikatz sekurlsa::logonpasswords detected",
            "host": "test-host", "user": "test-user",
        })

        assert alert is not None
        assert "PB-TEST" in alert.get("playbook_matches", [])

        runs = soar._load(soar.RUNS_FILE)
        assert len(runs) == 1
        assert runs[0]["matched"] is True
        assert any(a["action"] == "create_case" for a in runs[0]["actions_fired"])
        assert any(a["action"] == "isolate_host" for a in runs[0]["actions_queued"])

        approvals = soar._load(soar.APPROVALS_FILE)
        assert len(approvals) == 1
        assert approvals[0]["action_type"] == "isolate_host"
        assert approvals[0]["status"] == "PENDING"

    def test_disabled_playbook_never_fires(self, tmp_soar_files):
        pb = [{
            "playbook_id": "PB-OFF", "name": "Disabled", "enabled": False,
            "trigger": {}, "conditions": [],
            "actions": [{"type": "notify", "auto": True, "params": {}}],
        }]
        soar._save(soar.PLAYBOOK_FILE, pb)
        alert = ap.process_alert({"event": "e", "detail": "d", "host": "h"})
        assert "PB-OFF" not in (alert.get("playbook_matches") or [])

    def test_a_soar_crash_never_blocks_alert_persistence(self, tmp_soar_files, monkeypatch):
        """process_alert() wraps the SOAR call specifically so a bug in a
        playbook/action can never prevent the alert itself from being
        recorded — verify that guarantee holds even when run_playbooks
        actually raises."""
        def _boom(alert):
            raise RuntimeError("simulated SOAR failure")
        monkeypatch.setattr(soar, "run_playbooks", _boom)
        import core.alert_pipeline as ap_mod
        monkeypatch.setattr(ap_mod, "run_playbooks", _boom, raising=False)

        alert = ap.process_alert({"event": "e", "detail": "mimikatz", "host": "h"})
        assert alert is not None
        assert alert.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class TestCreateCaseDedup:
    """Regression test for this round's fix: create_case() used to always
    insert a new case with no de-dup check, diverging from
    alert_pipeline's own folding logic."""

    def test_repeated_playbook_fire_folds_not_duplicates(self, tmp_soar_files):
        alert1 = {"id": "A1", "host": "h1", "user": "u1",
                  "mitre_tactic": "Credential Access", "severity": "HIGH"}
        alert2 = {"id": "A2", "host": "h1", "user": "u1",
                  "mitre_tactic": "Credential Access", "severity": "HIGH"}
        r1 = ra.create_case(alert1, priority="P1", triggered_by="playbook:PB-1")
        r2 = ra.create_case(alert2, priority="P1", triggered_by="playbook:PB-1")
        assert r1["case_id"] == r2["case_id"]
        cases = ap._load(ap.CASE_FILE)
        assert len(cases) == 1
        assert set(cases[0]["related_alerts"]) == {"A1", "A2"}

    def test_different_tactic_opens_new_case(self, tmp_soar_files):
        ra.create_case({"id": "A1", "host": "h1", "mitre_tactic": "Credential Access",
                        "severity": "HIGH"}, triggered_by="playbook:PB-1")
        ra.create_case({"id": "A2", "host": "h1", "mitre_tactic": "Exfiltration",
                        "severity": "HIGH"}, triggered_by="playbook:PB-1")
        assert len(ap._load(ap.CASE_FILE)) == 2


class TestIsolationCleanup:
    """Regression test for this round's fix: isolate_host()/restore_host()
    used to only ever manage 4 fixed rule names, so any per-IP allow rule
    created by isolate_host() was never cleaned up by restore_host()."""

    def test_isolate_records_every_created_rule_including_dynamic_allow_ips(self, monkeypatch, tmp_path):
        state_file = tmp_path / "isolation_state.json"
        monkeypatch.setattr(ra, "ISOLATION_STATE_FILE", str(state_file))

        # netsh isn't present in this sandbox — patch subprocess.run so the
        # rule-tracking logic can be tested independent of the OS call
        import subprocess as _sp
        monkeypatch.setattr(_sp, "run", lambda *a, **k: type("R", (), {"returncode": 0, "stderr": "", "stdout": ""})())

        ra.isolate_host("test-host", allow_ips=["10.0.0.1", "10.0.0.2"])
        state = json.load(open(state_file))
        rules = state["test-host"]
        # Both dynamic allow rules must be tracked, not just the 4 fixed ones
        assert any("10_0_0_1" in r for r in rules)
        assert any("10_0_0_2" in r for r in rules)
        assert len(rules) == 6  # Block, BlockIn, 2x Allow_IP, AllowDNS, AllowDashboard

    def test_restore_removes_exactly_the_recorded_rules(self, monkeypatch, tmp_path):
        state_file = tmp_path / "isolation_state.json"
        monkeypatch.setattr(ra, "ISOLATION_STATE_FILE", str(state_file))
        deleted = []
        monkeypatch.setattr(ra, "_delete_rule", lambda name: deleted.append(name))

        json.dump({"test-host": ["RuleA", "RuleB", "RuleC_Allow_10_0_0_1"]}, open(state_file, "w"))
        ra.restore_host("test-host")
        assert set(deleted) == {"RuleA", "RuleB", "RuleC_Allow_10_0_0_1"}
        # host entry should be cleared after restore
        assert "test-host" not in json.load(open(state_file))


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))