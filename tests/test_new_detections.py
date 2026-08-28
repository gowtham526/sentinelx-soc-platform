"""
Tests for this round's three new detection features:
    core/evidence_snapshot.py
    detectors/canary_detector.py
    core/anomaly_baseline.py
and their integration into core/alert_pipeline.py (Signals 23/24, and the
Stage 3b / Stage 4c hooks in process_alert()).

Run from the project root:  pytest tests/ -v

Same isolation discipline as tests/test_soar_engine.py: every file-backed
module gets its path(s) redirected to a temp dir for the duration of a
test via the tmp_detection_files fixture, so nothing here ever touches
real project data (data/behavior_baseline.json, data/evidence_snapshots/,
canary_files/, alerts.json, etc.).
"""

import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core import alert_pipeline as ap
from core import evidence_snapshot as es
from core import anomaly_baseline as ab
from detectors import canary_detector as cd
from core import soar_engine as soar


@pytest.fixture
def tmp_detection_files():
    """Redirect evidence_snapshot / anomaly_baseline / canary_detector /
    alert_pipeline file paths to a temp dir for the duration of a test,
    then restore the originals.

    Also redirects soar_engine's files: process_alert()'s Stage 4b calls
    run_playbooks() unconditionally (same as Stage 3b/4c call anomaly and
    evidence), so the one test here that goes through the real
    process_alert() (TestProcessAlertWiring) would otherwise leak a real
    entry into data/playbook_runs.json every time it runs — the same
    class of pollution just fixed in test_soar_engine.py's fixture, from
    the opposite direction."""
    tmpdir = tempfile.mkdtemp()
    originals = {
        "es_dir":  es.SNAPSHOT_DIR,
        "ab_file": ab.BASELINE_FILE,
        "cd_dir":  cd.DEFAULT_CANARY_DIR,
        "ap_alert":    ap.ALERT_FILE,
        "ap_case":     ap.CASE_FILE,
        "ap_incident": ap.INCIDENT_FILE,
        "ap_timeline": ap.TIMELINE_FILE,
        "soar_playbook":  soar.PLAYBOOK_FILE,
        "soar_runs":      soar.RUNS_FILE,
        "soar_approvals": soar.APPROVALS_FILE,
    }

    es.SNAPSHOT_DIR  = os.path.join(tmpdir, "evidence_snapshots")
    ab.BASELINE_FILE = os.path.join(tmpdir, "behavior_baseline.json")
    cd.DEFAULT_CANARY_DIR = os.path.join(tmpdir, "canary_files")
    ap.ALERT_FILE    = os.path.join(tmpdir, "alerts.json")
    ap.CASE_FILE     = os.path.join(tmpdir, "cases.json")
    ap.INCIDENT_FILE = os.path.join(tmpdir, "incidents.json")
    ap.TIMELINE_FILE = os.path.join(tmpdir, "timeline.json")
    soar.PLAYBOOK_FILE  = os.path.join(tmpdir, "playbooks.json")
    soar.RUNS_FILE      = os.path.join(tmpdir, "playbook_runs.json")
    soar.APPROVALS_FILE = os.path.join(tmpdir, "pending_approvals.json")
    ap._save(ap.CASE_FILE, [])

    yield tmpdir

    es.SNAPSHOT_DIR  = originals["es_dir"]
    ab.BASELINE_FILE = originals["ab_file"]
    cd.DEFAULT_CANARY_DIR = originals["cd_dir"]
    ap.ALERT_FILE    = originals["ap_alert"]
    ap.CASE_FILE     = originals["ap_case"]
    ap.INCIDENT_FILE = originals["ap_incident"]
    ap.TIMELINE_FILE = originals["ap_timeline"]
    soar.PLAYBOOK_FILE  = originals["soar_playbook"]
    soar.RUNS_FILE      = originals["soar_runs"]
    soar.APPROVALS_FILE = originals["soar_approvals"]
    shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────
# core/evidence_snapshot.py  (2 tests)
# ─────────────────────────────────────────────────────────────

class TestEvidenceSnapshot:
    def test_capture_snapshot_captures_real_data(self, tmp_detection_files):
        """Real capture, not a mock — this test process itself is a
        running process, so processes should never come back empty."""
        alert = {"id": "ALT-TEST0001", "host": "test-host",
                  "event": "Test CRITICAL Event", "severity": "CRITICAL"}
        snap = es.capture_snapshot(alert)

        assert snap is not None
        assert snap["alert_id"] == "ALT-TEST0001"
        assert snap["host"] == "test-host"
        assert len(snap["processes"]) > 0
        assert isinstance(snap["connections"], list)
        assert isinstance(snap["users"], list)

        path = os.path.join(es.SNAPSHOT_DIR, "ALT-TEST0001.json")
        assert os.path.exists(path)

    def test_get_snapshot_roundtrip_and_missing_id(self, tmp_detection_files):
        alert = {"id": "ALT-TEST0002", "host": "h", "event": "e", "severity": "CRITICAL"}
        es.capture_snapshot(alert)

        loaded = es.get_snapshot("ALT-TEST0002")
        assert loaded is not None
        assert loaded["alert_id"] == "ALT-TEST0002"

        assert es.get_snapshot("does-not-exist") is None


# ─────────────────────────────────────────────────────────────
# detectors/canary_detector.py  (3 tests)
# ─────────────────────────────────────────────────────────────

class _FakeFSEvent:
    def __init__(self, path, is_directory=False):
        self.src_path = path
        self.is_directory = is_directory


class TestCanaryFileDetector:
    def test_handler_fires_on_canary_file(self, tmp_path):
        canary_file = tmp_path / "decoy.txt"
        canary_file.write_text("bait")
        fired = []
        handler = cd._CanaryFileHandler(
            canary_paths=[str(canary_file)],
            alert_callback=fired.append,
            host="test-host", user="test-user",
        )

        handler.on_modified(_FakeFSEvent(str(canary_file)))

        assert len(fired) == 1
        assert fired[0]["event"] == "Canary File Triggered"
        assert "CANARY_HINT:TRIGGERED" in fired[0]["detail"]

    def test_handler_silent_on_non_canary_file(self, tmp_path):
        canary_file = tmp_path / "decoy.txt"
        canary_file.write_text("bait")
        other_file = tmp_path / "not_a_decoy.txt"
        other_file.write_text("ordinary work file")
        fired = []
        handler = cd._CanaryFileHandler(
            canary_paths=[str(canary_file)],
            alert_callback=fired.append,
            host="test-host", user="test-user",
        )

        handler.on_modified(_FakeFSEvent(str(other_file)))

        assert len(fired) == 0

    def test_get_canary_file_paths_creates_defaults(self, tmp_detection_files, monkeypatch):
        monkeypatch.delenv("CANARY_FILE_PATHS", raising=False)

        paths = cd._get_canary_file_paths()

        assert len(paths) >= 1
        for p in paths:
            assert os.path.exists(p)
            assert os.path.dirname(p) == os.path.abspath(cd.DEFAULT_CANARY_DIR)


# ─────────────────────────────────────────────────────────────
# core/anomaly_baseline.py  (5 tests)
# ─────────────────────────────────────────────────────────────

class TestAnomalyBaseline:
    def test_cold_start_is_inert(self, tmp_detection_files):
        """Below MIN_BASELINE_SAMPLES completed windows, nothing gets
        flagged no matter how high the count runs — there isn't enough
        history yet to call anything abnormal."""
        now = 1_700_000_000.0
        hint = None
        for i in range(50):
            hint = ab.record_and_check("hostCold", "eventStart", now=now + i)
        assert hint is None

    def test_spike_after_baseline_is_flagged(self, tmp_detection_files):
        """A real baseline (with genuine variance, not a degenerate
        zero-stdev one) established over several windows, then one
        window slammed with 40 occurrences — must come back HIGH."""
        base = 1_700_000_000.0
        win  = ab.WINDOW_SECONDS
        baseline_counts = [2, 3, 4, 2, 4, 3, 2]  # mean ~2.9, real spread

        hint = "unset"
        for w, count in enumerate(baseline_counts):
            window_start = base + w * win
            for i in range(count):
                hint = ab.record_and_check("hostA", "eventX", now=window_start + i)
        assert hint is None  # never anomalous while still building baseline

        spike_start = base + len(baseline_counts) * win
        hint = None
        for i in range(40):
            hint = ab.record_and_check("hostA", "eventX", now=spike_start + i)
        assert hint == "HIGH"

    def test_unrelated_pairs_isolated(self, tmp_detection_files):
        """Driving (hostA, eventX) into a HIGH anomaly must not affect
        (hostB, eventY) — separate state per key."""
        base = 1_700_000_000.0
        win  = ab.WINDOW_SECONDS
        for w, count in enumerate([2, 3, 4, 2, 4, 3, 2]):
            for i in range(count):
                ab.record_and_check("hostA", "eventX", now=base + w * win + i)
        for i in range(40):
            ab.record_and_check("hostA", "eventX", now=base + 7 * win + i)

        # hostB/eventY has never been touched — must still read as cold start
        hint = ab.record_and_check("hostB", "eventY", now=base + 7 * win)
        assert hint is None

    def test_steady_rate_not_flagged(self, tmp_detection_files):
        """A pair that keeps running at roughly its own baseline rate
        should never be flagged — anomaly detection is about deviation,
        not raw volume."""
        base = 1_700_000_000.0
        win  = ab.WINDOW_SECONDS
        baseline_counts = [2, 3, 4, 2, 4, 3, 2]
        for w, count in enumerate(baseline_counts):
            for i in range(count):
                ab.record_and_check("hostSteady", "eventNormal", now=base + w * win + i)

        # One more window at the same typical rate (3 occurrences)
        steady_start = base + len(baseline_counts) * win
        hint = None
        for i in range(3):
            hint = ab.record_and_check("hostSteady", "eventNormal", now=steady_start + i)
        assert hint is None

    def test_medium_vs_high_threshold(self, tmp_detection_files):
        """Exact z-score control via directly-seeded baseline stats
        (mean=5, stdev=2, n=10) rather than relying on Welford
        accumulation arithmetic — z=3.0 must land MEDIUM, z=5.0 must
        land HIGH."""
        now = 1_700_100_000.0
        key = "hostZ|eventQ"
        state = {
            key: {
                "window_start": now, "window_count": 0,
                "baseline_n": 10, "baseline_mean": 5.0,
                "baseline_m2": (2.0 ** 2) * (10 - 1),  # stdev=2 given n=10
            }
        }
        ab._save_state(state)

        hint = None
        for _ in range(11):  # z = (11-5)/2 = 3.0
            now += 1
            hint = ab.record_and_check("hostZ", "eventQ", now=now)
        assert hint == "MEDIUM"

        state = ab._load_state()
        state[key]["window_count"] = 0
        ab._save_state(state)

        hint = None
        for _ in range(15):  # z = (15-5)/2 = 5.0
            now += 1
            hint = ab.record_and_check("hostZ", "eventQ", now=now)
        assert hint == "HIGH"


# ─────────────────────────────────────────────────────────────
# Signals 23 & 24 in calculate_severity()  (2 tests)
# ─────────────────────────────────────────────────────────────

class TestNewSignals:
    def test_signal_23_canary_hint_scores_75_and_forces_critical(self):
        severity, score = ap.calculate_severity(
            "Canary File Triggered", "detail text\nCANARY_HINT:TRIGGERED", 0, 0, 0
        )
        assert score >= 75
        assert severity == "CRITICAL"  # 75 alone clears the 71 threshold

    def test_signal_24_anomaly_hint_scores_15_and_25(self):
        _, score_none   = ap.calculate_severity("Event", "plain detail text", 0, 0, 0)
        _, score_medium = ap.calculate_severity("Event", "plain detail text\nANOMALY_HINT:MEDIUM", 0, 0, 0)
        _, score_high   = ap.calculate_severity("Event", "plain detail text\nANOMALY_HINT:HIGH", 0, 0, 0)
        assert score_medium - score_none == 15
        assert score_high - score_none == 25


# ─────────────────────────────────────────────────────────────
# End-to-end wiring through the real process_alert()  (1 test)
# ─────────────────────────────────────────────────────────────

class TestProcessAlertWiring:
    def test_process_alert_wires_anomaly_and_evidence_snapshot(self, tmp_detection_files):
        """The unit tests above exercise anomaly_baseline and
        evidence_snapshot directly; this proves process_alert() itself
        actually calls into them (Stage 3b, Stage 4c) rather than the
        two modules just existing next to a pipeline that never uses
        them — exactly the class of gap this whole project keeps
        catching (SOAR was fully built and tested standalone once too,
        and still wasn't wired in)."""
        alert = ap.process_alert({
            "event":  "Canary File Triggered",
            "detail": "Canary file modified\nCANARY_HINT:TRIGGERED",
            "host":   "wiretest-host", "user": "tester",
        })

        assert alert is not None
        assert alert["severity"] == "CRITICAL"

        # Stage 3b: anomaly_baseline.record_and_check() was actually called
        state = ab._load_state()
        assert "wiretest-host|Canary File Triggered" in state

        # Stage 4c: evidence_snapshot.capture_snapshot() was actually called
        snap = es.get_snapshot(alert["id"])
        assert snap is not None
        assert snap["host"] == "wiretest-host"