"""
SentinelX Live End-to-End Pipeline Smoke Test
=============================================
Validates:
1. Alert processing through 8-stage pipeline
2. Critical severity calculation from keyword signals
3. MITRE technique identification
4. Case creation in data/cases.json
5. Alert persistence in data/alerts.json
6. Timeline logging in data/timeline.json
7. Forensic evidence snapshot creation
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alert_pipeline import process_alert, _load, ALERT_FILE, CASE_FILE, TIMELINE_FILE
from core.evidence_snapshot import get_snapshot


def test_live_pipeline_full_cycle():
    alert_id = f"SMOKE-{int(time.time()*1000)}"
    raw_event = {
        "id": alert_id,
        "event": "Mimikatz Credential Dumping Detected",
        "detail": "Command: mimikatz.exe sekurlsa::logonpasswords PID 4321",
        "host": "SMOKE-HOST-01",
        "user": "SYSTEM",
        "ip": "192.168.1.105"
    }

    # 1. Process alert through pipeline
    processed = process_alert(raw_event)
    assert processed is not None
    assert processed.get("severity") == "CRITICAL"
    assert processed.get("score", 0) >= 71
    assert processed.get("mitre_id") in ("T1003", "T1003.001", "T1003.002", "T1003.004", "T1003.005")

    # 2. Verify alert persistence
    alerts = _load(ALERT_FILE)
    assert any(a.get("id") == alert_id for a in alerts)

    # 3. Verify timeline persistence
    timeline = _load(TIMELINE_FILE)
    assert any(t.get("alert_id") == alert_id for t in timeline)

    # 4. Verify case auto-creation
    cases = _load(CASE_FILE)
    matching_cases = [c for c in cases if c.get("host") == "SMOKE-HOST-01"]
    assert len(matching_cases) > 0

    # 5. Verify forensic evidence snapshot on CRITICAL
    snap = get_snapshot(alert_id)
    assert snap is not None
    assert "processes" in snap
    assert "connections" in snap
