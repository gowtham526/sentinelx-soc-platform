import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from integrations.ai_analyst import analyze_alert, draft_incident_report


def test_ai_analyst_local_fallback_on_unconfigured_key():
    dummy_alert = {
        "id": "ALT-101",
        "event": "Mimikatz Memory Dump Attempt",
        "severity": "CRITICAL",
        "host": "SOC-ENDPOINT-01",
        "user": "analyst",
        "mitre_id": "T1003.001",
        "mitre_tactic": "Credential Access",
        "detail": "powershell.exe executed sekurlsa::logonpasswords"
    }

    res = analyze_alert(dummy_alert)
    assert res.get("available") is True
    assert res.get("model") == "SentinelX Expert SOC AI (Local Engine)"
    assert "credential" in res.get("summary", "").lower()
    assert res.get("false_positive_likelihood") == "low"
    assert len(res.get("suggested_actions", [])) >= 3


def test_draft_incident_report_local_fallback():
    dummy_inc = {"incident_id": "INC-001", "host": "SOC-ENDPOINT-01", "user": "analyst", "severity": "CRITICAL"}
    alerts = [{"id": "ALT-101", "event": "Mimikatz", "severity": "CRITICAL", "host": "SOC-ENDPOINT-01"}]
    
    report = draft_incident_report(dummy_inc, alerts)
    assert report.get("available") is True
    assert "Incident Report" in report.get("report", "")
    assert "SOC-ENDPOINT-01" in report.get("report", "")
