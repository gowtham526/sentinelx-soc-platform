import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, _hash_pw, USERS
USERS["admin"]["password_hash"] = _hash_pw("admin123")
USERS["analyst"]["password_hash"] = _hash_pw("analyst123")
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _get_token(client):
    res = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
    return res.get_json()["token"]


def test_threathunt_query_api(client):
    token = _get_token(client)
    res = client.post("/api/threathunt/query", json={"keyword": "powershell", "min_severity": "MEDIUM"},
                      headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "total_hits" in data
    assert "results" in data


def test_playbook_dry_run_api(client):
    token = _get_token(client)
    res = client.post("/api/playbooks/dry_run", json={
        "name": "Ransomware Emergency Lockdown",
        "severity": "CRITICAL",
        "actions": ["isolate_host", "kill_process", "snapshot_evidence", "notify_voice"]
    }, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert len(data["execution_steps"]) == 4
    assert data["execution_steps"][0]["status"] == "SIMULATED_SUCCESS"


def test_compliance_export_package_api(client):
    token = _get_token(client)
    res = client.get("/api/report/compliance_export", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    pkg = data["compliance_package"]
    assert "NIST_CSF_v2" in pkg["compliance_scores"]
    assert "SOC_2_Type_II" in pkg["compliance_scores"]
    assert len(pkg["evidence_integrity_sha256"]) == 64  # valid SHA-256
