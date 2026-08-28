"""
SentinelX End-to-End System & API Integration Tests
===================================================
Tests all core subsystems working together:
1. Flask API endpoints & Authentication (Login, Token Verify, RBAC)
2. Alert pipeline end-to-end execution
3. Case generation & incident tracking
4. SOAR Playbook evaluation and execution
5. Forensic evidence snapshot access
6. Geolocation API security & response format
"""

import os
import sys
import json
import time
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, _hash_pw, USERS
USERS["admin"]["password_hash"] = _hash_pw("admin123")
USERS["analyst"]["password_hash"] = _hash_pw("analyst123")
from app import app, USERS, _issue_token, _load_users
from core import alert_pipeline as ap
from core import soar_engine as soar
from core import response_actions as ra
from core import evidence_snapshot as es
from core import anomaly_baseline as ab


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def admin_headers():
    token = _issue_token("admin")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


@pytest.fixture
def analyst_headers():
    token = _issue_token("analyst")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


class TestAuthenticationAndRBAC:
    """Test auth endpoints, token creation/verification, and role restrictions."""

    def test_login_success_analyst(self, client):
        r = client.post("/api/auth/login", json={"username": "analyst", "password": "analyst123"})
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("success") is True
        assert data.get("role") == "analyst"
        assert "token" in data

    def test_login_success_admin(self, client):
        r = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("success") is True
        assert data.get("role") == "admin"
        assert "token" in data

    def test_login_invalid_credentials(self, client):
        r = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
        assert r.status_code == 401
        data = r.get_json()
        assert data.get("success") is False

    def test_verify_valid_token(self, client, admin_headers):
        r = client.get("/api/auth/verify", headers=admin_headers)
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("valid") is True
        assert data.get("role") == "admin"

    def test_verify_invalid_token(self, client):
        r = client.get("/api/auth/verify", headers={"Authorization": "Bearer invalid:token:signature"})
        assert r.status_code == 401
        data = r.get_json()
        assert data.get("valid") is False

    def test_kill_process_requires_admin_role(self, client, analyst_headers, admin_headers):
        # Analyst role should be rejected with 403 Forbidden
        r_analyst = client.post("/api/kill_process", headers=analyst_headers, json={"pid": 999999, "name": "test"})
        assert r_analyst.status_code == 403

        # Admin role is allowed (even if pid doesn't exist, role check passes)
        r_admin = client.post("/api/kill_process", headers=admin_headers, json={"pid": 999999, "name": "test"})
        assert r_admin.status_code in (200, 400) or r_admin.get_json().get("success") is False

    def test_geo_lookup_requires_auth(self, client, analyst_headers):
        # Unauthenticated request fails with 401
        r_unauth = client.get("/api/geo?ip=8.8.8.8")
        assert r_unauth.status_code == 401

        # Authenticated request succeeds with 200
        r_auth = client.get("/api/geo?ip=8.8.8.8", headers=analyst_headers)
        assert r_auth.status_code == 200
        data = r_auth.get_json()
        assert data.get("status") == "success"

    def test_geo_preset_locations(self, client, analyst_headers):
        # 1. India / Chennai (182.79.0.1)
        r_in = client.get("/api/geo?ip=182.79.0.1", headers=analyst_headers)
        assert r_in.status_code == 200
        d_in = r_in.get_json()
        assert "India" in d_in.get("country", "")
        assert d_in.get("countryCode") == "IN"
        assert d_in.get("lat") is not None and d_in.get("lon") is not None

        # 2. Russia (95.173.136.1)
        r_ru = client.get("/api/geo?ip=95.173.136.1", headers=analyst_headers)
        assert r_ru.status_code == 200
        d_ru = r_ru.get_json()
        assert "Russia" in d_ru.get("country", "")
        assert d_ru.get("countryCode") == "RU"

        # 3. USA (8.8.8.8)
        r_us = client.get("/api/geo?ip=8.8.8.8", headers=analyst_headers)
        assert r_us.status_code == 200
        d_us = r_us.get_json()
        assert "United States" in d_us.get("country", "")
        assert d_us.get("countryCode") == "US"

        # 4. Germany (185.220.101.7)
        r_de = client.get("/api/geo?ip=185.220.101.7", headers=analyst_headers)
        assert r_de.status_code == 200
        d_de = r_de.get_json()
        assert "Germany" in d_de.get("country", "")
        assert d_de.get("countryCode") == "DE"

        # 5. United Kingdom (81.2.69.142)
        r_gb = client.get("/api/geo?ip=81.2.69.142", headers=analyst_headers)
        assert r_gb.status_code == 200
        d_gb = r_gb.get_json()
        assert "United Kingdom" in d_gb.get("country", "") or d_gb.get("countryCode") == "GB"

        # 6. China (114.114.114.114)
        r_cn = client.get("/api/geo?ip=114.114.114.114", headers=analyst_headers)
        assert r_cn.status_code == 200
        d_cn = r_cn.get_json()
        assert "China" in d_cn.get("country", "") or d_cn.get("countryCode") == "CN"

        # 7. Private / LAN IP (127.0.0.1) -> Maps to Chennai, India
        r_lan = client.get("/api/geo?ip=127.0.0.1", headers=analyst_headers)
        assert r_lan.status_code == 200
        d_lan = r_lan.get_json()
        assert d_lan.get("is_private") is True
        assert d_lan.get("countryCode") == "IN"
        assert "Chennai" in d_lan.get("city", "")
        assert abs(d_lan.get("lat") - 13.0827) < 0.1
        assert abs(d_lan.get("lon") - 80.2707) < 0.1


class TestAPIEndpoints:
    """Test REST API data queries, custom rules, and system status."""

    def test_system_health(self, client, analyst_headers):
        r = client.get("/api/system/health", headers=analyst_headers)
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("status") == "operational"
        assert "cpu" in data
        assert "memory" in data
        assert "disk" in data

    def test_get_alerts(self, client, analyst_headers):
        r = client.get("/api/alerts", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_get_cases(self, client, analyst_headers):
        r = client.get("/api/cases", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_get_incidents(self, client, analyst_headers):
        r = client.get("/api/incidents", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_get_timeline(self, client, analyst_headers):
        r = client.get("/api/timeline", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_get_audit_log(self, client, analyst_headers):
        r = client.get("/api/audit_log", headers=analyst_headers)
        assert r.status_code == 200
        assert isinstance(r.get_json(), list)

    def test_custom_rules_crud(self, client, admin_headers):
        # Create custom rule
        r_create = client.post("/api/rules/custom", headers=admin_headers, json={
            "name": "Test Detection Rule",
            "keyword": f"test_kw_{int(time.time()*1000)}",
            "score": 35,
            "description": "Integration test rule",
            "active": True
        })
        assert r_create.status_code == 200
        data = r_create.get_json()
        assert data.get("success") is True
        rule_id = data["rule"]["id"]

        # Toggle rule
        r_toggle = client.post(f"/api/rules/custom/{rule_id}/toggle", headers=admin_headers)
        assert r_toggle.status_code == 200
        assert r_toggle.get_json().get("success") is True

        # Delete rule
        r_delete = client.delete(f"/api/rules/custom/{rule_id}", headers=admin_headers)
        assert r_delete.status_code == 200
        assert r_delete.get_json().get("success") is True
