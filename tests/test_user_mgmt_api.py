import json
import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, _hash_pw, USERS
USERS["admin"]["password_hash"] = _hash_pw("admin123")
USERS["analyst"]["password_hash"] = _hash_pw("analyst123")
from app import app, USERS, _load_users, _save_users


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _get_token(client, username, password):
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200
    return res.get_json()["token"]


def test_get_users_list(client):
    token = _get_token(client, "analyst", "analyst123")
    res = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    usernames = [u["username"] for u in data["users"]]
    assert "admin" in usernames
    assert "analyst" in usernames


def test_create_user_admin_only(client):
    admin_token = _get_token(client, "admin", "admin123")
    analyst_token = _get_token(client, "analyst", "analyst123")

    # Analyst cannot create users (403 Forbidden)
    res_forbidden = client.post("/api/users", json={"username": "testuser1", "password": "Password123", "role": "analyst"},
                                headers={"Authorization": f"Bearer {analyst_token}"})
    assert res_forbidden.status_code == 403

    # Clean up testuser1 if exists
    client.delete("/api/users/testuser1", headers={"Authorization": f"Bearer {admin_token}"})

    # Admin successfully creates user
    res_create = client.post("/api/users", json={"username": "testuser1", "password": "Password123", "role": "analyst"},
                             headers={"Authorization": f"Bearer {admin_token}"})
    assert res_create.status_code == 201
    assert res_create.get_json()["success"] is True

    # New user can log in immediately!
    login_new = client.post("/api/auth/login", json={"username": "testuser1", "password": "Password123"})
    assert login_new.status_code == 200
    assert login_new.get_json()["role"] == "analyst"

    # Clean up
    client.delete("/api/users/testuser1", headers={"Authorization": f"Bearer {admin_token}"})


def test_update_user_role_and_password_reset(client):
    admin_token = _get_token(client, "admin", "admin123")

    # Create temporary user
    client.delete("/api/users/temp_analyst", headers={"Authorization": f"Bearer {admin_token}"})
    client.post("/api/users", json={"username": "temp_analyst", "password": "Password123", "role": "analyst"},
                headers={"Authorization": f"Bearer {admin_token}"})

    # Update role to auditor
    res_role = client.put("/api/users/temp_analyst/role", json={"role": "auditor"},
                          headers={"Authorization": f"Bearer {admin_token}"})
    assert res_role.status_code == 200

    # Reset password
    res_pw = client.post("/api/users/temp_analyst/reset_password", json={"new_password": "NewSecretPassword!"},
                         headers={"Authorization": f"Bearer {admin_token}"})
    assert res_pw.status_code == 200

    # Login with new password
    login_pw = client.post("/api/auth/login", json={"username": "temp_analyst", "password": "NewSecretPassword!"})
    assert login_pw.status_code == 200
    assert login_pw.get_json()["role"] == "auditor"

    # Delete user
    res_del = client.delete("/api/users/temp_analyst", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_del.status_code == 200
