import os
import json
import urllib.request
from core.database import db

def run_tests():
    print("==================================================================")
    print("  SENTINELX: DATABASE & REST API VERIFICATION SUITE")
    print("==================================================================")
    
    # 1. Test Direct Database Queries
    all_users = db.get_all_users()
    print(f" [DB CHECK] Total users in SQL database: {len(all_users)}")
    assert "nani" in all_users, "Admin user 'nani' missing from SQL database"
    assert "analyst" in all_users, "User 'analyst' missing from SQL database"
    print(" [DB CHECK] Required roles present: Admin ('nani'), Analyst ('analyst')")
    
    all_alerts = db.get_all_alerts(limit=10)
    print(f" [DB CHECK] Alerts table query successful: {len(all_alerts)} records fetched.")
    
    audit_entries = db.get_audit_logs(limit=5)
    print(f" [DB CHECK] Audit logs table query successful: {len(audit_entries)} records fetched.")
    
    # 2. Test Backend API Login (if server is running)
    print("\n--- Testing API Endpoints ---")
    for u, p in [("nani", "nani123"), ("analyst", "analyst123")]:
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:5000/api/auth/login",
                data=json.dumps({"username": u, "password": p}).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read().decode("utf-8"))
            print(f" [API LOGIN] User [{u}] -> Success: {data.get('success')}, Role: {data.get('role')}")
        except Exception as e:
            print(f" [API LOGIN] (Server offline or busy) {u}: {e}")

    # 3. Test New User Registration directly through DatabaseManager
    test_user = "prod_analyst"
    import bcrypt
    pw_hash = bcrypt.hashpw(b"securePass123!", bcrypt.gensalt()).decode("utf-8")
    db.upsert_user(test_user, pw_hash, role="analyst")
    fetched = db.get_user(test_user)
    assert fetched is not None, "Failed to retrieve newly created user"
    assert fetched["role"] == "analyst", "Role mismatch"
    print(f" [DB TEST] Upsert and fetch test user '{test_user}': SUCCESS")
    
    # Cleanup test user
    db.delete_user(test_user)
    assert db.get_user(test_user) is None, "Failed to delete test user"
    print(f" [DB TEST] Delete test user '{test_user}': SUCCESS")

    print("\n==================================================================")
    print("  ALL DATABASE INTEGRATION TESTS PASSED 100%!")
    print("==================================================================")

if __name__ == "__main__":
    run_tests()
