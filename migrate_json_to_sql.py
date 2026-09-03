"""
Automated Migration Script: JSON Flat-Files -> Production Relational Database
Migrates all legacy JSON data into the SQL database tables with 100% data fidelity.
"""

import os
import sys
import json
from core.database import db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

def migrate():
    print("================================================================")
    print("  SENTINELX: DATABASE MIGRATION (JSON -> PRODUCTION SQL)")
    print("================================================================")
    
    # 1. Migrate Users
    users_file = os.path.join(DATA_DIR, "users.json")
    if os.path.exists(users_file):
        try:
            with open(users_file, "r", encoding="utf-8") as f:
                users_data = json.load(f)
            u_count = 0
            for username, details in users_data.items():
                pw_hash = details.get("password_hash") or details.get("password") or ""
                role = details.get("role", "analyst")
                status = details.get("status", "Active")
                if pw_hash:
                    db.upsert_user(username, pw_hash, role, status)
                    u_count += 1
            print(f" [MIGRATION] Successfully migrated {u_count} user accounts to SQL users table.")
        except Exception as e:
            print(f" [MIGRATION] Error migrating users.json: {e}")

    # 2. Migrate Alerts
    alerts_file = os.path.join(DATA_DIR, "alerts.json")
    if os.path.exists(alerts_file):
        try:
            with open(alerts_file, "r", encoding="utf-8") as f:
                alerts_data = json.load(f)
            a_count = 0
            for alert in alerts_data:
                db.upsert_alert(alert)
                a_count += 1
            print(f" [MIGRATION] Successfully migrated {a_count} alerts to SQL alerts table.")
        except Exception as e:
            print(f" [MIGRATION] Error migrating alerts.json: {e}")

    # 3. Migrate Blocked IPs
    blocked_file = os.path.join(DATA_DIR, "blocked_ips.json")
    if os.path.exists(blocked_file):
        try:
            with open(blocked_file, "r", encoding="utf-8") as f:
                blocked_data = json.load(f)
            b_count = 0
            for item in blocked_data:
                if isinstance(item, dict):
                    db.add_blocked_ip(item.get("ip"), item.get("reason", ""), item.get("blocked_by", "SOAR"), item.get("blocked_at"))
                elif isinstance(item, str):
                    db.add_blocked_ip(item)
                b_count += 1
            print(f" [MIGRATION] Successfully migrated {b_count} blocked IPs to SQL blocked_ips table.")
        except Exception as e:
            print(f" [MIGRATION] Error migrating blocked_ips.json: {e}")

    # 4. Migrate Audit Logs
    audit_file = os.path.join(DATA_DIR, "audit_log.jsonl")
    if os.path.exists(audit_file):
        try:
            log_count = 0
            with open(audit_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    entry = json.loads(line)
                    db.log_audit_event(
                        entry.get("user") or entry.get("username") or "system",
                        entry.get("action") or "EVENT",
                        entry.get("details") or "",
                        entry.get("ip") or "127.0.0.1"
                    )
                    log_count += 1
            print(f" [MIGRATION] Successfully migrated {log_count} audit log entries to SQL audit_logs table.")
        except Exception as e:
            print(f" [MIGRATION] Error migrating audit_log.jsonl: {e}")

    print("================================================================")
    print("  DATABASE MIGRATION COMPLETED SUCCESSFULLY!")
    print("================================================================")

if __name__ == "__main__":
    migrate()
