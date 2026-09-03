"""
SentinelX Unified Relational Database Module
Provides high-performance, ACID-compliant persistence for both Web and Mobile apps.
Supports:
  1. Production MySQL Server (via PyMySQL, configured via environment variables)
  2. Zero-Config Embedded SQL Engine (SQLite3 at data/sentinelx_production.db)
"""

import os
import sys
import json
import time
import threading
import sqlite3
from datetime import datetime

try:
    import pymysql
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

_DB_LOCK = threading.RLock()
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(DATA_DIR, exist_ok=True)
SQLITE_DB_PATH = os.path.join(DATA_DIR, "sentinelx_production.db")


class DatabaseManager:
    """Enterprise Database Manager supporting MySQL and Embedded SQL."""

    def __init__(self):
        self.db_type = os.environ.get("DB_TYPE", "").strip().lower()
        self.mysql_host = os.environ.get("MYSQL_HOST", "localhost").strip()
        self.mysql_port = int(os.environ.get("MYSQL_PORT", 3306))
        self.mysql_user = os.environ.get("MYSQL_USER", "root").strip()
        self.mysql_password = os.environ.get("MYSQL_PASSWORD", "").strip()
        self.mysql_db = os.environ.get("MYSQL_DATABASE", os.environ.get("MYSQL_DB", "sentinelx_db")).strip()
        
        self.is_mysql = False
        self._init_connection()
        self._init_tables()

    def _init_connection(self):
        """Attempt MySQL connection if requested; fallback seamlessly to embedded SQL."""
        if self.db_type == "mysql" or (self.mysql_password and HAS_PYMYSQL):
            if HAS_PYMYSQL:
                try:
                    conn = pymysql.connect(
                        host=self.mysql_host,
                        port=self.mysql_port,
                        user=self.mysql_user,
                        password=self.mysql_password,
                        charset="utf8mb4",
                        cursorclass=pymysql.cursors.DictCursor,
                        connect_timeout=3
                    )
                    with conn.cursor() as cur:
                        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{self.mysql_db}` CHARACTER SET utf8mb4;")
                    conn.select_db(self.mysql_db)
                    conn.close()
                    self.is_mysql = True
                    print(f" [DB] Connected successfully to Production MySQL Database: {self.mysql_host}:{self.mysql_port}/{self.mysql_db}")
                    return
                except Exception as e:
                    print(f" [DB] MySQL connection notice: {e}. Utilizing Embedded Relational SQL Engine.")
        
        self.is_mysql = False
        print(f" [DB] Initialized Relational SQL Engine at: {SQLITE_DB_PATH}")

    def get_connection(self):
        """Return an active connection object."""
        if self.is_mysql:
            return pymysql.connect(
                host=self.mysql_host,
                port=self.mysql_port,
                user=self.mysql_user,
                password=self.mysql_password,
                database=self.mysql_db,
                charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
        else:
            conn = sqlite3.connect(SQLITE_DB_PATH, timeout=20.0)
            conn.row_factory = sqlite3.Row
            return conn

    def _init_tables(self):
        """Initialize all relational database tables."""
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    # MySQL Schema
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS `users` (
                            `id` INT AUTO_INCREMENT PRIMARY KEY,
                            `username` VARCHAR(64) NOT NULL UNIQUE,
                            `password_hash` VARCHAR(255) NOT NULL,
                            `role` VARCHAR(32) NOT NULL DEFAULT 'analyst',
                            `status` VARCHAR(20) NOT NULL DEFAULT 'Active',
                            `force_password_change` TINYINT(1) NOT NULL DEFAULT 0,
                            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS `alerts` (
                            `id` INT AUTO_INCREMENT PRIMARY KEY,
                            `alert_id` VARCHAR(64) NOT NULL UNIQUE,
                            `title` VARCHAR(255) NOT NULL,
                            `severity` VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
                            `status` VARCHAR(32) NOT NULL DEFAULT 'Open',
                            `source` VARCHAR(64) DEFAULT 'Wazuh',
                            `rule_id` VARCHAR(64) DEFAULT NULL,
                            `host` VARCHAR(128) DEFAULT NULL,
                            `user` VARCHAR(64) DEFAULT NULL,
                            `src_ip` VARCHAR(45) DEFAULT NULL,
                            `dst_ip` VARCHAR(45) DEFAULT NULL,
                            `details` TEXT DEFAULT NULL,
                            `raw_payload` LONGTEXT DEFAULT NULL,
                            `timestamp` VARCHAR(64) DEFAULT NULL,
                            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS `cases` (
                            `id` INT AUTO_INCREMENT PRIMARY KEY,
                            `case_id` VARCHAR(64) NOT NULL UNIQUE,
                            `title` VARCHAR(255) NOT NULL,
                            `description` TEXT DEFAULT NULL,
                            `severity` VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
                            `status` VARCHAR(32) NOT NULL DEFAULT 'Open',
                            `assigned_to` VARCHAR(64) DEFAULT 'Unassigned',
                            `alert_ids` TEXT DEFAULT NULL,
                            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS `audit_logs` (
                            `id` INT AUTO_INCREMENT PRIMARY KEY,
                            `timestamp` VARCHAR(64) NOT NULL,
                            `username` VARCHAR(64) NOT NULL,
                            `action` VARCHAR(128) NOT NULL,
                            `details` TEXT DEFAULT NULL,
                            `ip` VARCHAR(45) DEFAULT '127.0.0.1',
                            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS `blocked_ips` (
                            `id` INT AUTO_INCREMENT PRIMARY KEY,
                            `ip` VARCHAR(45) NOT NULL UNIQUE,
                            `reason` VARCHAR(255) DEFAULT 'Threat Intelligence Match',
                            `blocked_by` VARCHAR(64) DEFAULT 'SOAR Playbook',
                            `blocked_at` VARCHAR(64) DEFAULT NULL,
                            `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                    """)
                else:
                    # SQLite Schema
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password_hash TEXT NOT NULL,
                            role TEXT NOT NULL DEFAULT 'analyst',
                            status TEXT NOT NULL DEFAULT 'Active',
                            force_password_change INTEGER NOT NULL DEFAULT 0,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS alerts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            alert_id TEXT NOT NULL UNIQUE,
                            title TEXT NOT NULL,
                            severity TEXT NOT NULL DEFAULT 'MEDIUM',
                            status TEXT NOT NULL DEFAULT 'Open',
                            source TEXT DEFAULT 'Wazuh',
                            rule_id TEXT DEFAULT NULL,
                            host TEXT DEFAULT NULL,
                            user TEXT DEFAULT NULL,
                            src_ip TEXT DEFAULT NULL,
                            dst_ip TEXT DEFAULT NULL,
                            details TEXT DEFAULT NULL,
                            raw_payload TEXT DEFAULT NULL,
                            timestamp TEXT DEFAULT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS cases (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            case_id TEXT NOT NULL UNIQUE,
                            title TEXT NOT NULL,
                            description TEXT DEFAULT NULL,
                            severity TEXT NOT NULL DEFAULT 'MEDIUM',
                            status TEXT NOT NULL DEFAULT 'Open',
                            assigned_to TEXT DEFAULT 'Unassigned',
                            alert_ids TEXT DEFAULT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS audit_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            username TEXT NOT NULL,
                            action TEXT NOT NULL,
                            details TEXT DEFAULT NULL,
                            ip TEXT DEFAULT '127.0.0.1',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS blocked_ips (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT NOT NULL UNIQUE,
                            reason TEXT DEFAULT 'Threat Intelligence Match',
                            blocked_by TEXT DEFAULT 'SOAR Playbook',
                            blocked_at TEXT DEFAULT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    conn.commit()
            finally:
                cursor.close()
                conn.close()

    # ── USER OPERATIONS ──────────────────────────────────────────

    def get_user(self, username):
        """Retrieve user dictionary by username."""
        username = (username or "").strip().lower()
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    cursor.execute("SELECT * FROM users WHERE username = %s LIMIT 1;", (username,))
                    row = cursor.fetchone()
                else:
                    cursor.execute("SELECT * FROM users WHERE username = ? LIMIT 1;", (username,))
                    row = cursor.fetchone()
                    if row:
                        row = dict(row)
                return row
            finally:
                cursor.close()
                conn.close()

    def get_all_users(self):
        """Return dict of all users in {username: {role, password_hash, ...}} format."""
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM users ORDER BY id ASC;")
                rows = cursor.fetchall()
                result = {}
                for r in rows:
                    item = dict(r)
                    result[item["username"]] = {
                        "role": item["role"],
                        "password_hash": item["password_hash"],
                        "status": item.get("status", "Active"),
                        "force_password_change": bool(item.get("force_password_change", 0)),
                        "created_at": str(item.get("created_at", ""))
                    }
                return result
            finally:
                cursor.close()
                conn.close()

    def upsert_user(self, username, password_hash, role="analyst", status="Active"):
        """Insert or update a user account in the SQL database."""
        username = (username or "").strip().lower()
        role = (role or "analyst").strip().lower()
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    query = """
                        INSERT INTO users (username, password_hash, role, status)
                        VALUES (%s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role), status = VALUES(status);
                    """
                    cursor.execute(query, (username, password_hash, role, status))
                else:
                    query = """
                        INSERT INTO users (username, password_hash, role, status)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, role=excluded.role, status=excluded.status;
                    """
                    cursor.execute(query, (username, password_hash, role, status))
                    conn.commit()
                return True
            finally:
                cursor.close()
                conn.close()

    def delete_user(self, username):
        """Remove user from database."""
        username = (username or "").strip().lower()
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    cursor.execute("DELETE FROM users WHERE username = %s;", (username,))
                else:
                    cursor.execute("DELETE FROM users WHERE username = ?;", (username,))
                    conn.commit()
                return True
            finally:
                cursor.close()
                conn.close()

    # ── ALERT OPERATIONS ─────────────────────────────────────────

    def upsert_alert(self, alert):
        """Insert or update an alert."""
        alert_id = str(alert.get("id") or alert.get("alert_id") or f"ALT-{int(time.time()*1000)}")
        title = alert.get("title") or alert.get("rule_name") or "Security Detection"
        severity = str(alert.get("severity") or "MEDIUM").upper()
        status = alert.get("status") or "Open"
        source = alert.get("source") or "Wazuh"
        rule_id = str(alert.get("rule_id") or "")
        host = alert.get("host") or ""
        user = alert.get("user") or ""
        src_ip = alert.get("src_ip") or ""
        dst_ip = alert.get("dst_ip") or ""
        details = alert.get("details") or ""
        raw_payload = json.dumps(alert)
        ts = alert.get("timestamp") or datetime.utcnow().isoformat() + "Z"

        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    query = """
                        INSERT INTO alerts (alert_id, title, severity, status, source, rule_id, host, user, src_ip, dst_ip, details, raw_payload, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE status=VALUES(status), details=VALUES(details);
                    """
                    cursor.execute(query, (alert_id, title, severity, status, source, rule_id, host, user, src_ip, dst_ip, details, raw_payload, ts))
                else:
                    query = """
                        INSERT INTO alerts (alert_id, title, severity, status, source, rule_id, host, user, src_ip, dst_ip, details, raw_payload, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, details=excluded.details;
                    """
                    cursor.execute(query, (alert_id, title, severity, status, source, rule_id, host, user, src_ip, dst_ip, details, raw_payload, ts))
                    conn.commit()
                return True
            finally:
                cursor.close()
                conn.close()

    def get_all_alerts(self, limit=500):
        """Retrieve all alerts."""
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(f"SELECT * FROM alerts ORDER BY id DESC LIMIT {int(limit)};")
                rows = cursor.fetchall()
                alerts = []
                for r in rows:
                    item = dict(r)
                    if item.get("raw_payload"):
                        try:
                            payload = json.loads(item["raw_payload"])
                            payload["status"] = item["status"]
                            alerts.append(payload)
                            continue
                        except Exception:
                            pass
                    alerts.append(item)
                return alerts
            finally:
                cursor.close()
                conn.close()

    def update_alert_status(self, alert_id, new_status):
        """Update status for a specific alert."""
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    cursor.execute("UPDATE alerts SET status = %s WHERE alert_id = %s;", (new_status, alert_id))
                else:
                    cursor.execute("UPDATE alerts SET status = ? WHERE alert_id = ?;", (new_status, alert_id))
                    conn.commit()
                return True
            finally:
                cursor.close()
                conn.close()

    # ── AUDIT LOG OPERATIONS ─────────────────────────────────────

    def log_audit_event(self, username, action, details="", ip="127.0.0.1"):
        """Append an audit log entry into the SQL database."""
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(details, (dict, list)):
            details = json.dumps(details)
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    cursor.execute("INSERT INTO audit_logs (timestamp, username, action, details, ip) VALUES (%s, %s, %s, %s, %s);",
                                   (ts, username, action, str(details), ip))
                else:
                    cursor.execute("INSERT INTO audit_logs (timestamp, username, action, details, ip) VALUES (?, ?, ?, ?, ?);",
                                   (ts, username, action, str(details), ip))
                    conn.commit()
                return True
            finally:
                cursor.close()
                conn.close()

    def get_audit_logs(self, limit=200):
        """Get recent audit logs."""
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(f"SELECT * FROM audit_logs ORDER BY id DESC LIMIT {int(limit)};")
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                cursor.close()
                conn.close()

    # ── BLOCKED IPS OPERATIONS ───────────────────────────────────

    def get_blocked_ips(self):
        """Retrieve list of blocked IPs."""
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ip, reason, blocked_by, blocked_at FROM blocked_ips ORDER BY id DESC;")
                return [dict(r) for r in cursor.fetchall()]
            finally:
                cursor.close()
                conn.close()

    def add_blocked_ip(self, ip, reason="Threat Intelligence Match", blocked_by="SOAR Playbook", blocked_at=None):
        """Add IP to blocked list."""
        if not blocked_at:
            blocked_at = datetime.utcnow().isoformat()
        with _DB_LOCK:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if self.is_mysql:
                    cursor.execute("INSERT INTO blocked_ips (ip, reason, blocked_by, blocked_at) VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE reason=VALUES(reason);",
                                   (ip, reason, blocked_by, blocked_at))
                else:
                    cursor.execute("INSERT INTO blocked_ips (ip, reason, blocked_by, blocked_at) VALUES (?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason;",
                                   (ip, reason, blocked_by, blocked_at))
                    conn.commit()
                return True
            finally:
                cursor.close()
                conn.close()


# Singleton Instance for the Platform
db = DatabaseManager()
