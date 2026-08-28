"""
SentinelX Audit Log
=====================
Tracks what ANALYSTS do — logins, blocking an IP, killing a process,
resolving an alert, editing a custom rule — separately from the alert/
detection data itself. This is standard in any real SOC platform:
detection data answers "what happened on the network," the audit log
answers "who did what, when, in this tool." Different question, different
file, so one can't get lost inside the other.

Every write is append-only (data/audit_log.jsonl — JSON-lines, one action
per line) so it can't accidentally get overwritten wholesale the way a
single JSON array file could with a bad save. Never raises — a logging
failure should never block the action it's trying to record.
"""

import os
import json
import time
from datetime import datetime
import threading
import hashlib

_CHAIN_HASH = None  # in-memory previous hash; initialized on first write

def _compute_chain_hash(prev_hash: str, record_json: str) -> str:
    """SHA-256 hash linking this record to the previous one."""
    return hashlib.sha256(f"{prev_hash}:{record_json}".encode("utf-8")).hexdigest()

def _get_last_hash() -> str:
    """Read the hash from the last line of the audit log, or return genesis hash."""
    global _CHAIN_HASH
    if _CHAIN_HASH is not None:
        return _CHAIN_HASH
    genesis = hashlib.sha256(b"SENTINELX_GENESIS").hexdigest()
    if not os.path.exists(_LOG_PATH):
        _CHAIN_HASH = genesis
        return genesis
    try:
        with open(_LOG_PATH, "r", encoding="utf-8") as f:
            last_line = None
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
            if last_line:
                rec = json.loads(last_line)
                _CHAIN_HASH = rec.get("chain_hash", genesis)
                return _CHAIN_HASH
    except Exception:
        pass
    _CHAIN_HASH = genesis
    return genesis

_LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "audit_log.jsonl")
_log_lock = threading.Lock()


def log_action(username: str, action: str, details: dict = None, ip: str = None):
    """
    Append one audit record. Fire-and-forget by design — call this from a
    route right after the action succeeds; a failure here prints a warning
    but never raises back into the caller.

    action examples: "login", "block_ip", "kill_process", "resolve_alert",
    "create_custom_rule", "delete_custom_rule", "close_incident",
    "ai_analysis_requested", "ai_report_generated"
    """
    try:
        os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)
        record = {
            "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ts":       time.time(),
            "user":     username or "unknown",
            "action":   action,
            "details":  details or {},
            "ip":       ip,
        }
        with _log_lock:
            prev = _get_last_hash()
            record_json = json.dumps(record, ensure_ascii=False)
            chain_hash = _compute_chain_hash(prev, record_json)
            record["prev_hash"] = prev
            record["chain_hash"] = chain_hash
            with open(_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            global _CHAIN_HASH
            _CHAIN_HASH = chain_hash
    except Exception as e:
        print(f"[AuditLog] WARNING: failed to write audit record: {e}")


def read_recent(limit: int = 200, user: str = None, action: str = None) -> list:
    """Returns the most recent audit records, newest first. Never raises —
    returns [] if the log doesn't exist yet or can't be read."""
    if not os.path.exists(_LOG_PATH):
        return []
    try:
        records = []
        with open(_LOG_PATH, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if user and rec.get("user") != user:
                    continue
                if action and rec.get("action") != action:
                    continue
                records.append(rec)
        records.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return records[:limit]
    except Exception as e:
        print(f"[AuditLog] WARNING: failed to read audit log: {e}")
        return []

def verify_chain() -> dict:
    """Verify the integrity of the audit log hash chain.
    Returns {valid: bool, total_records: int, errors: list[str]}."""
    genesis = hashlib.sha256(b"SENTINELX_GENESIS").hexdigest()
    errors = []
    total = 0
    prev_hash = genesis
    if not os.path.exists(_LOG_PATH):
        return {"valid": True, "total_records": 0, "errors": []}
    with open(_LOG_PATH, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Line {i}: malformed JSON")
                continue
            stored_prev = rec.get("prev_hash")
            stored_chain = rec.get("chain_hash")
            if stored_prev is None or stored_chain is None:
                # Legacy record without chain — skip validation
                continue
            if stored_prev != prev_hash:
                errors.append(f"Line {i}: prev_hash mismatch (expected {prev_hash[:12]}..., got {stored_prev[:12]}...)")
            # Recompute: strip chain fields, compute hash
            verify_rec = {k: v for k, v in rec.items() if k not in ("prev_hash", "chain_hash")}
            verify_json = json.dumps(verify_rec, ensure_ascii=False)
            expected = _compute_chain_hash(stored_prev, verify_json)
            if expected != stored_chain:
                errors.append(f"Line {i}: chain_hash mismatch")
            prev_hash = stored_chain
    return {"valid": len(errors) == 0, "total_records": total, "errors": errors}
