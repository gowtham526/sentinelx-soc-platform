"""Shift Handoff System.

Structured shift change records so incoming analysts have full context
on active cases, pending actions, and the outgoing analyst's notes.
Handoffs are stored in append-only JSONL for audit integrity.
"""
import json
import os
import time
import uuid
import threading

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_HANDOFF_FILE = os.path.join(_DIR, "shift_handoffs.jsonl")
_ALERTS_FILE = os.path.join(_DIR, "alerts.json")
_CASES_FILE = os.path.join(_DIR, "cases.json")
_lock = threading.Lock()


def _load_json(path, default=None):
    if default is None:
        default = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _snapshot_active_cases() -> list:
    """Capture current state of open cases for handoff context."""
    cases = _load_json(_CASES_FILE)
    active = []
    for c in cases:
        status = c.get("status", "open")
        if status in ("closed", "resolved"):
            continue
        active.append({
            "case_id": c.get("id", "?"),
            "title": c.get("title", c.get("tactic", "?")),
            "severity": c.get("severity", "?"),
            "host": c.get("host", "?"),
            "assigned_to": c.get("assigned_to"),
            "status": status,
            "alert_count": len(c.get("alert_ids", [])),
            "created_at": c.get("created_at", "?"),
        })
    return active


def _snapshot_recent_alerts(hours: int = 8) -> dict:
    """Summary of alerts from the last shift period."""
    alerts = _load_json(_ALERTS_FILE)
    cutoff = time.time() - (hours * 3600)
    recent = [a for a in alerts if a.get("ts", 0) > cutoff]
    
    by_severity = {}
    for a in recent:
        sev = a.get("severity", "low")
        by_severity[sev] = by_severity.get(sev, 0) + 1
    
    return {
        "period_hours": hours,
        "total": len(recent),
        "by_severity": by_severity,
    }


def create_handoff(outgoing_analyst: str, incoming_analyst: str = None,
                   notes: str = "", pending_actions: list = None,
                   case_notes: dict = None) -> dict:
    """Create a shift handoff record.
    
    Args:
        outgoing_analyst: Username of the analyst ending their shift
        incoming_analyst: Username of the incoming analyst (optional)
        notes: Free-text shift summary
        pending_actions: List of strings describing pending items
        case_notes: Dict of {case_id: "note about this case"}
    
    Returns: The handoff record
    """
    if pending_actions is None:
        pending_actions = []
    if case_notes is None:
        case_notes = {}
    
    active_cases = _snapshot_active_cases()
    alert_summary = _snapshot_recent_alerts()
    
    # Enrich active cases with analyst's notes
    for case in active_cases:
        cid = case.get("case_id", "")
        if cid in case_notes:
            case["handoff_note"] = case_notes[cid]
    
    handoff = {
        "shift_id": f"SH-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ts": time.time(),
        "outgoing_analyst": outgoing_analyst,
        "incoming_analyst": incoming_analyst or "(unspecified)",
        "notes": notes,
        "pending_actions": pending_actions,
        "active_cases": active_cases,
        "alert_summary": alert_summary,
    }
    
    # Append to JSONL
    os.makedirs(os.path.dirname(_HANDOFF_FILE), exist_ok=True)
    with _lock:
        with open(_HANDOFF_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(handoff, ensure_ascii=False) + "\n")
    
    return handoff


def get_latest_handoff() -> dict | None:
    """Get the most recent handoff record."""
    if not os.path.exists(_HANDOFF_FILE):
        return None
    last = None
    with open(_HANDOFF_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    continue
    return last


def get_handoff_history(limit: int = 20) -> list:
    """Get recent handoff records."""
    if not os.path.exists(_HANDOFF_FILE):
        return []
    records = []
    with open(_HANDOFF_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    # Return most recent first
    records.reverse()
    return records[:limit]
