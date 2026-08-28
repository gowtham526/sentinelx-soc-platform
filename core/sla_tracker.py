"""SLA Tracker & Escalation Engine.

Tracks Mean Time to Acknowledge (MTTA) and Mean Time to Resolve (MTTR)
per alert severity. Auto-flags alerts approaching SLA breach and can
escalate severity when SLA is exceeded.
"""
import json
import os
import time
import threading

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_SLA_STATE_FILE = os.path.join(_DIR, "sla_state.json")
_ALERTS_FILE = os.path.join(_DIR, "alerts.json")
_lock = threading.Lock()

# SLA definitions: minutes to acknowledge / minutes to resolve
_SLA_DEFAULTS = {
    "critical": {"ack_minutes": 15,   "resolve_minutes": 60},
    "high":     {"ack_minutes": 60,   "resolve_minutes": 240},
    "medium":   {"ack_minutes": 240,  "resolve_minutes": 1440},
    "low":      {"ack_minutes": 1440, "resolve_minutes": 4320},
}

_BREACH_WARNING_THRESHOLD = 0.75  # warn at 75% of SLA window


def _load_sla_state() -> dict:
    try:
        with open(_SLA_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_sla_state(state: dict):
    os.makedirs(os.path.dirname(_SLA_STATE_FILE), exist_ok=True)
    with _lock:
        with open(_SLA_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)


def _load_alerts() -> list:
    try:
        with open(_ALERTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def track_new_alert(alert_id: str, severity: str):
    """Start SLA clock for a new alert."""
    state = _load_sla_state()
    if alert_id not in state:
        state[alert_id] = {
            "severity": severity.lower(),
            "created_at": time.time(),
            "acknowledged_at": None,
            "resolved_at": None,
            "disposition": None,
            "escalated": False,
        }
        _save_sla_state(state)


def acknowledge_alert(alert_id: str, analyst: str = None) -> dict:
    """Mark an alert as acknowledged (analyst has seen it)."""
    state = _load_sla_state()
    if alert_id not in state:
        state[alert_id] = {
            "severity": "unknown",
            "created_at": time.time(),
            "acknowledged_at": None,
            "resolved_at": None,
            "disposition": None,
            "escalated": False,
        }
    if state[alert_id]["acknowledged_at"] is None:
        state[alert_id]["acknowledged_at"] = time.time()
        state[alert_id]["acknowledged_by"] = analyst
    _save_sla_state(state)
    return state[alert_id]


def resolve_alert(alert_id: str, disposition: str = "resolved",
                  analyst: str = None) -> dict:
    """Mark an alert as resolved with a disposition.
    
    Dispositions: resolved, false_positive, escalated, duplicate, informational
    """
    valid_dispositions = {"resolved", "false_positive", "escalated",
                          "duplicate", "informational"}
    if disposition not in valid_dispositions:
        disposition = "resolved"
    
    state = _load_sla_state()
    if alert_id not in state:
        state[alert_id] = {
            "severity": "unknown",
            "created_at": time.time(),
            "acknowledged_at": time.time(),
            "resolved_at": None,
            "disposition": None,
            "escalated": False,
        }
    # Auto-acknowledge if not already
    if state[alert_id]["acknowledged_at"] is None:
        state[alert_id]["acknowledged_at"] = time.time()
    state[alert_id]["resolved_at"] = time.time()
    state[alert_id]["disposition"] = disposition
    state[alert_id]["resolved_by"] = analyst
    _save_sla_state(state)
    return state[alert_id]


def get_sla_status() -> list:
    """Get SLA status for all unresolved alerts."""
    state = _load_sla_state()
    now = time.time()
    results = []
    
    for alert_id, info in state.items():
        if info.get("resolved_at"):
            continue  # skip resolved
        
        severity = info.get("severity", "medium")
        sla = _SLA_DEFAULTS.get(severity, _SLA_DEFAULTS["medium"])
        created = info.get("created_at", now)
        ack_at = info.get("acknowledged_at")
        
        elapsed_min = (now - created) / 60
        
        # Acknowledgment SLA
        ack_sla_min = sla["ack_minutes"]
        ack_status = "met"
        ack_remaining_min = 0
        if ack_at is None:
            ack_remaining_min = ack_sla_min - elapsed_min
            if elapsed_min > ack_sla_min:
                ack_status = "breached"
            elif elapsed_min > ack_sla_min * _BREACH_WARNING_THRESHOLD:
                ack_status = "warning"
            else:
                ack_status = "ok"
        
        # Resolution SLA
        resolve_sla_min = sla["resolve_minutes"]
        resolve_remaining_min = resolve_sla_min - elapsed_min
        if elapsed_min > resolve_sla_min:
            resolve_status = "breached"
        elif elapsed_min > resolve_sla_min * _BREACH_WARNING_THRESHOLD:
            resolve_status = "warning"
        else:
            resolve_status = "ok"
        
        results.append({
            "alert_id": alert_id,
            "severity": severity,
            "age_minutes": round(elapsed_min, 1),
            "acknowledged": ack_at is not None,
            "ack_sla": {
                "target_minutes": ack_sla_min,
                "status": ack_status,
                "remaining_minutes": round(max(0, ack_remaining_min), 1),
            },
            "resolve_sla": {
                "target_minutes": resolve_sla_min,
                "status": resolve_status,
                "remaining_minutes": round(max(0, resolve_remaining_min), 1),
            },
        })
    
    # Sort: breached first, then warning, then by remaining time
    priority = {"breached": 0, "warning": 1, "ok": 2, "met": 3}
    results.sort(key=lambda x: (
        min(priority.get(x["ack_sla"]["status"], 3),
            priority.get(x["resolve_sla"]["status"], 3)),
        x["resolve_sla"]["remaining_minutes"]
    ))
    return results


def get_sla_report(days: int = 7) -> dict:
    """Generate SLA compliance report."""
    state = _load_sla_state()
    cutoff = time.time() - (days * 86400)
    
    by_severity = {}
    for alert_id, info in state.items():
        if info.get("created_at", 0) < cutoff:
            continue
        if not info.get("resolved_at"):
            continue
        
        sev = info.get("severity", "medium")
        if sev not in by_severity:
            by_severity[sev] = {
                "total": 0, "ack_met": 0, "resolve_met": 0,
                "mtta_sum": 0, "mttr_sum": 0,
                "dispositions": {},
            }
        
        stats = by_severity[sev]
        stats["total"] += 1
        sla = _SLA_DEFAULTS.get(sev, _SLA_DEFAULTS["medium"])
        
        created = info["created_at"]
        ack_at = info.get("acknowledged_at", created)
        resolved_at = info["resolved_at"]
        
        mtta = (ack_at - created) / 60  # minutes
        mttr = (resolved_at - created) / 60
        
        stats["mtta_sum"] += mtta
        stats["mttr_sum"] += mttr
        
        if mtta <= sla["ack_minutes"]:
            stats["ack_met"] += 1
        if mttr <= sla["resolve_minutes"]:
            stats["resolve_met"] += 1
        
        disp = info.get("disposition", "resolved")
        stats["dispositions"][disp] = stats["dispositions"].get(disp, 0) + 1
    
    report = {"period_days": days, "by_severity": {}}
    for sev, stats in by_severity.items():
        total = stats["total"]
        report["by_severity"][sev] = {
            "total_resolved": total,
            "ack_sla_met_pct": round(stats["ack_met"] / total * 100, 1) if total else 0,
            "resolve_sla_met_pct": round(stats["resolve_met"] / total * 100, 1) if total else 0,
            "avg_mtta_minutes": round(stats["mtta_sum"] / total, 1) if total else 0,
            "avg_mttr_minutes": round(stats["mttr_sum"] / total, 1) if total else 0,
            "dispositions": stats["dispositions"],
        }
    return report
