"""Alert Suppression Rules Engine.

Allows analysts to create time-limited rules that auto-suppress known-benign
alert patterns without touching detector code. Every rule MUST have an expiry.
Suppressed alerts are logged separately for audit.
"""
import json
import os
import re
import threading
import time
import uuid

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_RULES_FILE = os.path.join(_DIR, "suppression_rules.json")
_SUPPRESSED_FILE = os.path.join(_DIR, "suppressed_alerts.json")
_lock = threading.Lock()
_MAX_EXPIRY_DAYS = 30


def _load(path, default=None):
    if default is None:
        default = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _lock:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def _match_condition(alert: dict, condition: dict) -> bool:
    """Check if a single condition matches an alert."""
    field = condition.get("field", "")
    operator = condition.get("operator", "equals")
    value = condition.get("value", "")
    
    alert_value = str(alert.get(field, "")).lower()
    match_value = str(value).lower()
    
    if operator == "equals":
        return alert_value == match_value
    elif operator == "contains":
        return match_value in alert_value
    elif operator == "regex":
        try:
            return bool(re.search(value, str(alert.get(field, "")), re.IGNORECASE))
        except re.error:
            return False
    elif operator == "in_list":
        items = [v.strip().lower() for v in str(value).split(",")]
        return alert_value in items
    elif operator == "not_equals":
        return alert_value != match_value
    return False


def check_suppression(alert: dict) -> dict | None:
    """Check if an alert matches any active suppression rule.
    
    Returns the matching rule if suppressed, None if the alert should pass through.
    Also logs suppressed alerts to the suppressed file.
    """
    rules = get_active_rules()
    for rule in rules:
        conditions = rule.get("conditions", [])
        if not conditions:
            continue
        # ALL conditions must match (AND logic)
        if all(_match_condition(alert, c) for c in conditions):
            # Log the suppression
            _log_suppressed(alert, rule)
            # Increment rule hit counter
            _increment_hit_count(rule["id"])
            return rule
    return None


def _log_suppressed(alert: dict, rule: dict):
    """Append suppressed alert to audit file."""
    suppressed = _load(_SUPPRESSED_FILE)
    suppressed.append({
        "alert_id": alert.get("id", "?"),
        "event": alert.get("event", "?"),
        "host": alert.get("host", "?"),
        "severity": alert.get("severity", "?"),
        "rule_id": rule["id"],
        "rule_name": rule.get("name", "?"),
        "suppressed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ts": time.time(),
    })
    # Keep last 5000 entries max
    if len(suppressed) > 5000:
        suppressed = suppressed[-5000:]
    _save(_SUPPRESSED_FILE, suppressed)


def _increment_hit_count(rule_id: str):
    """Increment the hit counter for a rule."""
    rules = _load(_RULES_FILE)
    for r in rules:
        if r["id"] == rule_id:
            r["hit_count"] = r.get("hit_count", 0) + 1
            r["last_hit"] = time.strftime("%Y-%m-%d %H:%M:%S")
            break
    _save(_RULES_FILE, rules)


def get_active_rules() -> list:
    """Return all non-expired suppression rules."""
    now = time.time()
    rules = _load(_RULES_FILE)
    return [r for r in rules if r.get("expires_at", 0) > now and r.get("active", True)]


def get_all_rules() -> list:
    """Return all rules (including expired), with an 'expired' flag."""
    now = time.time()
    rules = _load(_RULES_FILE)
    for r in rules:
        r["expired"] = r.get("expires_at", 0) <= now
    return rules


def create_rule(name: str, conditions: list, action: str = "suppress",
                expires_hours: float = 24, created_by: str = "system",
                reason: str = "") -> dict:
    """Create a new suppression rule.
    
    Args:
        name: Human-readable rule name
        conditions: List of {field, operator, value} dicts
        action: 'suppress' (drop alert) or 'lower_severity' (downgrade to low)
        expires_hours: Hours until rule expires (max 720 = 30 days)
        created_by: Username who created the rule
        reason: Why this rule exists
    
    Returns: The created rule dict
    """
    if not name or not conditions:
        raise ValueError("Rule must have a name and at least one condition")
    if action not in ("suppress", "lower_severity"):
        raise ValueError("Action must be 'suppress' or 'lower_severity'")
    
    expires_hours = min(expires_hours, _MAX_EXPIRY_DAYS * 24)
    
    rule = {
        "id": f"SR-{uuid.uuid4().hex[:8].upper()}",
        "name": name,
        "conditions": conditions,
        "action": action,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_by": created_by,
        "expires_at": time.time() + (expires_hours * 3600),
        "expires_hours": expires_hours,
        "reason": reason,
        "active": True,
        "hit_count": 0,
        "last_hit": None,
    }
    
    rules = _load(_RULES_FILE)
    rules.append(rule)
    _save(_RULES_FILE, rules)
    return rule


def delete_rule(rule_id: str) -> bool:
    """Delete a suppression rule by ID."""
    rules = _load(_RULES_FILE)
    original_len = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) < original_len:
        _save(_RULES_FILE, rules)
        return True
    return False


def get_suppression_stats(days: int = 7) -> dict:
    """Get suppression statistics."""
    cutoff = time.time() - (days * 86400)
    suppressed = _load(_SUPPRESSED_FILE)
    recent = [s for s in suppressed if s.get("ts", 0) > cutoff]
    
    # Count per rule
    by_rule = {}
    for s in recent:
        rid = s.get("rule_id", "?")
        rname = s.get("rule_name", "?")
        if rid not in by_rule:
            by_rule[rid] = {"rule_id": rid, "rule_name": rname, "count": 0}
        by_rule[rid]["count"] += 1
    
    return {
        "period_days": days,
        "total_suppressed": len(recent),
        "by_rule": sorted(by_rule.values(), key=lambda x: x["count"], reverse=True),
        "active_rules": len(get_active_rules()),
    }
