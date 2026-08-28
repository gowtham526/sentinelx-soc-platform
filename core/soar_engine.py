"""
SentinelX SOAR Engine v1.0
============================
Real playbook orchestration — evaluates every enabled playbook against an
alert, executes auto:true actions immediately, and queues auto:false /
requires_approval:true actions for a human to approve or reject.

This is deliberately separate from the existing AUTOMATION_ENGINE page /
/api/framework/playbook route, which is retrospective reporting ("what % of
standard response steps happened after the fact") — it doesn't decide or
execute anything conditionally. This module is the real thing: it makes a
decision, and it can act on that decision.

HOOK POINT
-----------
Called from core/alert_pipeline.py's process_alert(), immediately after
Stage 4 (severity assignment) and before persistence — so playbooks always
see the final, correct severity, never a pre-scoring guess. (This is the
one thing that was missing when this file was first drafted — the engine
existed and worked standalone, but nothing ever called run_playbooks() from
the actual alert flow. Fixed in the same change that added this file.)

DATA MODEL
-----------
data/playbooks.json        — the playbook definitions (see PLAYBOOK SHAPE
                              below)
data/playbook_runs.json    — audit log: every evaluation, matched or not,
                              which actions fired, outcome. Written on every
                              single alert regardless of match — this IS the
                              audit trail for the whole subsystem.
data/pending_approvals.json — actions queued because requires_approval:true,
                              waiting on a human with admin role.

PLAYBOOK SHAPE
----------------
{
  "playbook_id": "PB-001",
  "name": "...",
  "enabled": true,
  "trigger": {"mitre_tactic": "Credential Access", "min_severity": "HIGH"},
  "conditions": [
    {"field": "vt_score", "op": ">=", "value": 5},
    {"field": "host", "op": "not_in", "value": ["domain-controller-01"]}
  ],
  "actions": [
    {"type": "block_ip", "auto": true, "params": {}},
    {"type": "isolate_host", "auto": false, "params": {}, "requires_approval": true}
  ],
  "created_by": "admin",
  "created_at": "..."
}
"""

import os
import json
import time
import threading
from datetime import datetime

from core import response_actions as ra

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

PLAYBOOK_FILE   = os.path.join(DATA_DIR, "playbooks.json")
RUNS_FILE       = os.path.join(DATA_DIR, "playbook_runs.json")
APPROVALS_FILE  = os.path.join(DATA_DIR, "pending_approvals.json")

_file_lock = threading.Lock()

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _load(path, default=None):
    if default is None:
        default = []
    if not os.path.exists(path):
        return default
    with _file_lock:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default


def _save(path, data, limit=None):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _file_lock:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data[:limit] if limit else data, f, indent=2, ensure_ascii=False)


for _f in (PLAYBOOK_FILE, RUNS_FILE, APPROVALS_FILE):
    if not os.path.exists(_f):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(_f, "w", encoding="utf-8") as _fp:
            json.dump([], _fp)


# ─────────────────────────────────────────────────────────────
# CONDITION EVALUATION
# ─────────────────────────────────────────────────────────────

def _get_field(alert: dict, field: str):
    """Supports a couple of derived fields beyond a flat alert.get()."""
    if field == "vt_score":
        return alert.get("vt_score", 0)
    if field == "abuse_score":
        return alert.get("abuse_score", 0)
    return alert.get(field)


def _eval_condition(alert: dict, cond: dict) -> bool:
    field = cond.get("field", "")
    op    = cond.get("op", "==")
    value = cond.get("value")
    actual = _get_field(alert, field)

    try:
        if op == "==":       return actual == value
        if op == "!=":       return actual != value
        if op in (">=", "<=", ">", "<"):
            try:
                num_actual = float(actual if actual is not None else 0)
                num_value  = float(value if value is not None else 0)
            except (TypeError, ValueError):
                # Non-numeric values: fall back to string comparison
                str_actual = str(actual or "")
                str_value  = str(value or "")
                if op == ">=":  return str_actual >= str_value
                if op == "<=":  return str_actual <= str_value
                if op == ">":   return str_actual > str_value
                if op == "<":   return str_actual < str_value
            else:
                if op == ">=":  return num_actual >= num_value
                if op == "<=":  return num_actual <= num_value
                if op == ">":   return num_actual > num_value
                if op == "<":   return num_actual < num_value
        if op == "in":       return actual in (value or [])
        if op == "not_in":   return actual not in (value or [])
        if op == "contains": return str(value or "").lower() in str(actual or "").lower()
    except (TypeError, ValueError):
        return False
    return False


def _trigger_matches(alert: dict, trigger: dict) -> bool:
    if not trigger:
        return True  # no trigger filter = matches every alert (conditions still apply)
    tactic = trigger.get("mitre_tactic")
    if tactic and alert.get("mitre_tactic") != tactic:
        return False
    min_sev = trigger.get("min_severity")
    if min_sev:
        alert_rank = _SEVERITY_RANK.get(alert.get("severity", "LOW"), 0)
        min_rank   = _SEVERITY_RANK.get(min_sev, 0)
        if alert_rank < min_rank:
            return False
    return True


# ─────────────────────────────────────────────────────────────
# ACTION EXECUTION
# ─────────────────────────────────────────────────────────────

def _kill_process_action(alert: dict, params: dict, triggered_by: str) -> dict:
    """Extract PID from alert detail text or params and kill via psutil."""
    import re
    pid = params.get("pid")
    if not pid:
        # Try to extract PID from alert detail text (e.g. "PID 1234")
        detail = alert.get("detail", "")
        match = re.search(r'PID\s+(\d+)', detail)
        if match:
            pid = int(match.group(1))
    if not pid:
        return {"success": False, "error": "No PID available in alert or params"}
    try:
        import psutil
        proc = psutil.Process(int(pid))
        proc_name = proc.name()
        proc.kill()
        return {"success": True, "killed_pid": int(pid), "process_name": proc_name,
                "triggered_by": triggered_by}
    except Exception as e:
        return {"success": False, "error": f"Failed to kill PID {pid}: {e}"}


_ACTION_DISPATCH = {
    "block_ip":       lambda alert, params, tb: ra.block_ip(
                            alert.get("ip", params.get("ip", "")),
                            reason=f"Playbook action on alert {alert.get('id','')}",
                            triggered_by=tb),
    "kill_process":   lambda alert, params, tb: _kill_process_action(alert, params, tb),
    "isolate_host":   lambda alert, params, tb: ra.isolate_host(
                            alert.get("host", params.get("host", "unknown")),
                            reason=f"Playbook action on alert {alert.get('id','')}",
                            allow_ips=params.get("allow_ips", []),
                            triggered_by=tb),
    "disable_user":   lambda alert, params, tb: ra.disable_user(
                            alert.get("user", params.get("username", "unknown")),
                            host=alert.get("host", ""),
                            reason=f"Playbook action on alert {alert.get('id','')}",
                            triggered_by=tb),
    "quarantine_file":lambda alert, params, tb: ra.quarantine_file(
                            params.get("path", ""),
                            reason=f"Playbook action on alert {alert.get('id','')}",
                            triggered_by=tb),
    "create_case":    lambda alert, params, tb: ra.create_case(
                            alert, priority=params.get("priority", "P2"), triggered_by=tb),
    "notify":         lambda alert, params, tb: ra.notify(
                            params.get("message") or f"Playbook fired on alert {alert.get('id','')} ({alert.get('event','')})",
                            channel=params.get("channel", "console"), triggered_by=tb),
}


def _execute_action(alert: dict, action: dict, playbook_id: str) -> dict:
    action_type = action.get("type", "")
    params      = action.get("params", {}) or {}
    fn = _ACTION_DISPATCH.get(action_type)
    if not fn:
        return {"success": False, "error": f"Unknown action type: {action_type}"}
    try:
        return fn(alert, params, f"playbook:{playbook_id}")
    except Exception as e:
        return {"success": False, "error": str(e)}


def _queue_approval(alert: dict, action: dict, playbook_id: str, playbook_name: str):
    approvals = _load(APPROVALS_FILE)
    entry = {
        "approval_id":  f"APR-{int(time.time()*1000)}",
        "status":       "PENDING",
        "playbook_id":  playbook_id,
        "playbook_name":playbook_name,
        "action_type":  action.get("type"),
        "action_params":action.get("params", {}),
        "alert_id":     alert.get("id", ""),
        "alert_event":  alert.get("event", ""),
        "alert_severity": alert.get("severity", ""),
        "host":         alert.get("host", ""),
        "created_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "decided_by":   "",
        "decided_at":   "",
        "decision_reason": "",
    }
    approvals.insert(0, entry)
    _save(APPROVALS_FILE, approvals, 500)

    try:
        from integrations.notifier import notify_alert
        notify_alert({"severity": "HIGH", "event": f"Playbook approval needed: {action.get('type')}",
                      "host": alert.get("host", ""), "user": alert.get("user", ""),
                      "timestamp": entry["created_at"],
                      "detail": f"Playbook '{playbook_name}' wants to run "
                                f"{action.get('type')} on alert {alert.get('id','')} "
                                f"and needs admin approval."})
    except Exception:
        pass  # notification is a convenience here, never blocks queueing

    return entry


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────

def run_playbooks(alert: dict) -> list:
    """
    Evaluates every enabled playbook against `alert`. Returns the list of
    playbook_ids that matched. Always writes a playbook_runs.json entry —
    matched or not — that entry is the audit trail this whole subsystem
    exists to provide.
    """
    playbooks = _load(PLAYBOOK_FILE)
    matched_ids = []

    for pb in playbooks:
        if not pb.get("enabled", True):
            continue

        pb_id   = pb.get("playbook_id", "?")
        pb_name = pb.get("name", "Unnamed Playbook")

        trigger_ok = _trigger_matches(alert, pb.get("trigger", {}))
        conditions_ok = trigger_ok and all(
            _eval_condition(alert, c) for c in pb.get("conditions", [])
        )
        is_match = trigger_ok and conditions_ok

        actions_fired = []
        actions_queued = []

        if is_match:
            matched_ids.append(pb_id)
            for action in pb.get("actions", []):
                if action.get("requires_approval") or action.get("auto") is False:
                    entry = _queue_approval(alert, action, pb_id, pb_name)
                    actions_queued.append({"action": action.get("type"),
                                            "approval_id": entry["approval_id"]})
                else:
                    result = _execute_action(alert, action, pb_id)
                    actions_fired.append({"action": action.get("type"),
                                           "success": result.get("success", False),
                                           "detail": result})

        # Always log the evaluation — matched or not.
        runs = _load(RUNS_FILE)
        runs.insert(0, {
            "run_id":       f"RUN-{int(time.time()*1000000)}",
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "playbook_id":  pb_id,
            "playbook_name":pb_name,
            "alert_id":     alert.get("id", ""),
            "alert_event":  alert.get("event", ""),
            "matched":      is_match,
            "trigger_ok":   trigger_ok,
            "conditions_ok":conditions_ok,
            "actions_fired": actions_fired,
            "actions_queued": actions_queued,
        })
        _save(RUNS_FILE, runs, 2000)

    return matched_ids


def test_playbook(playbook: dict, alert: dict) -> dict:
    """Dry-run: evaluates a playbook (which may not even be saved yet)
    against a sample alert with NO side effects — no actions execute, no
    approvals queued, nothing written to disk. Used by the 'test' button
    in the Playbook Builder before an analyst enables a new playbook."""
    trigger_ok = _trigger_matches(alert, playbook.get("trigger", {}))
    condition_results = [
        {"condition": c, "result": _eval_condition(alert, c)}
        for c in playbook.get("conditions", [])
    ]
    conditions_ok = trigger_ok and all(c["result"] for c in condition_results)
    would_fire = trigger_ok and conditions_ok

    return {
        "would_match":  would_fire,
        "trigger_ok":   trigger_ok,
        "condition_results": condition_results,
        "actions_that_would_run": [
            {"type": a.get("type"),
             "would_auto_execute": would_fire and not (a.get("requires_approval") or a.get("auto") is False),
             "would_need_approval": would_fire and (a.get("requires_approval") or a.get("auto") is False)}
            for a in playbook.get("actions", [])
        ] if would_fire else [],
    }
