"""
SentinelX Response Actions v1.1
=================================
Shared, structured response-action functions. Every action here follows the
same pattern already used by kill_process and firewall block in app.py:
native tool first, subprocess fallback, always return a structured result
dict (never raise), always log the outcome.

WHY THESE LIVE HERE, NOT IN app.py
------------------------------------
Both app.py's Flask routes (a human clicking a button) AND core/soar_engine.py
(a playbook auto-executing) need to call the exact same underlying action —
duplicating the logic in two places is how "block IP" ended up implemented
several different ways across the frontend before. These functions take
plain arguments, need no Flask request context, and can be called from
anywhere.

v1.1 changes (fixes found reviewing v1.0 before wiring it in):
  - isolate_host()/restore_host(): v1.0 only ever deleted 4 fixed rule
    names on restore, but isolate_host() can create a variable number of
    per-IP allow rules depending on allow_ips — calling isolate twice, or
    isolating then restoring, left orphaned firewall rules behind forever.
    Now tracks exactly which rule names were created per host in
    data/isolation_state.json and restore_host() deletes precisely those.
  - create_case(): v1.0 always created a new case with no de-dup check —
    a playbook firing repeatedly for the same ongoing incident would spam
    duplicate cases, and diverged from alert_pipeline.py's own case-folding
    logic. Now checks for an existing fresh OPEN case on the same
    host+tactic first (lazy-imports core.alert_pipeline to reuse its
    _load/_save/CASE_FILE rather than a third copy of the same logic).
  - notify(): v1.0 was console-only despite integrations/notifier.py
    already existing with real email/Slack/Teams support. Now delegates
    to it for real channels, console remains the default/fallback.
  - Every action now also writes to core.audit_log (lazy-imported) so
    playbook-triggered actions show up in the same audit trail as
    analyst-triggered ones, not just this module's own action-specific log.
"""

import os
import json
import time
import socket
import hashlib
import shutil
import subprocess
import threading
from datetime import datetime

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
BASE_DIR   = os.path.dirname(BASE_DIR)  # up from core/ to project root
DATA_DIR   = os.path.join(BASE_DIR, "data")
ALERT_FILE = os.path.join(DATA_DIR, "alerts.json")
BLOCK_FILE = os.path.join(DATA_DIR, "blocked_ips.json")
FW_FILE    = os.path.join(DATA_DIR, "firewall_log.json")
RESPONSE_LOG_FILE   = os.path.join(DATA_DIR, "response_actions_log.json")
QUARANTINE_DIR      = os.path.join(DATA_DIR, "quarantine")
ISOLATION_STATE_FILE = os.path.join(DATA_DIR, "isolation_state.json")

_file_lock = threading.Lock()


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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _file_lock:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data[:limit] if limit else data, f, indent=2, ensure_ascii=False)


def _log_action(action_type: str, target: str, result: dict, reason: str, triggered_by: str):
    """Every response action writes here — this IS the per-action audit
    trail. Also mirrors a summary line into core.audit_log so 'everything
    an analyst/playbook did' has one place to look regardless of which
    subsystem performed it."""
    log = _load(RESPONSE_LOG_FILE)
    log.insert(0, {
        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action":       action_type,
        "target":       target,
        "reason":       reason,
        "triggered_by": triggered_by,   # "analyst:<username>" or "playbook:<id>"
        "success":      result.get("success", False),
        "method":       result.get("method", "-"),
        "error":        result.get("error", ""),
    })
    _save(RESPONSE_LOG_FILE, log, 1000)

    try:
        from core.audit_log import log_action as _audit
        actor = triggered_by.split(":", 1)[1] if ":" in triggered_by else triggered_by
        _audit(actor, f"response_{action_type}",
               {"target": target, "success": result.get("success", False), "reason": reason})
    except Exception:
        pass  # audit mirroring is a convenience, never blocks the actual action


def _log_alert(event: str, detail: str, severity: str = "HIGH", host: str = None):
    """Response actions also drop a normal alert entry so they show up in
    the regular alert feed, the same way kill_process already does."""
    alerts = _load(ALERT_FILE)
    alerts.insert(0, {
        "id":        f"RSP-{int(time.time()*1000)}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     event,
        "severity":  severity,
        "detail":    detail,
        "host":      host or socket.gethostname(),
        "user":      "system",
        "status":    "RESOLVED",
    })
    _save(ALERT_FILE, alerts, 500)


# ─────────────────────────────────────────────────────────────
# ISOLATE HOST
# Restrictive Windows Firewall profile: block all inbound/outbound except
# an explicit allow-list (mgmt IP, DNS, this dashboard's own port).
# Reversible via restore_host() — v1.1 tracks exactly which rule names
# were created so restore is exact, not a guess at fixed names.
# ─────────────────────────────────────────────────────────────

ISOLATION_RULE_PREFIX = "SentinelX_Isolate"

def _delete_rule(name: str):
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                    capture_output=True, timeout=5)


def isolate_host(host: str, reason: str = "", allow_ips: list | None = None,
                  dashboard_port: int = 5000, triggered_by: str = "system") -> dict:
    """
    Best-effort host isolation via netsh advfirewall. Only meaningfully
    isolates the LOCAL machine (netsh has no remote-host mode without
    additional remoting setup) — for a remote host this records the
    intent and logs it, but the actual block only takes effect if this
    function runs ON that host (e.g. via the agent).
    """
    allow_ips = allow_ips or []
    result = {"success": False, "method": "netsh_isolate", "host": host}

    # Idempotent: fully undo any PREVIOUS isolation of this host first,
    # using the exact rule list from last time (not a fixed guess) —
    # this is the fix for rules accumulating across repeated calls.
    state = _load(ISOLATION_STATE_FILE, {})
    for old_rule in state.get(host, []):
        _delete_rule(old_rule)

    created_rules = [f"{ISOLATION_RULE_PREFIX}_Block", f"{ISOLATION_RULE_PREFIX}_BlockIn"]
    try:
        r1 = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={created_rules[0]}", "dir=out", "action=block",
             "remoteip=any", "enable=yes"],
            capture_output=True, text=True, timeout=10
        )
        r2 = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={created_rules[1]}", "dir=in", "action=block",
             "remoteip=any", "enable=yes"],
            capture_output=True, text=True, timeout=10
        )

        for ip in allow_ips:
            rule_name = f"{ISOLATION_RULE_PREFIX}_Allow_{ip.replace('.', '_')}"
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}", "dir=out", "action=allow",
                 f"remoteip={ip}", "enable=yes"],
                capture_output=True, timeout=5
            )
            created_rules.append(rule_name)

        dns_rule = f"{ISOLATION_RULE_PREFIX}_AllowDNS"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={dns_rule}", "dir=out", "action=allow",
             "remoteport=53", "protocol=UDP", "enable=yes"],
            capture_output=True, timeout=5
        )
        created_rules.append(dns_rule)

        dash_rule = f"{ISOLATION_RULE_PREFIX}_AllowDashboard"
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={dash_rule}", "dir=out", "action=allow",
             f"localport={dashboard_port}", "protocol=TCP", "enable=yes"],
            capture_output=True, timeout=5
        )
        created_rules.append(dash_rule)

        result["success"] = (r1.returncode == 0 and r2.returncode == 0)
        if not result["success"]:
            result["error"] = (r1.stderr or r2.stderr or "netsh returned non-zero — run as Administrator")
    except FileNotFoundError:
        result["error"] = "netsh not found — isolation only supported on Windows"
    except Exception as e:
        result["error"] = str(e)

    # Record exactly what was created (even on partial failure — some
    # rules may have succeeded before an error) so restore_host() can
    # clean up precisely rather than guessing.
    state[host] = created_rules
    _save(ISOLATION_STATE_FILE, state)

    detail = (
        f"Host isolation {'SUCCEEDED' if result['success'] else 'FAILED'}\n"
        f"Host    : {host}\n"
        f"Reason  : {reason}\n"
        f"Allowed : {', '.join(allow_ips) if allow_ips else '(dashboard + DNS only)'}\n"
        + (f"Error   : {result.get('error','')}" if not result["success"] else "All inbound/outbound blocked except allow-list")
    )
    _log_alert("Host Isolated" if result["success"] else "Host Isolation Failed",
               detail, severity="CRITICAL", host=host)
    _log_action("isolate_host", host, result, reason, triggered_by)
    return result


def restore_host(host: str, triggered_by: str = "system") -> dict:
    """Reverse isolate_host() — removes exactly the rules recorded for
    this host in data/isolation_state.json, whatever that set turned out
    to be (fixed rules + however many per-IP allow rules existed)."""
    result = {"success": False, "method": "netsh_restore", "host": host}
    state = _load(ISOLATION_STATE_FILE, {})
    rules_to_remove = state.get(host, [
        # Fallback if this host has no recorded state (e.g. isolated by an
        # older version of this function) — best effort on the fixed names.
        f"{ISOLATION_RULE_PREFIX}_Block", f"{ISOLATION_RULE_PREFIX}_BlockIn",
        f"{ISOLATION_RULE_PREFIX}_AllowDNS", f"{ISOLATION_RULE_PREFIX}_AllowDashboard",
    ])
    try:
        for name in rules_to_remove:
            _delete_rule(name)
        result["success"] = True
        state.pop(host, None)
        _save(ISOLATION_STATE_FILE, state)
    except FileNotFoundError:
        result["error"] = "netsh not found — isolation only supported on Windows"
    except Exception as e:
        result["error"] = str(e)

    _log_alert("Host Isolation Removed", f"Host {host} restored to normal network access",
               severity="MEDIUM", host=host)
    _log_action("restore_host", host, result, "manual restore", triggered_by)
    return result


# ─────────────────────────────────────────────────────────────
# DISABLE USER ACCOUNT
# Local accounts only — explicitly does NOT claim to cover AD.
# ─────────────────────────────────────────────────────────────

def disable_user(username: str, host: str = "", reason: str = "",
                  triggered_by: str = "system") -> dict:
    result = {"success": False, "method": "net_user_local", "username": username}
    try:
        r = subprocess.run(
            ["net", "user", username, "/active:no"],
            capture_output=True, text=True, timeout=10
        )
        result["success"] = (r.returncode == 0)
        if not result["success"]:
            stderr = (r.stderr or r.stdout or "").strip()
            if "could not be found" in stderr.lower() or "1908" in stderr or "2221" in stderr:
                result["error"] = (
                    f"'{username}' is not a LOCAL account on this machine — this "
                    f"action only disables local Windows accounts. If this is a "
                    f"domain account, disabling it requires an AD-aware path "
                    f"(e.g. Disable-ADAccount via RSAT/PowerShell against a DC), "
                    f"which this function does not implement."
                )
            else:
                result["error"] = stderr or "net user returned non-zero — run as Administrator"
    except FileNotFoundError:
        result["error"] = "'net' command not found — only supported on Windows"
    except Exception as e:
        result["error"] = str(e)

    detail = (
        f"Account disable {'SUCCEEDED' if result['success'] else 'FAILED'}\n"
        f"Username: {username}\n"
        f"Host    : {host or socket.gethostname()}\n"
        f"Reason  : {reason}\n"
        + (f"Error   : {result.get('error','')}" if not result["success"] else "Account set to inactive")
    )
    _log_alert("User Account Disabled" if result["success"] else "User Disable Failed",
               detail, severity="HIGH", host=host)
    _log_action("disable_user", username, result, reason, triggered_by)
    return result


# ─────────────────────────────────────────────────────────────
# QUARANTINE FILE
# Move to data/quarantine/<sha256>/, strip execute permission,
# record original path + hash + who/when, with a restore path.
# ─────────────────────────────────────────────────────────────

def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return hashlib.sha256(path.encode()).hexdigest()  # fallback if unreadable


def quarantine_file(path: str, reason: str = "", triggered_by: str = "system") -> dict:
    result = {"success": False, "method": "move_quarantine", "path": path}

    if not os.path.exists(path):
        result["error"] = f"File not found: {path}"
        _log_action("quarantine_file", path, result, reason, triggered_by)
        return result

    try:
        file_hash = _sha256_of(path)
        dest_dir  = os.path.join(QUARANTINE_DIR, file_hash)
        os.makedirs(dest_dir, exist_ok=True)
        filename  = os.path.basename(path)
        dest_path = os.path.join(dest_dir, filename)

        shutil.move(path, dest_path)
        try:
            # Best-effort, and worth being precise about what this actually
            # does: on Windows this only sets the read-only attribute (no
            # true ACL-level execute-deny — that would need icacls, which
            # varies more by Windows version/permissions than this is worth
            # taking a hard dependency on). On POSIX it does clear the
            # execute bit for real. Either way, moving the file out of its
            # original location is the primary containment; this is
            # defense-in-depth on top of that, not the main mechanism.
            os.chmod(dest_path, 0o444)
        except Exception:
            pass

        meta = {
            "original_path": path,
            "quarantine_path": dest_path,
            "sha256": file_hash,
            "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "quarantined_by": triggered_by,
            "reason": reason,
            "restored": False,
        }
        with open(os.path.join(dest_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        result.update({"success": True, "sha256": file_hash,
                        "quarantine_path": dest_path, "original_path": path})
    except Exception as e:
        result["error"] = str(e)

    detail = (
        f"File quarantine {'SUCCEEDED' if result['success'] else 'FAILED'}\n"
        f"Original path : {path}\n"
        f"Reason        : {reason}\n"
        + (f"SHA256        : {result.get('sha256','-')}\nQuarantine dir: {result.get('quarantine_path','-')}"
           if result["success"] else f"Error         : {result.get('error','')}")
    )
    _log_alert("File Quarantined" if result["success"] else "File Quarantine Failed",
               detail, severity="HIGH")
    _log_action("quarantine_file", path, result, reason, triggered_by)
    return result


def restore_file(sha256: str, triggered_by: str = "system") -> dict:
    """Reverse quarantine_file() using the stored metadata."""
    result = {"success": False, "method": "restore_quarantine", "sha256": sha256}
    dest_dir = os.path.join(QUARANTINE_DIR, sha256)
    meta_path = os.path.join(dest_dir, "metadata.json")

    if not os.path.exists(meta_path):
        result["error"] = f"No quarantine record found for {sha256}"
        return result

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        quarantine_path = meta["quarantine_path"]
        original_path   = meta["original_path"]
        if not os.path.exists(quarantine_path):
            result["error"] = "Quarantined file no longer present on disk"
            return result
        os.makedirs(os.path.dirname(original_path), exist_ok=True)
        shutil.move(quarantine_path, original_path)
        meta["restored"] = True
        meta["restored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        result["success"] = True
        result["restored_to"] = original_path
    except Exception as e:
        result["error"] = str(e)

    _log_action("restore_file", sha256, result, "manual restore", triggered_by)
    return result


# ─────────────────────────────────────────────────────────────
# BLOCK IP — the one canonical implementation. app.py's manual "Block IP"
# routes now call this instead of the inline duplicate they used to have,
# and playbooks call the exact same function — one behavior, one place
# it can have a bug, one place to fix it.
# ─────────────────────────────────────────────────────────────

def block_ip(ip: str, reason: str = "", ip_type: str = "Threat IP",
             triggered_by: str = "system") -> dict:
    result = {"success": False, "method": "netsh_block", "ip": ip}

    blocked = _load(BLOCK_FILE)
    if any(b.get("ip") == ip for b in blocked):
        result["success"] = True
        result["already_blocked"] = True
        _log_action("block_ip", ip, result, reason, triggered_by)
        return result

    entry = {
        "ip": ip,
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": reason or "Manual block",
        "type": ip_type,
        "blocked_by": triggered_by,
    }
    blocked.insert(0, entry)
    _save(BLOCK_FILE, blocked)
    log = _load(FW_FILE)
    log.insert(0, {**entry, "action": "BLOCK"})
    _save(FW_FILE, log, 200)

    try:
        rule_name = f"SentinelX_Block_{ip.replace('.', '_')}"
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}", "enable=yes"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            result["success"] = True
        else:
            result["success"] = False
            result["note"] = "Blocklist JSON updated but firewall rule failed — requires Administrator privileges"
            result["stderr"] = r.stderr.strip() if r.stderr else ""
    except Exception as e:
        result["success"] = False
        result["note"] = f"Blocklist JSON updated but firewall rule not applied: {e}"

    _log_action("block_ip", ip, result, reason, triggered_by)
    return result


# ─────────────────────────────────────────────────────────────
# CREATE CASE / NOTIFY — lightweight actions a playbook can trigger
# directly, independent of alert_pipeline's own auto-case logic — but
# NOT ignorant of it. v1.1: checks for an existing fresh OPEN case on the
# same host+tactic before creating a new one, same rule alert_pipeline's
# _auto_create_case() already applies, so a playbook re-firing on an
# ongoing incident doesn't spam duplicate cases.
# ─────────────────────────────────────────────────────────────

def create_case(alert: dict, priority: str = "P2", triggered_by: str = "system") -> dict:
    host   = alert.get("host", "unknown")
    tactic = alert.get("mitre_tactic", "-")

    # Lazy import: alert_pipeline eventually imports soar_engine (which
    # imports this module) to call run_playbooks() — importing
    # alert_pipeline at module load time here would be circular. By the
    # time this function actually runs, everything is already loaded.
    try:
        from core.alert_pipeline import _load as _ap_load, _save as _ap_save, \
            CASE_FILE as _AP_CASE_FILE, CASE_REOPEN_WINDOW_HOURS
        from datetime import datetime as _dt
        cases = _ap_load(_AP_CASE_FILE)
        now = _dt.now()
        for c in cases:
            if c.get("host") != host or c.get("status") != "OPEN" or c.get("tactic") != tactic:
                continue
            try:
                last_touch = _dt.strptime(c.get("last_alert_at") or c.get("created", ""),
                                           "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            if (now - last_touch).total_seconds() <= CASE_REOPEN_WINDOW_HOURS * 3600:
                c["last_alert_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
                c.setdefault("related_alerts", []).append(alert.get("id", ""))
                _ap_save(_AP_CASE_FILE, cases, 300)
                result = {"success": True, "method": "playbook_case_folded", "case_id": c["case_id"]}
                _log_action("create_case", c["case_id"], result, f"folded, priority={priority}", triggered_by)
                return result
        case_file, cases_list = _AP_CASE_FILE, cases
    except ImportError:
        case_file, cases_list = os.path.join(DATA_DIR, "cases.json"), _load(os.path.join(DATA_DIR, "cases.json"))

    case = {
        "case_id":  f"CASE-{int(time.time())}",
        "status":   "OPEN",
        "analyst":  "Unassigned",
        "severity": alert.get("severity", "MEDIUM"),
        "priority": priority,
        "host":     host,
        "user":     alert.get("user", "unknown"),
        "tactic":   tactic,
        "created":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_alert_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "closed":   "",
        "notes":    [],
        "related_alerts": [alert.get("id", "")],
        "source_alert": alert.get("id", ""),
        "manual":   False,
        "playbook_created": True,
    }
    cases_list.insert(0, case)
    _save(case_file, cases_list, 300)
    result = {"success": True, "method": "playbook_case", "case_id": case["case_id"]}
    _log_action("create_case", case["case_id"], result, f"priority={priority}", triggered_by)
    return result


def notify(message: str, channel: str = "console", triggered_by: str = "system") -> dict:
    """Delegates to integrations/notifier.py for real channels (email/
    slack/teams); console is the default/fallback and always works."""
    if channel in ("email", "slack", "teams"):
        try:
            from integrations import notifier as _notif
            fn = {"email": lambda: _notif.send_email(f"[SentinelX Playbook] {message}", message),
                  "slack": lambda: _notif.send_slack(message),
                  "teams": lambda: _notif.send_teams(message)}[channel]
            outcome = fn()
            print(f"\n🔔 [SOAR NOTIFY:{channel}] {message}")
            result = {"success": outcome.get("success", False), "method": f"notify_{channel}",
                       "detail": outcome}
            _log_action("notify", channel, result, message, triggered_by)
            return result
        except Exception as e:
            print(f"\n🔔 [SOAR NOTIFY:{channel}] FAILED ({e}) — falling back to console: {message}")

    print(f"\n🔔 [SOAR NOTIFY:console] {message}")
    result = {"success": True, "method": "notify_console"}
    _log_action("notify", "console", result, message, triggered_by)
    return result
