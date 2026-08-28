"""
SentinelX Evidence Snapshot v1.0
==================================
Captures point-in-time forensic state — running processes, active network
connections, logged-in users — the instant a CRITICAL alert fires.

This is NOT a detector: it never calls fire()/process_alert(). It's called
FROM process_alert() (see core/alert_pipeline.py, Stage 4c) once severity
is already known, the same way core/soar_engine.py is called from Stage 4b.
Forensic value drops fast once a host is touched further (attacker cleans
up, process exits, connection closes), so this runs as early as severity
allows rather than being deferred to persistence.

Every psutil access is individually guarded — a process can exit between
being listed and being read, permissions can be denied, one bad handle
should never be able to lose the rest of the snapshot or, worse, take
process_alert() down with it (it's wrapped non-fatal at the call site too,
same as SOAR and the notifier).

DATA MODEL
-----------
data/evidence_snapshots/<alert_id>.json — one file per alert, rather than
one growing JSON array. A snapshot can be a few hundred KB on a busy host,
and analysts only ever pull ONE snapshot at a time (GET /api/evidence/<id>
in app.py) — no reason to load every snapshot ever taken to serve one.
"""

import os
import json
import time
import socket
from datetime import datetime

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False
    print("[EvidenceSnapshot] WARNING: psutil not available — "
          "evidence snapshots disabled")

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAPSHOT_DIR = os.path.join(BASE_DIR, "data", "evidence_snapshots")


# ─────────────────────────────────────────────────────────────
# INDIVIDUALLY-GUARDED CAPTURE HELPERS
# ─────────────────────────────────────────────────────────────

def _safe_processes() -> list:
    """Snapshot of running processes. Each process read individually
    guarded — psutil raises NoSuchProcess/AccessDenied/ZombieProcess for
    perfectly normal races (process exits between iteration and read,
    a system process we can't introspect) and none of those should cost
    us the rest of the list."""
    out = []
    if not PSUTIL_OK:
        return out
    try:
        iterator = psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"])
    except Exception:
        return out
    for p in iterator:
        try:
            info = p.info
            create_time = info.get("create_time")
            out.append({
                "pid":      info.get("pid"),
                "name":     info.get("name") or "-",
                "username": info.get("username") or "-",
                "cmdline":  " ".join(info.get("cmdline") or [])[:300],
                "created":  datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S")
                            if create_time else "-",
            })
        except Exception:
            continue
    return out


def _safe_connections() -> list:
    """Snapshot of active network connections. net_connections() itself
    can raise (AccessDenied on some platforms/permission levels) — that
    degrades to an empty list rather than losing processes/users too."""
    out = []
    if not PSUTIL_OK:
        return out
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return out
    for c in conns:
        try:
            out.append({
                "pid":    c.pid,
                "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-",
                "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-",
                "status": c.status,
            })
        except Exception:
            continue
    return out


def _safe_users() -> list:
    """Snapshot of logged-in users (psutil.users())."""
    out = []
    if not PSUTIL_OK:
        return out
    try:
        for u in psutil.users():
            out.append({
                "name":     u.name,
                "terminal": u.terminal or "-",
                "host":     u.host or "-",
                "started":  datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S"),
            })
    except Exception:
        pass
    return out


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────

def capture_snapshot(alert: dict) -> dict | None:
    """Capture processes/connections/logged-in users right now, save it
    tied to this alert's id, and return the snapshot dict.

    Returns None (and writes nothing) if psutil isn't available at all —
    a missing dependency shouldn't produce an empty-but-present snapshot
    file that reads as "captured, found nothing." Called from
    process_alert() inside a try/except, same as SOAR and the notifier —
    non-fatal by design.
    """
    if not PSUTIL_OK:
        return None

    alert_id = alert.get("id") or f"UNKNOWN-{int(time.time())}"
    snapshot = {
        "alert_id":      alert_id,
        "captured_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host":          alert.get("host", socket.gethostname()),
        "trigger_event": alert.get("event", "-"),
        "severity":      alert.get("severity", "-"),
        "processes":     _safe_processes(),
        "connections":   _safe_connections(),
        "users":         _safe_users(),
    }

    try:
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        path = os.path.join(SNAPSHOT_DIR, f"{alert_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[EvidenceSnapshot] failed to write snapshot for {alert_id}: {e}")
        return None

    return snapshot


def get_snapshot(alert_id: str) -> dict | None:
    """Load a previously captured snapshot by alert id, or None if none
    exists (alert wasn't CRITICAL, or psutil was unavailable when it
    fired)."""
    path = os.path.join(SNAPSHOT_DIR, f"{alert_id}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def list_snapshot_ids() -> list:
    """All alert IDs that currently have a snapshot on disk — used by the
    integration-status route to report a count without loading every
    snapshot just to size a list."""
    if not os.path.isdir(SNAPSHOT_DIR):
        return []
    try:
        return sorted(f[:-5] for f in os.listdir(SNAPSHOT_DIR) if f.endswith(".json"))
    except Exception:
        return []