"""
SentinelX Suricata Connector v1.0
==================================
Feeds Suricata IDS/IPS alerts into the same process_alert() pipeline every
other detector uses.

WHY THIS READS A FILE INSTEAD OF CALLING AN API
------------------------------------------------
Suricata itself is a detection *engine*, not a web service — it doesn't
expose a REST API you can query for "give me your alerts." What it does
have:

  1. eve.json — a JSON-Lines log (one JSON object per line) that Suricata
     writes continuously when `eve-log` is enabled in suricata.yaml. This
     is the standard, documented way every SIEM/dashboard integrates with
     Suricata, and it's what this connector tails.

  2. A unix socket control channel (`suricata --unix-socket`, the same
     protocol the `suricatasc` CLI uses) for runtime commands — reload
     rules, get stats, and (relevant for IPS-style response) add a value
     to a *dataset* that your rules reference, which is the realistic way
     to do "block this IP dynamically" with Suricata. This connector
     includes a best-effort helper for that (suricata_block_ip below), but
     it only works if you've already set up a dataset + a rule that uses
     it — Suricata doesn't have a generic "block this IP" switch, blocking
     is something YOUR ruleset has to be written to do.

CONFIGURATION (.env)
---------------------
SURICATA_EVE_JSON_PATH   Path to eve.json. Required — if unset, this
                         connector logs one line and stays idle.
                         e.g. C:\\Suricata\\log\\eve.json  or  /var/log/suricata/eve.json
SURICATA_HOST_LABEL      Optional label for the "host" field on alerts
                         (defaults to this machine's hostname). Set this
                         if Suricata is monitoring a different box/segment
                         than the one running SentinelX.
SURICATA_UNIX_SOCKET     Optional, only needed for suricata_block_ip().
                         e.g. /var/run/suricata/suricata-command.socket

NOTE ON SEVERITY
-----------------
Suricata's own `alert.severity` field is 1=high, 2=medium, 3=low — the
INVERSE of what you'd intuitively expect (lower number = more severe).
This connector converts that to SentinelX's CRITICAL/HIGH/MEDIUM scale
before anything else touches it, so the rest of the app never has to
think about Suricata's numbering.
"""

import os
import io
import json
import socket
import time

# ── minimal, self-sufficient .env loader (same pattern as threat_intel.py) ──
def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

EVE_JSON_PATH = os.environ.get("SURICATA_EVE_JSON_PATH", "").strip()
HOST_LABEL    = os.environ.get("SURICATA_HOST_LABEL", "").strip() or socket.gethostname()
UNIX_SOCKET   = os.environ.get("SURICATA_UNIX_SOCKET", "").strip()

# High-signal rule categories that bump risk up a tier even when Suricata's
# own severity field is lower than you'd expect (rulesets are inconsistent
# about how they set `alert.severity` — the category text is often a more
# reliable signal for genuinely dangerous stuff).
_CRITICAL_CATEGORY_HINTS = (
    "trojan", "exploit", "shellcode", "ransomware", "c2", "command and control",
    "malware", "backdoor",
)
_HIGH_CATEGORY_HINTS = (
    "scan", "policy violation", "attempted", "web application attack",
)


def _map_suricata_severity(alert_obj: dict) -> str:
    """
    Suricata severity: 1=high, 2=medium, 3=low (inverted vs. intuition).
    Combined with a category-text check since ruleset severity tagging
    is inconsistent in practice.
    """
    sev_num  = alert_obj.get("severity", 3)
    category = str(alert_obj.get("category", "")).lower()
    signature = str(alert_obj.get("signature", "")).lower()
    combined = category + " " + signature

    if any(h in combined for h in _CRITICAL_CATEGORY_HINTS):
        return "CRITICAL"
    if sev_num == 1:
        return "HIGH"
    if any(h in combined for h in _HIGH_CATEGORY_HINTS):
        return "HIGH"
    if sev_num == 2:
        return "MEDIUM"
    return "MEDIUM" if sev_num <= 2 else "LOW"


def _tail_lines(path: str):
    """
    Generator: yields new lines appended to `path`, starting from EOF (so
    we never replay Suricata's entire history on startup — only alerts from
    now on, same "don't alert on pre-existing state" philosophy every other
    detector in this app uses for its baseline). Handles log rotation by
    noticing the file shrank and reopening from the start in that case.
    """
    f = None
    last_size = 0
    while True:
        try:
            if f is None:
                f = io.open(path, "r", encoding="utf-8", errors="ignore")
                f.seek(0, os.SEEK_END)
                last_size = os.path.getsize(path)

            line = f.readline()
            if line:
                yield line
                continue

            time.sleep(1)
            try:
                cur_size = os.path.getsize(path)
            except OSError:
                cur_size = last_size
            if cur_size < last_size:
                # File was rotated/truncated — reopen from the top
                try:
                    f.close()
                except Exception:
                    pass
                f = None
                continue
            last_size = cur_size

        except FileNotFoundError:
            time.sleep(3)
            f = None
        except Exception:
            time.sleep(3)


def monitor_suricata(alert_callback):
    """
    Tail eve.json and feed `event_type == "alert"` entries into the pipeline.
    Every other event type (flow, dns, http, tls, fileinfo, stats, ...) is
    read but skipped for now — they're valuable for enrichment later
    (e.g. cross-referencing a host's DNS activity when investigating an
    alert) but are not detections on their own, so surfacing them as alerts
    would just add noise.
    """
    if not EVE_JSON_PATH:
        print("  [Suricata] SURICATA_EVE_JSON_PATH not set in .env — connector idle")
        return
    if not os.path.exists(EVE_JSON_PATH):
        print(f"  [Suricata] WARNING: {EVE_JSON_PATH} does not exist — "
              f"check the path and that Suricata's eve-log output is enabled")
        return

    print(f"  [Suricata] Tailing {EVE_JSON_PATH}")

    for raw_line in _tail_lines(EVE_JSON_PATH):
        try:
            evt = json.loads(raw_line)
        except (json.JSONDecodeError, ValueError):
            continue  # partial line mid-write, or non-JSON noise — skip, don't crash

        try:
            if evt.get("event_type") != "alert":
                continue

            alert_obj = evt.get("alert", {})
            signature = alert_obj.get("signature", "Suricata Alert")
            category  = alert_obj.get("category", "Unknown")
            sig_id    = alert_obj.get("signature_id", "?")
            action    = alert_obj.get("action", "allowed")  # "blocked" = IPS drop actually fired

            src_ip, src_port   = evt.get("src_ip", "?"),  evt.get("src_port", "?")
            dest_ip, dest_port = evt.get("dest_ip", "?"), evt.get("dest_port", "?")
            proto     = evt.get("proto", "?")
            app_proto = evt.get("app_proto", "")

            risk = _map_suricata_severity(alert_obj)

            detail = (
                f"{signature}\n"
                f"Category  : {category}\n"
                f"Rule SID  : {sig_id}\n"
                f"Flow      : {src_ip}:{src_port} -> {dest_ip}:{dest_port} ({proto}"
                + (f"/{app_proto}" if app_proto else "") + ")\n"
                f"IPS action: {action}\n"
                f"SURICATA_RISK:{risk}"
            )

            # Suricata operates at the network layer — it has no concept of
            # an OS username the way an endpoint detector does. Being
            # explicit about that here rather than guessing/leaving blank.
            alert_callback({
                "event":  f"Suricata: {category}",
                "detail": detail,
                "host":   HOST_LABEL,
                "user":   "network",
            })

        except Exception as e:
            print(f"  [Suricata] error processing event: {e}")
            continue


# ─────────────────────────────────────────────────────────────
# OPTIONAL: best-effort dynamic block via the unix socket control channel.
# Requires Suricata running with --unix-socket AND a dataset + rule you've
# already configured to use it (see module docstring). This is NOT wired
# into any automatic response path by default — call it explicitly from a
# response action if you set up the Suricata side of this.
# ─────────────────────────────────────────────────────────────

def suricata_block_ip(ip: str, dataset_name: str = "blocklist_ips") -> dict:
    """
    Best-effort: add `ip` to a Suricata dataset via the unix socket protocol
    (the same JSON command protocol `suricatasc` uses). Returns a structured
    result dict — never raises. Does nothing useful unless your ruleset
    already has a rule referencing this dataset, e.g.:
        alert ip [dataset_name] any -> any any (msg:"blocked by SentinelX"; ...)
    """
    if not UNIX_SOCKET:
        return {"success": False, "method": "suricata_socket",
                "error": "SURICATA_UNIX_SOCKET not configured in .env"}
    if not os.path.exists(UNIX_SOCKET):
        return {"success": False, "method": "suricata_socket",
                "error": f"socket not found at {UNIX_SOCKET} — is Suricata "
                         f"running with --unix-socket?"}

    try:
        import socket as _socket
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(UNIX_SOCKET)

        # Suricata's socket protocol requires a version handshake first
        sock.sendall(json.dumps({"version": "0.2"}).encode() + b"\n")
        sock.recv(4096)

        cmd = {
            "command": "dataset-add",
            "arguments": {"setname": dataset_name, "settype": "string", "datavalue": ip},
        }
        sock.sendall(json.dumps(cmd).encode() + b"\n")
        resp = sock.recv(4096)
        sock.close()

        parsed = json.loads(resp.decode(errors="ignore"))
        ok = parsed.get("return") == "OK"
        return {"success": ok, "method": "suricata_socket", "ip": ip,
                "dataset": dataset_name, "raw": parsed}
    except Exception as e:
        return {"success": False, "method": "suricata_socket", "error": str(e)}
