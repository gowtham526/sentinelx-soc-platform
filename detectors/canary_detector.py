"""
SentinelX Canary / Honeytoken Detector v1.0
==============================================
Two independent monitors, both exported from this module and both wired
into main_engine.py like any other detector:

  monitor_canary_files(alert_callback)   — decoy files, watchdog-based,
                                            cross-platform.
  monitor_canary_account(alert_callback) — decoy user account, Windows
                                            Security event log-based.

Canaries only work because nothing legitimate ever touches them. A decoy
file sitting in a folder, or a decoy account that exists but is never
used by anyone real — any interaction at all means someone (or something)
is snooping around who shouldn't be. That's why Signal 23 in
core/alert_pipeline.py treats a canary hit as a flat +75: this isn't a
heuristic guess like most other signals, it's ground truth.

Same platform-guard discipline as detectors/registry_detector.py (fixed
earlier in this project for exactly this class of bug: an unguarded
platform-only import must never be able to crash the rest of the app).
watchdog is cross-platform and works everywhere including this sandbox;
win32evtlog is Windows-only and is guarded the same way sysmon_detector's
family of detectors already guard it.
"""

import os
import time
import socket

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False
    print("[CanaryDetector] WARNING: watchdog not installed — "
          "file canary monitoring disabled")

try:
    import win32evtlog
    import xml.etree.ElementTree as ET
    WIN32_OK = True
except ImportError:
    WIN32_OK = False
    print("[CanaryDetector] WARNING: pywin32 not available (non-Windows host, "
          "or not installed) — decoy account monitoring disabled")

BASE_DIR          = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CANARY_DIR = os.path.join(BASE_DIR, "canary_files")
SECURITY_LOG_NAME  = "Security"


# ─────────────────────────────────────────────────────────────
# DECOY FILES (watchdog)
# ─────────────────────────────────────────────────────────────

def _get_canary_file_paths() -> list:
    """CANARY_FILE_PATHS (.env) is a comma-separated list of absolute
    paths. If unset, auto-create a small default set of enticingly-named
    decoy files under ./canary_files/ so the feature works with zero
    setup — same philosophy as the built-in YARA starter ruleset and the
    key-free IOC feeds."""
    configured = os.environ.get("CANARY_FILE_PATHS", "").strip()
    if configured:
        return [p.strip() for p in configured.split(",") if p.strip()]

    try:
        os.makedirs(DEFAULT_CANARY_DIR, exist_ok=True)
    except Exception as e:
        print(f"[CanaryDetector] could not create default canary dir: {e}")
        return []

    defaults = {
        "passwords_backup.xlsx":    "SentinelX canary file. Do not use — monitored for access.\n",
        "aws_root_credentials.txt": "SentinelX canary file. Do not use — monitored for access.\n",
        "employee_ssn_export.csv":  "SentinelX canary file. Do not use — monitored for access.\n",
        "passwords.txt":            "SentinelX canary file. Do not use — monitored for access.\n",
        "secret_keys.txt":          "SentinelX canary file. Do not use — monitored for access.\n",
        "admin_credentials.txt":    "SentinelX canary file. Do not use — monitored for access.\n",
    }
    paths = []
    for name, content in defaults.items():
        p = os.path.join(DEFAULT_CANARY_DIR, name)
        if not os.path.exists(p):
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as e:
                print(f"[CanaryDetector] could not create decoy file {p}: {e}")
                continue
        paths.append(os.path.abspath(p))
    return paths


if WATCHDOG_OK:
    class _CanaryFileHandler(FileSystemEventHandler):
        """Filters every filesystem event down to just the configured
        decoy paths — touching any OTHER file in the watched directory
        (which will happen constantly in a real folder) stays silent."""

        def __init__(self, canary_paths, alert_callback, host, user):
            self.canary_paths = {os.path.abspath(p) for p in canary_paths}
            self.alert_callback = alert_callback
            self.host = host
            self.user = user
            self.seen = set()

        def _maybe_alert(self, path, action):
            abspath = os.path.abspath(path)
            if abspath not in self.canary_paths:
                return  # not a decoy file — correctly silent

            dedup_key = f"{abspath}|{action}|{int(time.time() // 5)}"
            if dedup_key in self.seen:
                return
            self.seen.add(dedup_key)

            detail = (
                f"Canary file {action}\n"
                f"Path    : {abspath}\n"
                f"MITRE   : T1083 — File and Directory Discovery\n"
                f"CANARY_HINT:TRIGGERED"
            )
            try:
                self.alert_callback({
                    "event":  "Canary File Triggered",
                    "detail": detail,
                    "host":   self.host,
                    "user":   self.user,
                    "source": "canary",
                    "log_source": "Security",
                })
            except Exception as e:
                print(f"[CanaryDetector] alert_callback failed: {e}")

        def on_modified(self, event):
            if not event.is_directory:
                self._maybe_alert(event.src_path, "modified")

        def on_created(self, event):
            if not event.is_directory:
                self._maybe_alert(event.src_path, "created")

        def on_moved(self, event):
            self._maybe_alert(event.src_path, "moved/renamed")

        def on_deleted(self, event):
            self._maybe_alert(event.src_path, "deleted")


def monitor_canary_files(alert_callback):
    """Watches configured (or auto-created default) decoy files for any
    modification/creation/move/delete and fires an alert with
    CANARY_HINT:TRIGGERED the moment one is touched. Runs until the
    process is killed — same lifecycle as every other main_engine.py
    detector thread."""
    if not WATCHDOG_OK:
        print("  [CanaryDetector] watchdog unavailable — file canary monitoring offline")
        return

    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    canary_paths = _get_canary_file_paths()
    if not canary_paths:
        print("  [CanaryDetector] no canary files configured or creatable — file canary monitoring offline")
        return

    watch_dirs = sorted({os.path.dirname(p) for p in canary_paths})
    handler = _CanaryFileHandler(canary_paths, alert_callback, host, user)
    observer = Observer()
    for d in watch_dirs:
        try:
            observer.schedule(handler, d, recursive=False)
        except Exception as e:
            print(f"  [CanaryDetector] could not watch {d}: {e}")

    observer.start()
    print(f"  [CanaryDetector] Watching {len(canary_paths)} decoy file(s) "
          f"in {len(watch_dirs)} location(s)")

    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join(timeout=5)


# ─────────────────────────────────────────────────────────────
# DECOY ACCOUNT (Windows Security log)
# ─────────────────────────────────────────────────────────────

if WIN32_OK:
    def _parse_security_xml(xml_str):
        """Parse a Security-log event's XML. Returns (data_dict,
        record_id, event_id) — same shape/spirit as the XML parsing
        helper in detectors/sysmon_file_detector.py, just pointed at the
        System EventID element too since we need to tell 4624 (success)
        apart from 4625 (failure)."""
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        data, record_id, event_id = {}, 0, 0
        try:
            root = ET.fromstring(xml_str)
            for d in root.findall(".//" + ns + "Data"):
                data[d.attrib.get("Name", "")] = d.text or ""
            rec_elem = root.find(".//" + ns + "EventRecordID")
            if rec_elem is not None and rec_elem.text:
                record_id = int(rec_elem.text)
            eid_elem = root.find(".//" + ns + "EventID")
            if eid_elem is not None and eid_elem.text:
                event_id = int(eid_elem.text)
        except Exception:
            pass
        return data, record_id, event_id


def monitor_canary_account(alert_callback):
    """Watches the Security log for ANY logon attempt — successful
    (4624) or failed (4625) — against the configured decoy account. The
    account exists but nobody legitimate ever uses it, so a hit (either
    outcome) only happens during account enumeration, a credential
    spray, or lateral movement — never normal use."""
    if not WIN32_OK:
        print("  [CanaryDetector] pywin32 unavailable — decoy account monitoring offline")
        return

    decoy_account = os.environ.get("CANARY_ACCOUNT_NAME", "").strip()
    if not decoy_account:
        print("  [CanaryDetector] CANARY_ACCOUNT_NAME not set — decoy account monitoring offline")
        return

    host = socket.gethostname()
    seen_record_ids = set()
    query = "*[System[(EventID=4624 or EventID=4625)]]"

    try:
        handle = win32evtlog.EvtQuery(
            SECURITY_LOG_NAME, win32evtlog.EvtQueryReverseDirection, query
        )
        first = win32evtlog.EvtNext(handle, 1)
        startup_record_id = 0
        if first:
            xml_str = win32evtlog.EvtRender(first[0], win32evtlog.EvtRenderEventXml)
            _, startup_record_id, _ = _parse_security_xml(xml_str)
    except Exception as e:
        print(f"  [CanaryDetector] baseline read failed ({e}) — will process all matching events")
        startup_record_id = 0

    print(f"  [CanaryDetector] Watching Security log for logon attempts as '{decoy_account}'")

    while True:
        try:
            handle = win32evtlog.EvtQuery(
                SECURITY_LOG_NAME, win32evtlog.EvtQueryReverseDirection, query
            )
            events = win32evtlog.EvtNext(handle, 50)

            for event in events:
                try:
                    xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    data, record_id, event_id = _parse_security_xml(xml_str)

                    if record_id <= startup_record_id or record_id in seen_record_ids:
                        continue
                    seen_record_ids.add(record_id)

                    target_user = str(data.get("TargetUserName", "")).strip()
                    if target_user.lower() != decoy_account.lower():
                        continue  # not the decoy account — correctly silent

                    outcome = "SUCCESSFUL LOGON" if event_id == 4624 else "FAILED LOGON"
                    src_ip  = str(data.get("IpAddress", "-"))

                    detail = (
                        f"Logon attempt against decoy account\n"
                        f"Account  : {target_user}\n"
                        f"Outcome  : {outcome}\n"
                        f"Source IP: {src_ip}\n"
                        f"MITRE    : T1078 — Valid Accounts\n"
                        f"CANARY_HINT:TRIGGERED"
                    )

                    alert_callback({
                        "event":  "Canary Account Triggered",
                        "detail": detail,
                        "host":   host,
                        "user":   target_user,
                        "source": "canary",
                        "log_source": "Security",
                    })

                except Exception as e:
                    print(f"  [CanaryDetector] error processing event: {e}")

            time.sleep(3)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"  [CanaryDetector] poll error: {e}")
            time.sleep(3)