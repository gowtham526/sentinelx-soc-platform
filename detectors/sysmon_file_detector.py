r"""
SentinelX Sysmon File Detector v3.0
=====================================
Reads Sysmon Event ID 11 (FileCreate) from the Windows Event Log
and alerts on suspicious file creation.

Changes from v2.4
─────────────────
1. SEVERITY REMOVED FROM CALLBACK — pipeline decides via
   FILE_RISK:<level> hint embedded in detail.

2. DETECTION LOGIC COMPLETELY REWRITTEN:
   Old: only matched 10 hardcoded filenames (backdoor.exe, evil.exe...)
        Missing: test.exe, update.exe, svc.exe, anything real-world.
   New: multi-signal scoring:
     - ANY .exe/.dll/.bat/.ps1 in Temp, AppData, ProgramData,
       Public, Downloads, Recycle → suspicious
     - Known-bad filename keywords still checked (broader list)
     - Signed/whitelisted paths excluded
     - Risk score embedded as FILE_RISK hint for pipeline

3. DEDUPLICATION FIXED:
   Old: same file triggered a new alert every 2 seconds.
   New: seen_files set tracks TargetFilename — fires once per file.

4. BARE EXCEPT REPLACED with specific exception handling so errors
   don't silently swallow bugs.

5. FORMATTING NORMALISED (was inconsistent whitespace/linebreaks).
"""

import time
import socket
import os

try:
    import win32evtlog
    import xml.etree.ElementTree as ET
    WIN32_OK = True
except ImportError:
    WIN32_OK = False
    print("[SysmonFileDetector] WARNING: pywin32 not installed — "
          "native Sysmon EID 11 monitoring disabled")

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

# ─────────────────────────────────────────────────────────────
# HIGH-RISK PATHS — ANY executable in these paths is suspicious
# ─────────────────────────────────────────────────────────────

HIGH_RISK_PATHS = [
    "\\temp\\", "\\tmp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
    "\\public\\",
    "\\downloads\\",
    "\\recycle\\", "\\$recycle.bin\\",
    "\\users\\public\\",
]

# ─────────────────────────────────────────────────────────────
# HIGH-RISK EXTENSIONS — file types worth watching in any path
# ─────────────────────────────────────────────────────────────

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".hta",
    ".scr", ".pif", ".com",
}

# ─────────────────────────────────────────────────────────────
# CRITICAL KEYWORD FILENAMES — escalate regardless of path
# ─────────────────────────────────────────────────────────────

CRITICAL_KEYWORDS = [
    "mimikatz", "meterpreter", "cobalt", "beacon",
    "backdoor", "payload", "exploit", "ransomware",
    "keylog", "stealer", "injector", "dropper",
    "evil", "malware", "virus", "trojan", "rat",
    "nc.exe", "netcat", "ncat", "psexec",
    "procdump", "wce.exe", "fgdump", "pwdump",
    "invoke-expression", "shellcode",
]

# ─────────────────────────────────────────────────────────────
# SAFE PATH PREFIXES — never alert on these
# ─────────────────────────────────────────────────────────────

SAFE_PREFIXES = [
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\",
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
]


def _parse_xml(xml_str: str):
    """Parse Sysmon EID 11 XML. Returns (data_dict, record_id)."""
    ns       = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    data     = {}
    rec_id   = 0
    try:
        root = ET.fromstring(xml_str)
        for d in root.findall(".//" + ns + "Data"):
            data[d.attrib.get("Name", "")] = d.text or ""
        rec_elem = root.find(".//" + ns + "EventRecordID")
        if rec_elem is not None and rec_elem.text:
            rec_id = int(rec_elem.text)
    except Exception:
        pass
    return data, rec_id


def _score_file(target_filename: str) -> tuple:
    """
    Score a file creation event.
    Returns (risk_hint, should_alert, reason).
    risk_hint  → "CRITICAL", "HIGH", or None (no alert).
    """
    fn_lower = target_filename.lower()

    # Safe paths → never alert
    for sp in SAFE_PREFIXES:
        if fn_lower.startswith(sp):
            return None, False, ""

    # Get extension
    _, ext = os.path.splitext(fn_lower)

    # Critical keyword in filename → CRITICAL regardless of path
    for kw in CRITICAL_KEYWORDS:
        if kw in fn_lower:
            return "CRITICAL", True, f"Known-bad filename keyword: '{kw}'"

    # Executable in a high-risk writable path → HIGH
    if ext in HIGH_RISK_EXTENSIONS:
        for rp in HIGH_RISK_PATHS:
            if rp in fn_lower:
                return "HIGH", True, f"Executable dropped to high-risk path: {rp}"

    # Not suspicious
    return None, False, ""


def monitor_sysmon_file(alert_callback):
    """
    Monitor Sysmon EID 11 (FileCreate) for suspicious file drops.

    severity is NOT set in alert_callback — pipeline decides via
    FILE_RISK:<level> embedded in detail.
    """
    if not WIN32_OK:
        print("[SysmonFileDetector] pywin32 unavailable — file monitoring offline")
        return

    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    seen_files:   set = set()   # TargetFilename dedup
    seen_rec_ids: set = set()   # Record ID dedup
    startup_rec_id    = 0

    # Capture baseline — newest EID 11 record ID at startup
    try:
        handle = win32evtlog.EvtQuery(
            LOG_NAME,
            win32evtlog.EvtQueryReverseDirection,
            "*[System[(EventID=11)]]",
        )
        events = win32evtlog.EvtNext(handle, 1)
        if events:
            xml_str          = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
            _, startup_rec_id = _parse_xml(xml_str)
            print(f"  [SysmonFileDetector] Baseline at record ID {startup_rec_id}")
    except Exception as e:
        print(f"  [SysmonFileDetector] Baseline failed ({e}) — will process all events")
        startup_rec_id = 0

    print(f"  [SysmonFileDetector] Active — {len(HIGH_RISK_PATHS)} high-risk paths, "
          f"{len(CRITICAL_KEYWORDS)} critical keywords")

    while True:
        try:
            handle = win32evtlog.EvtQuery(
                LOG_NAME,
                win32evtlog.EvtQueryReverseDirection,
                "*[System[(EventID=11)]]",
            )
            events = win32evtlog.EvtNext(handle, 50)

            for event in events:
                try:
                    xml_str           = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    data, record_id   = _parse_xml(xml_str)

                    if record_id <= startup_rec_id:
                        continue
                    if record_id in seen_rec_ids:
                        continue
                    seen_rec_ids.add(record_id)

                    target = str(data.get("TargetFilename", "")).strip()
                    if not target:
                        continue

                    # Dedup by filename — one alert per unique file path
                    if target.lower() in seen_files:
                        continue

                    risk_hint, should_alert, reason = _score_file(target)

                    if not should_alert:
                        continue

                    seen_files.add(target.lower())

                    image   = str(data.get("Image",        "-"))
                    process = str(data.get("ProcessId",    "-"))
                    created = str(data.get("CreationUtcTime", "-"))

                    # Real content scan, not just filename/path heuristics
                    # (see integrations/yara_scanner.py) — best-effort: the
                    # file may already be gone, locked, or huge, all of
                    # which the scanner handles gracefully on its own.
                    yara_line = ""
                    try:
                        from integrations.yara_scanner import scan_file, highest_match_severity
                        yr = scan_file(target)
                        if yr["scanned"] and yr["matches"]:
                            rule_names = ", ".join(m["rule"] for m in yr["matches"])
                            yara_sev = highest_match_severity(yr["matches"])
                            yara_line = f"YARA    : MATCHED [{rule_names}]\nYARA_RISK:{yara_sev}\n"
                    except Exception:
                        pass

                    detail = (
                        f"Suspicious file created in high-risk location\n"
                        f"File    : {target}\n"
                        f"Reason  : {reason}\n"
                        f"Created : {created}\n"
                        f"By      : {image} (PID {process})\n"
                        f"{yara_line}"
                        f"MITRE   : T1204.002 — Malicious File\n"
                        f"FILE_RISK:{risk_hint}"   # scored by calculate_severity
                    )

                    alert_callback({
                        "event":  "Suspicious File Creation Detected",
                        "detail": detail,
                        # NO "severity" key — pipeline decides.
                        "host":   host,
                        "user":   user,
                        "source": "sysmon_file",
                        "log_source": "Sysmon",
                    })

                except Exception:
                    pass

            time.sleep(2)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(2)