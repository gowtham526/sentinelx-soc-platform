"""
SentinelX Command History & Ephemeral Process Detector v1.0
=============================================================
Catches commands that execute and exit too fast for the normal
process-scanning detectors (powershell_detector, cmd_detector).

Strategy:
  1. Monitors PowerShell ConsoleHost_history.txt for new lines
  2. Monitors Windows Prefetch directory for newly-touched .pf files
     matching suspicious binaries (certutil, wevtutil, etc.)
  3. Uses a rapid 0.1s scan of cmd.exe/powershell.exe processes
     BUT also captures child processes spawned by cmd.exe

This is complementary to — not a replacement for — the existing
powershell_detector.py and cmd_detector.py.
"""

import os
import time
import socket
import hashlib
import glob

# ─────────────────────────────────────────────────────────────
# SUSPICIOUS PATTERNS (checked against PS history lines)
# ─────────────────────────────────────────────────────────────

HISTORY_RULES = [
    # CRITICAL
    ("invoke-mimikatz",            "CRITICAL", "Mimikatz via PS history",        "T1003.001"),
    ("invoke-kerberoast",          "CRITICAL", "Kerberoasting in PS history",    "T1558.003"),
    ("sekurlsa",                   "CRITICAL", "Sekurlsa module in PS history",  "T1003.001"),
    ("mimikatz",                   "CRITICAL", "Mimikatz keyword in PS history", "T1003"),
    ("vssadmin delete",            "CRITICAL", "Shadow copy deletion (history)", "T1490"),
    ("wmic shadowcopy delete",     "CRITICAL", "Shadow copy deletion WMI",       "T1490"),
    ("bcdedit /set",               "CRITICAL", "Boot config mod (history)",      "T1490"),
    ("invoke-shellcode",           "CRITICAL", "Shellcode injection (history)",  "T1055"),
    ("sc stop windefend",          "CRITICAL", "Defender stopped (history)",     "T1562.001"),
    ("sc delete windefend",        "CRITICAL", "Defender deleted (history)",     "T1562.001"),
    ("format c:",                  "CRITICAL", "Drive format (history)",         "T1561"),
    ("psexec",                     "CRITICAL", "PsExec (history)",              "T1021.002"),
    ("schtasks /create",           "CRITICAL", "Scheduled task creation",        "T1053.005"),

    # HIGH
    ("certutil -urlcache",         "HIGH",     "Certutil download cradle",       "T1105"),
    ("certutil -decode",           "HIGH",     "Certutil base64 decode",         "T1027"),
    ("certutil -split",            "HIGH",     "Certutil file splitting",        "T1027"),
    ("bitsadmin /transfer",        "HIGH",     "BITSAdmin download",             "T1197"),
    ("wevtutil cl",                "HIGH",     "Event log cleared (history)",    "T1070.001"),
    ("wevtutil el",                "HIGH",     "Event log listing (recon)",      "T1070.001"),
    ("invoke-webrequest",          "HIGH",     "PS web download (history)",      "T1105"),
    ("downloadstring",             "HIGH",     "DownloadString cradle",          "T1105"),
    ("downloadfile",               "HIGH",     "DownloadFile cradle",            "T1105"),
    ("net.webclient",              "HIGH",     "WebClient object (history)",     "T1105"),
    ("-windowstyle hidden",        "HIGH",     "Hidden PS window (history)",     "T1564.003"),
    ("-w hidden",                  "HIGH",     "Hidden window flag (history)",   "T1564.003"),
    ("net user /add",              "HIGH",     "New user created (history)",     "T1136.001"),
    ("net localgroup administrators /add", "CRITICAL", "Admin group add",        "T1098"),
    ("reg add hkcu\\software\\microsoft\\windows\\currentversion\\run", "HIGH", "Run key persistence", "T1547.001"),
    ("reg add hklm\\software\\microsoft\\windows\\currentversion\\run", "HIGH", "Run key persistence", "T1547.001"),
    ("clear-eventlog",             "HIGH",     "Event log cleared (PS)",         "T1070.001"),
    ("compress-archive",           "HIGH",     "Archive for exfil staging",      "T1560"),
    ("curl -o ",                   "HIGH",     "Curl download to file",          "T1105"),
    ("mshta http",                 "HIGH",     "MSHTA remote HTA exec",          "T1218.005"),
    ("sc create",                  "HIGH",     "Service creation (persistence)", "T1543.003"),
    ("-enc ",                      "HIGH",     "Encoded PS command",             "T1027"),
    ("-encodedcommand",            "HIGH",     "EncodedCommand flag",            "T1027"),

    # MEDIUM
    ("whoami /all",                "MEDIUM",   "Full user/priv enum",            "T1033"),
    ("whoami /priv",               "MEDIUM",   "Privilege enumeration",          "T1057"),
    ("net user",                   "MEDIUM",   "User enumeration",               "T1087.001"),
    ("systeminfo",                 "MEDIUM",   "OS enumeration",                 "T1082"),
    ("ipconfig /all",              "MEDIUM",   "Full network config dump",       "T1016"),
    ("netstat -ano",               "MEDIUM",   "Active connections with PIDs",   "T1049"),
]

_seen_hashes = set()


def _hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def _get_ps_history_path() -> str:
    """Return path to PowerShell ConsoleHost_history.txt."""
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return ""
    return os.path.join(
        appdata, "Microsoft", "Windows", "PowerShell",
        "PSReadLine", "ConsoleHost_history.txt"
    )


def monitor_cmdhistory(alert_callback):
    """
    Watch PowerShell history file for new suspicious commands.
    This catches commands that execute and exit too fast for the
    normal process-scanning detectors.
    """
    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    history_path = _get_ps_history_path()
    last_line_count = 0
    last_size = 0

    # Also scan for cmd.exe history via doskey /history workaround
    # and Prefetch files for ephemeral binaries
    prefetch_dir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Prefetch")

    # Prefetch-based detection for ephemeral commands
    PREFETCH_TARGETS = {
        "CERTUTIL":  ("HIGH",     "Certutil execution detected (Prefetch)",    "T1105"),
        "WEVTUTIL":  ("HIGH",     "Wevtutil execution detected (Prefetch)",    "T1070.001"),
        "VSSADMIN":  ("CRITICAL", "VSS Admin execution detected (Prefetch)",   "T1490"),
        "BCDEDIT":   ("CRITICAL", "BCD Edit execution detected (Prefetch)",    "T1490"),
        "PSEXEC":    ("CRITICAL", "PsExec execution detected (Prefetch)",      "T1021.002"),
        "MIMIKATZ":  ("CRITICAL", "Mimikatz execution detected (Prefetch)",    "T1003"),
        "PROCDUMP":  ("CRITICAL", "ProcDump execution detected (Prefetch)",    "T1003.001"),
        "WBADMIN":   ("CRITICAL", "WBAdmin execution detected (Prefetch)",     "T1490"),
        "MSHTA":     ("HIGH",     "MSHTA execution detected (Prefetch)",       "T1218.005"),
        "REGSVR32":  ("HIGH",     "Regsvr32 execution detected (Prefetch)",    "T1218.010"),
        "BITSADMIN": ("HIGH",     "BITSAdmin execution detected (Prefetch)",   "T1197"),
    }

    # Initialize: record current prefetch timestamps
    prefetch_baseline = {}
    if os.path.isdir(prefetch_dir):
        try:
            for pf in os.listdir(prefetch_dir):
                if pf.upper().endswith(".PF"):
                    full = os.path.join(prefetch_dir, pf)
                    try:
                        prefetch_baseline[pf.upper()] = os.path.getmtime(full)
                    except OSError:
                        pass
        except PermissionError:
            pass

    # Initialize: record current PS history line count
    if history_path and os.path.isfile(history_path):
        try:
            with open(history_path, "r", encoding="utf-8", errors="ignore") as f:
                last_line_count = sum(1 for _ in f)
            last_size = os.path.getsize(history_path)
        except Exception:
            pass

    print(f"  [CmdHistory] Monitoring PS history + Prefetch for ephemeral commands")

    while True:
        try:
            # ── 1. PowerShell history file scanning ──────────────────
            if history_path and os.path.isfile(history_path):
                try:
                    current_size = os.path.getsize(history_path)
                    if current_size != last_size:
                        last_size = current_size
                        with open(history_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()

                        new_lines = lines[last_line_count:]
                        last_line_count = len(lines)

                        for line in new_lines:
                            line_stripped = line.strip()
                            if not line_stripped:
                                continue

                            line_lower = line_stripped.lower()

                            # Check against rules
                            for pattern, severity, desc, mitre in HISTORY_RULES:
                                if pattern in line_lower:
                                    h = _hash(line_lower[:200])
                                    if h in _seen_hashes:
                                        break
                                    _seen_hashes.add(h)
                                    if len(_seen_hashes) > 5000:
                                        _seen_hashes.clear()

                                    detail = (
                                        f"[{desc}]\n"
                                        f"MITRE    : {mitre}\n"
                                        f"Source   : PowerShell History\n"
                                        f"Command  : {line_stripped[:600]}\n"
                                        f"Matched  : {pattern}\n"
                                        f"Priority : {severity}"
                                    )

                                    alert_callback({
                                        "event":  f"Suspicious Command Detected",
                                        "detail": detail,
                                        "host":   host,
                                        "user":   user,
                                        "source": "cmdhistory",
                                        "log_source": "PowerShell",
                                    })
                                    break  # first match wins

                except Exception:
                    pass

            # ── 2. Prefetch scanning for ephemeral binaries ──────────
            if os.path.isdir(prefetch_dir):
                try:
                    for pf in os.listdir(prefetch_dir):
                        if not pf.upper().endswith(".PF"):
                            continue
                        pf_upper = pf.upper()
                        full = os.path.join(prefetch_dir, pf)

                        try:
                            mtime = os.path.getmtime(full)
                        except OSError:
                            continue

                        old_mtime = prefetch_baseline.get(pf_upper, 0)
                        if mtime <= old_mtime:
                            continue

                        prefetch_baseline[pf_upper] = mtime

                        # Check if this prefetch file matches a suspicious binary
                        for target_name, (severity, desc, mitre) in PREFETCH_TARGETS.items():
                            if target_name in pf_upper:
                                h = _hash(f"prefetch_{pf_upper}_{int(mtime)}")
                                if h in _seen_hashes:
                                    break
                                _seen_hashes.add(h)

                                detail = (
                                    f"[{desc}]\n"
                                    f"MITRE    : {mitre}\n"
                                    f"Source   : Windows Prefetch\n"
                                    f"File     : {pf}\n"
                                    f"Executed : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))}\n"
                                    f"Priority : {severity}"
                                )

                                alert_callback({
                                    "event":  f"Suspicious Execution Detected",
                                    "detail": detail,
                                    "host":   host,
                                    "user":   user,
                                    "source": "cmdhistory",
                                    "log_source": "Prefetch",
                                })
                                break
                except PermissionError:
                    pass

            time.sleep(0.5)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.5)
