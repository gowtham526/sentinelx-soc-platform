"""
SentinelX Registry Detector v3.0
==================================
Monitors Windows registry autorun keys for persistence.

Changes from v2.4
─────────────────
- Removed "severity" key from alert_callback — pipeline decides via
  REGISTRY_RISK:<level> hint embedded in detail.
- _score_value() result is now surfaced as REGISTRY_RISK:HIGH/CRITICAL
  in detail rather than passed as a direct severity override.
- Added MITRE technique hint (T1547.001) to detail for better
  pipeline MITRE mapping accuracy.
- Deleted entry alert also uses REGISTRY_RISK hint instead of
  hardcoded "MEDIUM" severity.
- Added more MALWARE_KEYWORDS covering LOLBins and evasion patterns.
- Added more SAFE_KEYWORDS to reduce IT admin false positives.
"""

import time
import socket
import os

# Every other Windows-only detector in this package (sysmon_file_detector,
# sysmon_network_detector) guards its platform import and degrades to a
# clear warning instead of crashing. This one didn't — an import failure
# here happened at module load time, before Flask or any other detector
# started, and took the entire app down with it. Same guard, for consistency
# and so this module is at least importable for testing on any platform.
try:
    import winreg
    WINREG_OK = True
except ImportError:
    WINREG_OK = False
    print("[RegistryDetector] WARNING: winreg not available (non-Windows "
          "platform) — registry persistence monitoring disabled")

# ─────────────────────────────────────────────────────────────
# REGISTRY KEYS TO WATCH
# (built only when winreg is actually available — these reference
# winreg constants directly, so this must stay behind the same guard)
# ─────────────────────────────────────────────────────────────

WATCH_KEYS = [] if not WINREG_OK else [
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),

    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),

    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),

    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),

    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
]

# ─────────────────────────────────────────────────────────────
# MALWARE KEYWORDS → REGISTRY_RISK:CRITICAL
# ─────────────────────────────────────────────────────────────

MALWARE_KEYWORDS = [
    # Known malware names / tools
    "payload", "evil", "malware", "virus", "trojan",
    "hack", "mimikatz", "meterpreter", "rat", "shell",
    "beacon", "stealer", "inject", "dropper", "exploit",
    "backdoor", "stager", "c2", "ransomware", "keylog",
    # LOLBin patterns that are suspicious in a Run key
    "powershell -enc", "powershell -w hidden", "powershell -windowstyle",
    "cmd /c", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "msiexec /q",
    "certutil -decode", "bitsadmin /transfer",
    # High-risk paths in a Run key value
    "temp\\", "tmp\\", "appdata\\roaming\\",
    "\\public\\", "\\downloads\\", "\\recycle",
]

# ─────────────────────────────────────────────────────────────
# SUSPICIOUS PATHS → REGISTRY_RISK:HIGH
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\roaming\\",
    "\\programdata\\", "\\public\\", "\\downloads\\",
    "\\recycle\\", "\\$recycle.bin\\",
]

# ─────────────────────────────────────────────────────────────
# SAFE KEYWORDS → suppress alert entirely
# ─────────────────────────────────────────────────────────────

SAFE_KEYWORDS = [
    # Microsoft and common signed software
    "onedrive", "teams", "discord", "spotify", "steam",
    "chrome", "edge", "firefox", "zoom", "skype",
    "dropbox", "googledrive", "whatsapp", "telegram",
    "nvidia", "amd", "realtek", "intel",
    "ctfmon", "windows security", "windows defender",
    "microsoft office", "microsoft update",
    "securityhealthsystray", "securityhealthservice",
    "program files\\microsoft", "program files (x86)\\microsoft",
    # IT admin tools known-good
    "bginfo", "sysinternals", "procmon", "autoruns",
    "sccm", "msiexec /passive", "msiexec /i",
]


def _get_registry_values(hive, subkey):
    """Read all values from a registry key. Returns dict {name: data}."""
    values = {}
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
        i   = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                values[name]  = str(data)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass
    return values


def _score_value(name: str, data: str) -> tuple:
    """
    Score a registry value.
    Returns (risk_hint, is_suspicious).
    risk_hint → "CRITICAL", "HIGH", or "MEDIUM".
    is_suspicious → False means skip entirely (safe entry).
    """
    combined = (name + " " + data).lower()

    # Known-safe → suppress
    if any(kw in combined for kw in SAFE_KEYWORDS):
        return None, False

    # Malware keywords → CRITICAL
    for kw in MALWARE_KEYWORDS:
        if kw in combined:
            return "CRITICAL", True

    # Suspicious paths → HIGH
    for sp in SUSPICIOUS_PATHS:
        if sp in combined:
            return "HIGH", True

    # New unknown Run key entry → MEDIUM (persistence is always notable)
    return "MEDIUM", True


def monitor_registry(alert_callback):
    """
    Monitor registry run keys for new or modified entries.
    Captures a clean baseline at startup — only new entries trigger alerts.

    severity is NOT set in alert_callback — pipeline decides via
    REGISTRY_RISK:<level> embedded in detail.
    """
    if not WINREG_OK:
        print("  [WARN] winreg not available — registry detector inactive")
        return

    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    # Capture baseline
    baseline = {}
    for hive, subkey in WATCH_KEYS:
        key_id             = f"{hive}\\{subkey}"
        baseline[key_id]   = _get_registry_values(hive, subkey)

    seen_alerts: set = set()

    print(f"  [RegistryDetector] Baseline captured — monitoring {len(WATCH_KEYS)} keys")

    while True:
        try:
            for hive, subkey in WATCH_KEYS:
                key_id  = f"{hive}\\{subkey}"
                current = _get_registry_values(hive, subkey)
                saved   = baseline.get(key_id, {})

                # ── NEW entries ──────────────────────────────
                for name, data in current.items():
                    if name in saved:
                        continue

                    alert_key = f"{key_id}|{name}|{data[:40]}"
                    if alert_key in seen_alerts:
                        continue
                    seen_alerts.add(alert_key)

                    risk_hint, suspicious = _score_value(name, data)
                    if not suspicious:
                        # Known-safe — add to baseline quietly
                        baseline[key_id][name] = data
                        continue

                    detail = (
                        f"New registry autorun entry detected\n"
                        f"Key            : {subkey}\n"
                        f"Name           : {name}\n"
                        f"Value          : {data[:200]}\n"
                        f"MITRE          : T1547.001 — Registry Run Keys\n"
                        f"REGISTRY_RISK:{risk_hint}"  # scored by calculate_severity
                    )

                    alert_callback({
                        "event":  "Registry Persistence Detected",
                        "detail": detail,
                        # NO "severity" key — pipeline decides.
                        "host":   host,
                        "user":   user,
                        "source": "registry",
                        "log_source": "Registry",
                    })

                    baseline[key_id][name] = data

                # ── DELETED entries (anti-forensics indicator) ──
                for name in list(saved.keys()):
                    if name in current:
                        continue

                    alert_key = f"DEL|{key_id}|{name}"
                    if alert_key in seen_alerts:
                        continue
                    seen_alerts.add(alert_key)

                    detail = (
                        f"Registry autorun entry REMOVED — possible anti-forensics\n"
                        f"Key            : {subkey}\n"
                        f"Name           : {name}\n"
                        f"MITRE          : T1070.004 — File/Registry Deletion\n"
                        f"REGISTRY_RISK:MEDIUM"
                    )

                    alert_callback({
                        "event":  "Registry Key Deleted",
                        "detail": detail,
                        # NO "severity" key — pipeline decides.
                        "host":   host,
                        "user":   user,
                        "source": "registry",
                        "log_source": "Registry",
                    })

                    del baseline[key_id][name]

            time.sleep(3)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(3)