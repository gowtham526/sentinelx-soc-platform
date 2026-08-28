"""
SentinelX Universal Process Scanner v1.0
==========================================
Catches ANY suspicious process regardless of parent.
Unlike powershell_detector (which only scans powershell.exe) and
cmd_detector (which only scans cmd.exe), this detector scans ALL
running processes against a list of known-suspicious executables
AND their command-line arguments.

This catches ephemeral commands like:
  certutil.exe, wevtutil.exe, vssadmin.exe, bcdedit.exe, mshta.exe,
  regsvr32.exe, bitsadmin.exe, etc.

These tools are "Living Off The Land Binaries" (LOLBins) — legitimate
Windows utilities that attackers abuse. They spawn, execute in <100ms,
and exit before normal scanners can catch them.

Strategy: Scan ALL processes every 0.1 seconds with minimal overhead.
"""

import psutil
import time
import socket
import os
import hashlib

_seen = set()

# ─────────────────────────────────────────────────────────────
# SUSPICIOUS EXECUTABLES — any of these running = worth checking
# Maps exe name (lowercase, no .exe) -> list of (cmdline_pattern, severity, description, mitre)
# If cmdline_pattern is None, any execution of this binary triggers.
# ─────────────────────────────────────────────────────────────

LOLBIN_RULES = {
    "certutil": [
        ("-urlcache",   "HIGH",     "Certutil download cradle",                "T1105"),
        ("-decode",     "HIGH",     "Certutil base64 decode (payload staging)","T1027"),
        ("-split",      "HIGH",     "Certutil file splitting",                 "T1027"),
        ("-encodehex",  "HIGH",     "Certutil hex encode (obfuscation)",       "T1027"),
        (None,          "MEDIUM",   "Certutil execution detected",             "T1105"),
    ],
    "wevtutil": [
        ("cl ",         "HIGH",     "Windows Event Log cleared",               "T1070.001"),
        ("cl\t",        "HIGH",     "Windows Event Log cleared",               "T1070.001"),
        (None,          "MEDIUM",   "Wevtutil execution detected",             "T1070.001"),
    ],
    "vssadmin": [
        ("delete",      "CRITICAL", "Volume shadow copy deletion (ransomware)","T1490"),
        (None,          "HIGH",     "VSS Admin execution detected",            "T1490"),
    ],
    "bcdedit": [
        ("/set",        "CRITICAL", "Boot config modification — recovery disable", "T1490"),
        (None,          "HIGH",     "BCDEdit execution detected",              "T1490"),
    ],
    "wbadmin": [
        ("delete",      "CRITICAL", "Backup deletion command",                 "T1490"),
        (None,          "HIGH",     "WBAdmin execution detected",              "T1490"),
    ],
    "mshta": [
        ("http",        "HIGH",     "MSHTA remote HTA download+exec",          "T1218.005"),
        ("vbscript",    "HIGH",     "MSHTA VBScript inline execution",         "T1218.005"),
        (None,          "MEDIUM",   "MSHTA execution detected",                "T1218.005"),
    ],
    "regsvr32": [
        ("/s /n /u /i:", "HIGH",    "Regsvr32 squiblydoo attack",              "T1218.010"),
        ("/i:http",      "HIGH",    "Regsvr32 remote COM registration",        "T1218.010"),
        (None,           "MEDIUM",  "Regsvr32 execution detected",             "T1218.010"),
    ],
    "bitsadmin": [
        ("/transfer",   "HIGH",     "BITSAdmin download cradle",               "T1197"),
        ("/create",     "HIGH",     "BITSAdmin job creation",                  "T1197"),
        (None,          "MEDIUM",   "BITSAdmin execution detected",            "T1197"),
    ],
    "rundll32": [
        ("javascript",  "HIGH",     "Rundll32 JavaScript execution",           "T1218.011"),
        ("http",        "HIGH",     "Rundll32 remote DLL load",                "T1218.011"),
    ],
    "cmstp": [
        ("/s",          "HIGH",     "CMSTP UAC bypass",                        "T1218.003"),
    ],
    "msiexec": [
        ("/quiet",      "MEDIUM",   "Silent MSI package install",              "T1218.007"),
        ("/q ",         "MEDIUM",   "Silent MSI install (short flag)",         "T1218.007"),
    ],
    "schtasks": [
        ("/create",     "CRITICAL", "Scheduled task creation (persistence)",   "T1053.005"),
        ("/change",     "HIGH",     "Scheduled task modification",             "T1053.005"),
    ],
    "at": [
        ("\\\\",        "CRITICAL", "Legacy 'at' remote scheduling",           "T1053.002"),
    ],
    "sc": [
        ("stop windefend",   "CRITICAL", "Windows Defender service stopped",    "T1562.001"),
        ("delete windefend", "CRITICAL", "Windows Defender service deleted",    "T1562.001"),
        ("create",           "HIGH",     "Service creation (persistence)",      "T1543.003"),
        ("config",           "HIGH",     "Service config modification",         "T1543.003"),
    ],
    "reg": [
        ("save hklm\\sam",     "CRITICAL", "SAM database save (credential theft)", "T1003.002"),
        ("save hklm\\system",  "CRITICAL", "SYSTEM hive save (credential theft)",  "T1003.002"),
        ("save hklm\\security","CRITICAL", "SECURITY hive save (credential theft)","T1003.002"),
    ],
    "netsh": [
        ("advfirewall set allprofiles state off", "CRITICAL", "Firewall disabled — all profiles", "T1562.004"),
        ("firewall set opmode disable",           "CRITICAL", "Firewall disabled (legacy)",       "T1562.004"),
        ("add helper",                            "HIGH",     "Netsh helper DLL (persistence)",   "T1546.007"),
    ],
    "taskkill": [
        ("msmpeng",     "CRITICAL", "Defender engine killed",                  "T1562.001"),
        ("defender",    "CRITICAL", "Defender process killed",                 "T1562.001"),
    ],
    "cipher": [
        ("/w",          "CRITICAL", "Secure wipe via cipher (data destruction)","T1070.004"),
    ],
    "procdump": [
        ("lsass",       "CRITICAL", "LSASS memory dump (credential theft)",    "T1003.001"),
        (None,          "HIGH",     "ProcDump execution detected",             "T1003.001"),
    ],
    "mimikatz": [
        (None,          "CRITICAL", "Mimikatz credential dumper detected",     "T1003"),
    ],
    "psexec": [
        (None,          "CRITICAL", "PsExec remote execution detected",        "T1021.002"),
    ],
    "psexec64": [
        (None,          "CRITICAL", "PsExec64 remote execution detected",      "T1021.002"),
    ],
    "wce": [
        (None,          "CRITICAL", "Windows Credential Editor detected",      "T1003"),
    ],
    "pwdump": [
        (None,          "CRITICAL", "Password dump utility detected",          "T1003"),
    ],
    "fgdump": [
        (None,          "CRITICAL", "FGdump credential extractor detected",    "T1003"),
    ],
    "gsecdump": [
        (None,          "CRITICAL", "GSecdump credential extractor detected",  "T1003"),
    ],
    "sharphound": [
        (None,          "HIGH",     "SharpHound AD enumeration tool",          "T1069"),
    ],
    "rubeus": [
        (None,          "CRITICAL", "Rubeus Kerberos attack tool",             "T1558"),
    ],
    "bloodhound": [
        (None,          "HIGH",     "BloodHound attack path tool",             "T1069"),
    ],
    "lazagne": [
        (None,          "CRITICAL", "LaZagne credential harvester",            "T1003"),
    ],
    "nmap": [
        (None,          "HIGH",     "Nmap network scanner detected",           "T1046"),
    ],
}

# Skip these process names entirely to avoid noise
NOISE_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe",
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "conhost.exe", "dwm.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchhost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "textinputhost.exe", "applicationframehost.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe",
    "code.exe", "devenv.exe", "idea64.exe",
    "python.exe", "pythonw.exe", "python3.exe", "py.exe",
    "flutter_tool.exe", "dart.exe", "java.exe", "javaw.exe",
    "node.exe", "npm.exe", "git.exe",
    "winget.exe", "windowsterminal.exe", "openssh.exe",
    "audiodg.exe", "fontdrvhost.exe", "ctfmon.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "msmpeng.exe", "nissrv.exe",
    "vmware.exe", "vmware-vmx.exe", "vmnat.exe", "vmnetdhcp.exe",
    "vmwarehostd.exe",
    "searchindexer.exe", "searchprotocolhost.exe",
    "spoolsv.exe", "printfilterpipelinesvc.exe",
    "wuauclt.exe", "trustedinstaller.exe",
    "mmc.exe", "taskmgr.exe",
}


def _hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="ignore")).hexdigest()


def monitor_universal(alert_callback):
    """
    Scan ALL running processes every 0.1 seconds.
    Match process names against known LOLBins and suspicious tools.
    Check their command-line arguments for specific attack patterns.
    """
    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    print("  Universal Process Scanner active (LOLBins + hacker tools)")

    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    raw_name = proc.info["name"] or ""
                    name_lower = raw_name.lower()

                    # Skip noise
                    if name_lower in NOISE_PROCESSES:
                        continue

                    # Strip .exe suffix for lookup
                    base_name = name_lower.replace(".exe", "")

                    if base_name not in LOLBIN_RULES:
                        continue

                    # Get command line
                    cmdline_list = proc.info["cmdline"] or []
                    cmdline = " ".join(cmdline_list).strip()
                    cmdline_lower = cmdline.lower()

                    # Match against rules for this binary
                    rules = LOLBIN_RULES[base_name]
                    matched = None

                    for pattern, severity, desc, mitre in rules:
                        if pattern is None:
                            # Catch-all: any execution of this binary
                            matched = (pattern or base_name, severity, desc, mitre)
                            # Don't break — keep checking for more specific matches
                        elif pattern in cmdline_lower:
                            matched = (pattern, severity, desc, mitre)
                            break  # Specific match found — use it

                    if not matched:
                        continue

                    pattern, severity, desc, mitre = matched

                    # Dedup
                    h = _hash(f"{base_name}_{cmdline_lower[:200]}_{int(time.time() // 3)}")
                    if h in _seen:
                        continue
                    _seen.add(h)
                    if len(_seen) > 5000:
                        _seen.clear()

                    proc_user = proc.info.get("username") or user

                    detail = (
                        f"[{desc}]\n"
                        f"MITRE    : {mitre}\n"
                        f"Process  : {raw_name} (PID {proc.info['pid']})\n"
                        f"User     : {proc_user}\n"
                        f"CMD      : {cmdline[:600]}\n"
                        f"Matched  : {pattern}\n"
                        f"Priority : {severity}"
                    )

                    alert_callback({
                        "event":  f"{desc}",
                        "detail": detail,
                        "host":   host,
                        "user":   proc_user,
                        "source": "universal",
                        "log_source": "Process",
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass

            time.sleep(0.1)  # Ultra-fast scanning — 10 times per second

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.1)
