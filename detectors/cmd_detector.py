"""
SentinelX CMD (Command Prompt) Detector v1.0
Monitors cmd.exe for attacker TTPs — mirrors and extends powershell_detector
with CMD-specific attack patterns.

Covers: MITRE ATT&CK T1059.003, T1547.001, T1112, T1003, T1082,
        T1069, T1087, T1021, T1562, T1070, T1490
"""

import psutil
import time
import socket
import os
import hashlib

_seen_cmdlines = set()

# ─────────────────────────────────────────────────────────────────────────
# DETECTION RULES  (pattern_lower, priority_label, description, mitre)
# First match = highest priority.
# NO severity key is sent — alert_pipeline.calculate_severity() decides.
# ─────────────────────────────────────────────────────────────────────────

CMD_RULES = [

    # ── CRITICAL: Credential Theft ──────────────────────────────────────
    ("mimikatz",                  "CRITICAL", "Mimikatz credential dumper",                    "T1003"),
    ("sekurlsa",                  "CRITICAL", "Mimikatz sekurlsa module (LSASS dump)",          "T1003.001"),
    ("procdump",                  "CRITICAL", "ProcDump — possible LSASS memory dump",          "T1003.001"),
    ("lsass",                     "CRITICAL", "LSASS process reference (credential access)",    "T1003.001"),
    ("gsecdump",                  "CRITICAL", "GSecdump credential extractor",                  "T1003"),
    ("wce.exe",                   "CRITICAL", "Windows Credential Editor",                      "T1003"),
    ("pwdump",                    "CRITICAL", "Password dump utility",                          "T1003"),
    ("fgdump",                    "CRITICAL", "FGdump credential extractor",                    "T1003"),

    # ── CRITICAL: Defense Evasion / Destruction ──────────────────────────
    ("vssadmin delete shadows",   "CRITICAL", "Volume shadow copy deletion (ransomware/wiper)", "T1490"),
    ("vssadmin delete",           "CRITICAL", "VSS shadow deletion (data destruction)",         "T1490"),
    ("wmic shadowcopy delete",    "CRITICAL", "Shadow copy deletion via WMI",                   "T1490"),
    ("bcdedit /set",              "CRITICAL", "Boot config modification — recovery disable",    "T1490"),
    ("wbadmin delete",            "CRITICAL", "Backup deletion command",                        "T1490"),
    ("netsh advfirewall set allprofiles state off", "CRITICAL", "Firewall disabled — all profiles", "T1562.004"),
    ("netsh firewall set opmode disable",           "CRITICAL", "Firewall disabled (legacy cmd)",    "T1562.004"),
    ("sc stop windefend",         "CRITICAL", "Windows Defender service stopped",               "T1562.001"),
    ("sc delete windefend",       "CRITICAL", "Windows Defender service deleted",               "T1562.001"),
    ("sc config windefend start= disabled", "CRITICAL", "Defender set to disabled on boot",     "T1562.001"),
    ("taskkill /im msmpeng",      "CRITICAL", "MsMpEng (Defender engine) killed",               "T1562.001"),
    ("reg add hklm\\software\\microsoft\\windows defender", "CRITICAL", "Defender registry tamper", "T1562.001"),

    # ── CRITICAL: Ransomware / Wiper indicators ──────────────────────────
    ("cipher /w",                 "CRITICAL", "Secure wipe via cipher (data destruction)",      "T1070.004"),
    ("format c:",                 "CRITICAL", "Drive format command — critical data loss",      "T1561"),
    ("del /f /s /q c:",           "CRITICAL", "Mass file deletion from C:",                     "T1070.004"),
    ("rd /s /q c:",               "CRITICAL", "Recursive directory removal from C:",            "T1070.004"),
    ("attrib +h +s +r",           "CRITICAL", "Mass file hiding (ransomware prep)",             "T1564"),

    # ── CRITICAL: Lateral Movement ──────────────────────────────────────
    ("psexec",                    "CRITICAL", "PsExec remote command execution",                "T1021.002"),
    ("wmic /node:",               "CRITICAL", "WMI remote execution",                           "T1047"),
    ("schtasks /create",          "CRITICAL", "Scheduled task creation (persistence/lat.mov)", "T1053.005"),
    ("at \\\\",                   "CRITICAL", "Legacy 'at' remote scheduling",                  "T1053.002"),

    # ── HIGH: Persistence ────────────────────────────────────────────────
    ("reg add hkcu\\software\\microsoft\\windows\\currentversion\\run", "HIGH", "Run key persistence (HKCU)", "T1547.001"),
    ("reg add hklm\\software\\microsoft\\windows\\currentversion\\run", "HIGH", "Run key persistence (HKLM)", "T1547.001"),
    ("schtasks /create /sc onlogon", "HIGH", "Scheduled task on logon (persistence)",         "T1053.005"),
    ("schtasks /create /sc onstart", "HIGH", "Scheduled task at system start (persistence)",  "T1053.005"),
    ("reg add hklm\\system\\currentcontrolset\\services", "HIGH", "Service registry persistence", "T1543.003"),
    ("sc create",                 "HIGH",     "Service creation (persistence)",                 "T1543.003"),
    ("sc config",                 "HIGH",     "Service config modification",                    "T1543.003"),
    ("netsh add helper",          "HIGH",     "Netsh helper DLL (persistence mechanism)",       "T1546.007"),

    # ── HIGH: Download Cradles ───────────────────────────────────────────
    ("certutil -decode",          "HIGH",     "Certutil base64 decode (payload staging)",       "T1027"),
    ("certutil -urlcache",        "HIGH",     "Certutil download cradle",                       "T1105"),
    ("certutil -split",           "HIGH",     "Certutil file splitting (staging)",              "T1027"),
    ("bitsadmin /transfer",       "HIGH",     "BITSAdmin download cradle",                      "T1197"),
    ("bitsadmin /create",         "HIGH",     "BITSAdmin job creation",                         "T1197"),
    ("curl -o ",                  "HIGH",     "Curl download to local file",                    "T1105"),
    ("wget ",                     "HIGH",     "Wget download (curl alias or standalone)",       "T1105"),
    ("mshta http",                "HIGH",     "MSHTA remote HTA download+exec",                 "T1218.005"),
    ("mshta.exe vbscript",        "HIGH",     "MSHTA VBScript inline execution",                "T1218.005"),
    ("regsvr32 /s /n /u /i:http", "HIGH",     "Regsvr32 squiblydoo download+exec",             "T1218.010"),
    ("regsvr32 /s /n /u /i:",     "HIGH",     "Regsvr32 remote COM registration",              "T1218.010"),
    ("rundll32 javascript:",       "HIGH",    "Rundll32 JavaScript execution",                  "T1218.011"),
    ("cmstp /s",                  "HIGH",     "CMSTP UAC bypass",                              "T1218.003"),

    # ── HIGH: Privilege Escalation ────────────────────────────────────────
    ("runas /user:administrator", "HIGH",     "Runas as administrator",                         "T1548.002"),
    ("icacls * /grant everyone",  "HIGH",     "Permissive ACL grant — privilege escalation",   "T1222"),
    ("takeown /f",                "HIGH",     "TakeOwn file ownership change",                  "T1222"),
    ("wmic useraccount",          "HIGH",     "WMIC user account manipulation",                 "T1069"),

    # ── HIGH: Exfiltration / C2 ──────────────────────────────────────────
    ("ftp -s:",                   "HIGH",     "FTP script-mode file transfer (exfil)",          "T1048"),
    ("xcopy /s",                  "HIGH",     "Mass file copy (possible exfil staging)",        "T1048"),
    ("compact /c",                "HIGH",     "File compression (exfil staging)",               "T1560"),
    ("rar a",                     "HIGH",     "RAR archive creation (exfil staging)",           "T1560"),
    ("7z a",                      "HIGH",     "7-Zip archive creation (exfil staging)",         "T1560"),
    ("net use \\\\",              "HIGH",     "Network share mount (lateral movement/exfil)",   "T1021.002"),
    ("copy \\\\",                 "HIGH",     "Remote copy to/from UNC path (exfil/lat.mov)",  "T1021"),

    # ── MEDIUM: Reconnaissance ───────────────────────────────────────────
    ("whoami /all",               "MEDIUM",   "Full whoami with privileges and SIDs",           "T1033"),
    ("whoami /priv",              "MEDIUM",   "Privilege enumeration",                          "T1057"),
    ("whoami",                    "LOW",      "Current user discovery",                         "T1033"),
    ("net user",                  "MEDIUM",   "User account enumeration",                       "T1087.001"),
    ("net localgroup",            "MEDIUM",   "Local group enumeration",                        "T1069.001"),
    ("net group /domain",         "MEDIUM",   "Domain group enumeration",                       "T1069.002"),
    ("net user /domain",          "MEDIUM",   "Domain user enumeration",                        "T1087.002"),
    ("net accounts",              "MEDIUM",   "Account policy enumeration",                     "T1201"),
    ("net share",                 "MEDIUM",   "Network share enumeration",                      "T1135"),
    ("net view",                  "MEDIUM",   "Network host discovery",                         "T1018"),
    ("net session",               "MEDIUM",   "Active session enumeration",                     "T1049"),
    ("ipconfig /all",             "MEDIUM",   "Full network config dump",                       "T1016"),
    ("ipconfig",                  "LOW",      "Network configuration discovery",                "T1016"),
    ("arp -a",                    "MEDIUM",   "ARP table enumeration (neighbor discovery)",     "T1018"),
    ("route print",               "MEDIUM",   "Routing table dump",                             "T1016.001"),
    ("netstat -ano",              "MEDIUM",   "Active connections with PIDs",                   "T1049"),
    ("netstat",                   "LOW",      "Network connections discovery",                  "T1049"),
    ("tasklist /svc",             "MEDIUM",   "Running services with processes",                "T1057"),
    ("tasklist /v",               "MEDIUM",   "Verbose running process list",                   "T1057"),
    ("tasklist",                  "LOW",      "Running processes list",                         "T1057"),
    ("systeminfo",                "MEDIUM",   "Full OS/hardware enumeration",                   "T1082"),
    ("wmic os get",               "MEDIUM",   "WMI OS version enumeration",                     "T1082"),
    ("wmic cpu get",              "MEDIUM",   "WMI CPU enumeration",                            "T1082"),
    ("wmic computersystem get",   "MEDIUM",   "WMI computer details",                           "T1082"),
    ("wmic product get",          "MEDIUM",   "Installed software via WMI",                     "T1518"),
    ("wmic process get",          "MEDIUM",   "Process list via WMI",                           "T1057"),
    ("wmic startup get",          "MEDIUM",   "WMI startup entry enumeration",                  "T1547"),
    ("reg query hklm",            "MEDIUM",   "HKLM registry key query",                       "T1012"),
    ("reg query hkcu",            "MEDIUM",   "HKCU registry key query",                       "T1012"),
    ("reg query hklm\\sam",       "HIGH",     "SAM database registry query (credential access)","T1003.002"),
    ("reg save hklm\\sam",        "HIGH",     "SAM database save to file (credential access)",  "T1003.002"),
    ("reg save hklm\\system",     "HIGH",     "SYSTEM hive save (credential access)",           "T1003.002"),
    ("reg save hklm\\security",   "HIGH",     "SECURITY hive save (credential access)",         "T1003.002"),
    ("nltest /dclist",            "MEDIUM",   "Domain controller discovery",                   "T1018"),
    ("nltest /domain_trusts",     "MEDIUM",   "Domain trust enumeration",                      "T1482"),
    ("nltest",                    "MEDIUM",   "Nltest domain reconnaissance",                  "T1482"),
    ("dsquery",                   "MEDIUM",   "Active Directory DSQUERY enumeration",           "T1018"),
    ("ping -n",                   "LOW",      "ICMP ping (host discovery)",                     "T1018"),
    ("nslookup",                  "LOW",      "DNS lookup (reconnaissance)",                    "T1018"),
    ("tracert",                   "LOW",      "Traceroute (network path discovery)",            "T1016"),

    # ── MEDIUM: Anti-Forensics / Log Tampering ────────────────────────────
    ("wevtutil cl",               "HIGH",     "Windows event log cleared",                     "T1070.001"),
    ("wevtutil el",               "MEDIUM",   "Event log listing (pre-erase recon)",           "T1070.001"),
    ("del /f /q %windir%\\system32\\winevt", "HIGH", "Event log files deleted", "T1070.001"),
    ("fsutil usn deletejournal",  "HIGH",     "USN Journal deletion (anti-forensics)",         "T1070.004"),
    ("reg delete hklm",           "MEDIUM",   "HKLM registry key deletion",                    "T1112"),
    ("reg delete hkcu",           "MEDIUM",   "HKCU registry key deletion",                    "T1112"),

    # ── MEDIUM: Account Manipulation ─────────────────────────────────────
    ("net user /add",             "HIGH",     "New local user account created",                "T1136.001"),
    ("net localgroup administrators /add", "CRITICAL", "User added to Administrators group",  "T1098"),
    ("net user /active:yes",      "MEDIUM",   "Account re-enabled",                            "T1098"),
    ("net user /passwordchg:no",  "MEDIUM",   "Password-change disabled on account",           "T1098"),

    # ── MEDIUM: Execution via LOLBins ─────────────────────────────────────
    ("msiexec /quiet /i",         "MEDIUM",   "Silent MSI package install",                    "T1218.007"),
    ("msiexec /q /i",             "MEDIUM",   "Silent MSI install (short flag)",               "T1218.007"),
    ("wmic process call create",  "HIGH",     "WMI process spawning",                          "T1047"),
    ("forfiles /m",               "MEDIUM",   "Forfiles LOLBin execution",                     "T1059.003"),
    ("pcalua.exe",                "MEDIUM",   "Program Compatibility Assistant LOLBin",        "T1218"),
    ("control.exe",               "MEDIUM",   "Control panel LOLBin for DLL exec",             "T1218"),
    ("odbcconf.exe",              "MEDIUM",   "ODBCCONF LOLBin (DLL sideload)",                "T1218"),
    ("xwizard.exe",               "MEDIUM",   "Xwizard LOLBin execution",                      "T1218"),

    # ── LOW: General Recon (still worth logging) ──────────────────────────
    ("hostname",                  "LOW",      "Hostname discovery",                             "T1082"),
    ("set ",                      "LOW",      "Environment variable listing",                   "T1082"),
    ("dir /s",                    "LOW",      "Deep recursive directory listing",               "T1083"),
    ("find /i",                   "LOW",      "Findstr/find file content search",              "T1083"),
    ("findstr /s",                "LOW",      "Findstr recursive search",                      "T1083"),
    ("type ",                     "LOW",      "File content read via type",                    "T1083"),
    ("echo %username%",           "LOW",      "Username env-var disclosure",                   "T1033"),
    ("echo %computername%",       "LOW",      "Computer name env-var disclosure",              "T1082"),
    ("echo %userdomain%",         "LOW",      "Domain env-var disclosure",                     "T1082"),
]

# ─────────────────────────────────────────────────────────────────────────
# NOISE — skip these common legitimate cmd usages
# ─────────────────────────────────────────────────────────────────────────
NOISE_CMDLINE = [
    "visual studio",
    "vscode",
    "microsoft.management",
    "antimalware",
    "splunk",
    "chocolatey",
    "git.exe",
    "pip install",
    "npm install",
]

# Processes that are cmd.exe wrappers (to extend detection scope)
CMD_PROCESS_NAMES = {"cmd.exe", "cmd", "command.com"}


def _cmdline_hash(cmdline: str) -> str:
    return hashlib.md5(cmdline.encode("utf-8", errors="ignore")).hexdigest()


def monitor_cmd(alert_callback):
    """
    Scan running processes every 0.5 seconds.
    Detect cmd.exe / command.com processes with suspicious TTPs.
    Deduplicates by cmdline content hash so short-lived commands still fire.
    """
    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    print("  CMD detector active (covers cmd.exe TTPs + LOLBins)")

    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    if name not in CMD_PROCESS_NAMES:
                        continue

                    cmdline_list = proc.info["cmdline"] or []
                    cmdline = " ".join(cmdline_list).strip()
                    if not cmdline:
                        continue

                    cmdline_lower = cmdline.lower()

                    # Skip noise
                    if any(n in cmdline_lower for n in NOISE_CMDLINE):
                        continue

                    # Match rules — first = highest priority
                    matched = None
                    for pattern, priority, desc, mitre in CMD_RULES:
                        if pattern in cmdline_lower:
                            matched = (pattern, priority, desc, mitre)
                            break

                    if not matched:
                        continue

                    pattern, priority, desc, mitre = matched

                    # Dedup by cmdline hash
                    chash = _cmdline_hash(cmdline_lower[:300])
                    if chash in _seen_cmdlines:
                        continue
                    _seen_cmdlines.add(chash)
                    if len(_seen_cmdlines) > 3000:
                        _seen_cmdlines.clear()

                    proc_user = (proc.info.get("username") or user)

                    detail = (
                        f"[{desc}]\n"
                        f"MITRE    : {mitre}\n"
                        f"Process  : {name} (PID {proc.info['pid']})\n"
                        f"User     : {proc_user}\n"
                        f"CMD      : {cmdline[:600]}\n"
                        f"Matched  : {pattern}\n"
                        f"Priority : {priority}"
                    )

                    alert_callback({
                        "event":  "Suspicious CMD Activity Detected",
                        "detail": detail,
                        # NO severity key — alert_pipeline.calculate_severity() decides
                        "host":   host,
                        "user":   proc_user,
                        "source": "cmd",
                        "log_source": "CMD",
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass

            time.sleep(0.15)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.15)
