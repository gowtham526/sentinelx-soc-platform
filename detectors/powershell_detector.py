"""
SentinelX PowerShell + CMD-via-PS Detector v3.0
Monitors running processes for suspicious PowerShell/pwsh activity.
Also catches CMD commands piped through PowerShell (e.g. powershell -c "net user /add").

MITRE ATT&CK coverage:
  T1059.001 (PS execution), T1059.003 (CMD via PS), T1027 (obfuscation),
  T1003 (credential access), T1490 (ransomware/wiper), T1562 (defense evasion),
  T1547 (persistence), T1021 (lateral movement), T1105 (ingress tool transfer),
  T1082/T1087/T1069 (discovery/recon), T1048 (exfiltration)
"""

import psutil
import time
import socket
import os
import hashlib

_seen_cmdlines = set()  # dedup by cmdline hash, not PID

# ─────────────────────────────────────────────────────────────────────────
# DETECTION RULES
# (pattern_lower, priority_label, description)
# First match wins — order highest priority first.
# NO severity key sent — alert_pipeline.calculate_severity() is source of truth.
# ─────────────────────────────────────────────────────────────────────────

PS_RULES = [

    # ── CRITICAL: Obfuscation & Encoding ──────────────────────────────────
    ("-enc ",                      "CRITICAL", "Encoded PS command (obfuscation) [T1027]"),
    ("-encodedcommand",            "CRITICAL", "EncodedCommand flag (obfuscation) [T1027]"),
    ("frombase64string(",          "CRITICAL", "Base64 decode in PowerShell [T1027]"),
    ("invoke-expression",          "CRITICAL", "IEX code injection [T1059.001]"),
    ("iex(",                       "CRITICAL", "IEX short-form injection [T1059.001]"),
    ("[char]",                     "CRITICAL", "Char-array obfuscation in PS [T1027]"),
    ("gzip",                       "HIGH",     "Gzip decompression cradle (obfuscation) [T1027]"),
    ("io.compression",             "HIGH",     "Compression class (payload decompression) [T1027]"),
    ("memorystream",               "HIGH",     "MemoryStream usage (payload staging) [T1027]"),
    ("reflection.assembly",        "CRITICAL", ".NET assembly reflection load [T1620]"),
    ("[system.reflection",         "CRITICAL", "System.Reflection assembly load [T1620]"),
    ("::load(",                    "CRITICAL", "Assembly.Load() (in-memory exec) [T1620]"),
    ("::loadfile(",                "CRITICAL", "Assembly.LoadFile() (in-memory exec) [T1620]"),

    # ── CRITICAL: AMSI / AV Bypass ────────────────────────────────────────
    ("amsibypass",                 "CRITICAL", "AMSI bypass attempt [T1562.001]"),
    ("amsi.dll",                   "CRITICAL", "AMSI DLL reference (bypass target) [T1562.001]"),
    ("amsiutils",                  "CRITICAL", "AmsiUtils reflection bypass [T1562.001]"),
    ("setfailed",                  "CRITICAL", "AmsiInitFailed patch (AMSI bypass) [T1562.001]"),
    ("disablerealtimemonitoring",  "CRITICAL", "Defender real-time monitoring disabled [T1562.001]"),
    ("set-mppreference",           "HIGH",     "Defender preference modification [T1562.001]"),
    ("add-mppreference",           "HIGH",     "Defender exclusion added [T1562.001]"),
    ("sc stop windefend",          "CRITICAL", "Defender service stopped [T1562.001]"),
    ("sc delete windefend",        "CRITICAL", "Defender service deleted [T1562.001]"),
    ("netsh advfirewall set allprofiles state off", "CRITICAL", "Firewall disabled — all profiles [T1562.004]"),
    ("netsh firewall set opmode disable",           "CRITICAL", "Firewall disabled (legacy) [T1562.004]"),

    # ── CRITICAL: Credential Theft ────────────────────────────────────────
    ("mimikatz",                   "CRITICAL", "Mimikatz keyword [T1003]"),
    ("sekurlsa",                   "CRITICAL", "Mimikatz sekurlsa module [T1003.001]"),
    ("invoke-mimikatz",            "CRITICAL", "PowerShell Mimikatz module [T1003.001]"),
    ("invoke-kerberoast",          "CRITICAL", "Kerberoasting attack [T1558.003]"),
    ("invoke-asreproast",          "CRITICAL", "AS-REP Roasting attack [T1558.004]"),
    ("invoke-dcsync",              "CRITICAL", "DCSync credential dump [T1003.006]"),
    ("get-kerberoastableaccount",  "CRITICAL", "Kerberoastable account discovery [T1558.003]"),
    ("sharphound",                 "HIGH",     "SharpHound AD enumeration [T1069/T1087]"),
    ("bloodhound",                 "HIGH",     "BloodHound attack path tool [T1069/T1087]"),
    ("procdump",                   "CRITICAL", "ProcDump (LSASS dump likely) [T1003.001]"),
    ("lsass",                      "CRITICAL", "LSASS process reference [T1003.001]"),
    ("reg save hklm\\sam",         "CRITICAL", "SAM database save (credential access) [T1003.002]"),
    ("reg save hklm\\system",      "CRITICAL", "SYSTEM hive save (credential access) [T1003.002]"),
    ("reg save hklm\\security",    "CRITICAL", "SECURITY hive save (credential access) [T1003.002]"),
    ("reg query hklm\\sam",        "HIGH",     "SAM database query [T1003.002]"),

    # ── CRITICAL: Ransomware / Data Destruction ───────────────────────────
    ("vssadmin delete shadows",    "CRITICAL", "Shadow copy deletion (ransomware) [T1490]"),
    ("vssadmin delete",            "CRITICAL", "VSS shadow deletion [T1490]"),
    ("wmic shadowcopy delete",     "CRITICAL", "Shadow copy deletion via WMI [T1490]"),
    ("bcdedit /set",               "CRITICAL", "Boot config mod — recovery disable [T1490]"),
    ("wbadmin delete",             "CRITICAL", "Backup deletion [T1490]"),
    ("cipher /w",                  "CRITICAL", "Secure wipe via cipher [T1070.004]"),
    ("format c:",                  "CRITICAL", "Drive format command [T1561]"),
    ("remove-item -recurse -force", "CRITICAL","Mass recursive file deletion [T1070.004]"),
    ("del /f /s /q c:",            "CRITICAL", "Mass file deletion from C: [T1070.004]"),
    ("rd /s /q c:",                "CRITICAL", "Recursive directory removal from C: [T1070.004]"),

    # ── CRITICAL: Shellcode / Injection ──────────────────────────────────
    ("invoke-shellcode",           "CRITICAL", "Shellcode injection via PS [T1055]"),
    ("invoke-meterpreter",         "CRITICAL", "Meterpreter staging [T1059.001]"),
    ("invoke-reflectivepeinjection","CRITICAL","Reflective PE injection [T1055.001]"),
    ("invoke-processinjection",    "CRITICAL", "Process injection technique [T1055]"),
    ("virtualalloc",               "CRITICAL", "VirtualAlloc memory allocation (shellcode) [T1055]"),
    ("writeprocessmemory",         "CRITICAL", "WriteProcessMemory (code injection) [T1055]"),
    ("createthread",               "CRITICAL", "CreateThread from PS (shellcode exec) [T1055]"),

    # ── CRITICAL: Lateral Movement ────────────────────────────────────────
    ("invoke-wmimethod",           "CRITICAL", "WMI method invocation (lateral movement) [T1047]"),
    ("wmic /node:",                "CRITICAL", "WMI remote execution [T1047]"),
    ("psexec",                     "CRITICAL", "PsExec remote command execution [T1021.002]"),
    ("new-pssession -computername","HIGH",     "PS remote session to another host [T1021.006]"),
    ("invoke-command -computername","HIGH",    "PS remote invoke on another host [T1021.006]"),
    ("schtasks /create",           "CRITICAL", "Scheduled task creation [T1053.005]"),
    ("register-scheduledtask",     "CRITICAL", "PS scheduled task registration [T1053.005]"),

    # ── HIGH: Persistence ─────────────────────────────────────────────────
    ("reg add hkcu\\software\\microsoft\\windows\\currentversion\\run", "HIGH", "Run key persistence (HKCU) [T1547.001]"),
    ("reg add hklm\\software\\microsoft\\windows\\currentversion\\run", "HIGH", "Run key persistence (HKLM) [T1547.001]"),
    ("new-itemproperty.*run",      "HIGH",     "PS Run key persistence [T1547.001]"),
    ("sc create",                  "HIGH",     "Service creation (persistence) [T1543.003]"),
    ("sc config",                  "HIGH",     "Service config modification [T1543.003]"),
    ("netsh add helper",           "HIGH",     "Netsh helper DLL (persistence) [T1546.007]"),

    # ── HIGH: Download Cradles ─────────────────────────────────────────────
    ("invoke-webrequest",          "HIGH",     "PowerShell remote file download [T1105]"),
    ("downloadstring(",            "HIGH",     "WebClient DownloadString cradle [T1105]"),
    ("downloadfile(",              "HIGH",     "WebClient DownloadFile cradle [T1105]"),
    ("net.webclient",              "HIGH",     "WebClient object creation [T1105]"),
    ("(new-object net.webclient)", "HIGH",     "Inline WebClient download cradle [T1105]"),
    ("-windowstyle hidden",        "HIGH",     "Hidden PowerShell window [T1564.003]"),
    ("-w hidden",                  "HIGH",     "Hidden window short flag [T1564.003]"),
    ("bypass",                     "HIGH",     "ExecutionPolicy bypass [T1059.001]"),
    ("raw.githubusercontent",      "HIGH",     "GitHub raw content download cradle [T1105]"),
    ("start-bitstransfer",         "HIGH",     "BITS transfer download [T1197]"),
    ("certutil -urlcache",         "HIGH",     "Certutil download cradle [T1105]"),
    ("certutil -decode",           "HIGH",     "Certutil base64 decode [T1027]"),
    ("bitsadmin /transfer",        "HIGH",     "BITSAdmin download cradle [T1197]"),
    ("mshta http",                 "HIGH",     "MSHTA remote HTA download+exec [T1218.005]"),
    ("regsvr32 /s /n /u /i:http",  "HIGH",     "Regsvr32 squiblydoo [T1218.010]"),
    ("curl -o ",                   "HIGH",     "Curl download to file [T1105]"),
    ("wget ",                      "HIGH",     "Wget download [T1105]"),

    # ── HIGH: Anti-Forensics / Log Tampering ──────────────────────────────
    ("clear-eventlog",             "HIGH",     "EventLog cleared via PS [T1070.001]"),
    ("wevtutil cl",                "HIGH",     "wevtutil event log clear [T1070.001]"),
    ("remove-eventlog",            "HIGH",     "EventLog source removed [T1070.001]"),
    ("fsutil usn deletejournal",   "HIGH",     "USN Journal deletion [T1070.004]"),
    ("attrib +h +s",               "HIGH",     "File hidden and system-flagged [T1564]"),

    # ── HIGH: Account Manipulation ────────────────────────────────────────
    ("net user /add",              "HIGH",     "New local user created [T1136.001]"),
    ("net localgroup administrators /add", "CRITICAL", "User added to Administrators [T1098]"),
    ("new-localuser",              "HIGH",     "PS new local user [T1136.001]"),
    ("add-localgroupmember",       "CRITICAL", "PS add user to local group [T1098]"),
    ("enable-localuser",           "MEDIUM",   "PS user account enabled [T1098]"),
    ("set-localuser",              "MEDIUM",   "PS local user modification [T1098]"),

    # ── HIGH: Exfiltration / Staging ──────────────────────────────────────
    ("compress-archive",           "HIGH",     "Archive creation (exfil staging) [T1560]"),
    ("rar a ",                     "HIGH",     "RAR archive creation [T1560]"),
    ("7z a ",                      "HIGH",     "7-Zip archive creation [T1560]"),
    ("net use \\\\",               "HIGH",     "Network share mount [T1021.002]"),
    ("copy \\\\",                  "HIGH",     "Remote UNC copy [T1021]"),

    # ── MEDIUM: Reconnaissance / Discovery ────────────────────────────────
    ("-nop ",                      "MEDIUM",   "NoProfile evasion flag [T1059.001]"),
    ("-noprofile",                 "MEDIUM",   "NoProfile evasion flag [T1059.001]"),
    ("get-credential",             "MEDIUM",   "Credential prompt [T1056]"),
    ("invoke-command",             "MEDIUM",   "PS remote command execution [T1021.006]"),
    ("enter-pssession",            "MEDIUM",   "PS remote session [T1021.006]"),
    ("new-pssession",              "MEDIUM",   "PS remote session creation [T1021.006]"),
    ("net user",                   "MEDIUM",   "User enumeration via PS [T1087.001]"),
    ("net localgroup",             "MEDIUM",   "Group enumeration via PS [T1069.001]"),
    ("net group /domain",          "MEDIUM",   "Domain group enumeration [T1069.002]"),
    ("whoami /all",                "MEDIUM",   "Full token/privilege dump [T1033]"),
    ("whoami /priv",               "MEDIUM",   "Privilege enumeration [T1057]"),
    ("nltest /dclist",             "MEDIUM",   "Domain controller discovery [T1018]"),
    ("nltest /domain_trusts",      "MEDIUM",   "Domain trust enumeration [T1482]"),
    ("nltest",                     "MEDIUM",   "Nltest domain reconnaissance [T1482]"),
    ("get-aduser",                 "MEDIUM",   "AD user enumeration [T1087.002]"),
    ("get-adcomputer",             "MEDIUM",   "AD computer enumeration [T1018]"),
    ("get-adgroupmember",          "MEDIUM",   "AD group membership query [T1069.002]"),
    ("get-addomaincontroller",     "MEDIUM",   "Domain controller enumeration [T1018]"),
    ("get-netshare",               "MEDIUM",   "Network share enumeration [T1135]"),
    ("invoke-portscan",            "HIGH",     "PS port scanner [T1046]"),
    ("test-netconnection",         "MEDIUM",   "PS network connectivity test [T1046]"),
    ("systeminfo",                 "MEDIUM",   "Full OS/hardware enumeration [T1082]"),
    ("ipconfig /all",              "MEDIUM",   "Full network config dump [T1016]"),
    ("arp -a",                     "MEDIUM",   "ARP table enumeration [T1018]"),
    ("netstat -ano",               "MEDIUM",   "Active connections with PIDs [T1049]"),
    ("tasklist",                   "LOW",      "Running process list [T1057]"),
    ("reg query hklm",             "MEDIUM",   "HKLM registry query [T1012]"),
    ("wmic computersystem get",    "MEDIUM",   "WMI computer details [T1082]"),
    ("wmic process get",           "MEDIUM",   "Process list via WMI [T1057]"),
    ("dsquery",                    "MEDIUM",   "AD DSQUERY enumeration [T1018]"),

    # ── LOW: Basic Recon ──────────────────────────────────────────────────
    ("whoami",                     "LOW",      "Whoami user discovery [T1033]"),
    ("hostname",                   "LOW",      "Hostname discovery [T1082]"),
    ("ipconfig",                   "LOW",      "Network config discovery [T1016]"),
    ("netstat",                    "LOW",      "Network connections [T1049]"),
    ("ping ",                      "LOW",      "ICMP ping host discovery [T1018]"),
    ("nslookup",                   "LOW",      "DNS lookup [T1018]"),
]

# ─────────────────────────────────────────────────────────────────────────
# NOISE — skip these processes entirely
# ─────────────────────────────────────────────────────────────────────────

NOISE_CMDLINE = [
    "windowsapps",
    "visual studio",
    "vscode",
    "microsoft.management",
    "windows defender",
    "securityhealth",
    "powershell ise",
    "powershell_ise",
    "antimalware",
    "splunk",
    "chocolatey",
    "pip install",
    "npm install",
    "git.exe",
]

PS_PROCESS_NAMES = {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}


def _cmdline_hash(cmdline: str) -> str:
    return hashlib.md5(cmdline.encode("utf-8", errors="ignore")).hexdigest()


def monitor_powershell(alert_callback):
    """
    Scan running processes every 0.2 seconds.
    Alert on any PowerShell/pwsh process with suspicious cmdline.
    Deduplicates by cmdline content hash (not PID) so short-lived
    processes are still caught.
    """
    host = socket.gethostname()

    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    print("  PowerShell monitor active (v3.0 — 100+ MITRE-mapped rules)")

    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
                try:
                    name = (proc.info["name"] or "").lower()

                    if name not in PS_PROCESS_NAMES:
                        continue

                    cmdline_list = proc.info["cmdline"] or []
                    cmdline      = " ".join(cmdline_list).strip()

                    if not cmdline:
                        continue

                    cmdline_lower = cmdline.lower()

                    # Skip noise
                    if any(n in cmdline_lower for n in NOISE_CMDLINE):
                        continue

                    # Check against rules
                    matched_rule = None
                    for pattern, severity, desc in PS_RULES:
                        if pattern in cmdline_lower:
                            matched_rule = (pattern, severity, desc)
                            break  # first (highest priority) match wins

                    if not matched_rule:
                        continue

                    pattern, severity, desc = matched_rule

                    # Dedup by cmdline hash
                    chash = _cmdline_hash(cmdline_lower[:300])
                    if chash in _seen_cmdlines:
                        continue
                    _seen_cmdlines.add(chash)

                    # Prune old hashes if too large
                    if len(_seen_cmdlines) > 3000:
                        _seen_cmdlines.clear()

                    proc_user = (proc.info.get("username") or user)

                    detail = (
                        "[" + desc + "]\n"
                        "Process  : " + name + " (PID " + str(proc.info["pid"]) + ")\n"
                        "User     : " + proc_user + "\n"
                        "CMD      : " + cmdline[:600] + "\n"
                        "Matched  : " + pattern + "\n"
                        "Priority : " + severity   # hint only — pipeline decides final severity
                    )

                    alert_callback({
                        "event":  "Suspicious PowerShell Detected",
                        "detail": detail,
                        # NO "severity" key — core.alert_pipeline.calculate_severity() decides
                        "host":   host,
                        "user":   proc_user,
                        "source": "powershell",
                        "log_source": "PowerShell",
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                except Exception:
                    pass

            time.sleep(0.05)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.05)