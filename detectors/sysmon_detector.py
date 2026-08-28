"""
SentinelX Sysmon Ancestry Detector v2.5 — UPGRADED
Detects parent-child process attack chains via psutil (Sysmon fallback).

KEY UPGRADES from v2.4:
1. FALSE POSITIVE REDUCTION:
   - cmd->powershell and ps->cmd now check if cmdline contains
     known-benign patterns before firing (admin scripts, VS Code, etc.)
   - svchost->powershell suppressed for signed/system scheduled tasks
   - Allowlist of known-good parent process paths (system32 checks)

2. MULTI-HOP DETECTION (3+ process chains):
   - Tracks grandparent PIDs to detect 3-hop chains
   - E.g. winword → cmd → powershell → CRITICAL (macro chain)
   - E.g. explorer → cmd → powershell → HIGH (user shell upgrade)

3. PROPER SEVERITY PASSED TO PIPELINE:
   - Passes detector-assessed severity to process_alert()
   - Pipeline v2.5 respects this via the detector_sev fix

4. CMDLINE CONTEXT IN DETAIL:
   - Full cmdline included for analyst investigation
   - Grandparent process shown in 3-hop chains
"""

import time
import socket
import os
import re

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
NS       = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# ─────────────────────────────────────────────────────────────
# ANCESTRY ATTACK CHAINS
# (parent, child) -> (severity, mitre, tactic, description)
# ─────────────────────────────────────────────────────────────

ANCESTRY_CHAINS = {
    # Office Macro Attacks — CRITICAL
    ("winword.exe",   "powershell.exe"):  ("CRITICAL","T1566.001","Execution",        "Word -> PowerShell [Macro Attack]"),
    ("winword.exe",   "pwsh.exe"):        ("CRITICAL","T1566.001","Execution",        "Word -> PS Core [Macro Attack]"),
    ("winword.exe",   "cmd.exe"):         ("CRITICAL","T1566.001","Execution",        "Word -> CMD [Macro Dropper]"),
    ("winword.exe",   "wscript.exe"):     ("CRITICAL","T1566.001","Execution",        "Word -> WScript [Macro VBS]"),
    ("winword.exe",   "cscript.exe"):     ("CRITICAL","T1566.001","Execution",        "Word -> CScript [Macro JS]"),
    ("winword.exe",   "mshta.exe"):       ("CRITICAL","T1566.001","Execution",        "Word -> MSHTA [Macro HTA]"),
    ("winword.exe",   "rundll32.exe"):    ("CRITICAL","T1566.001","Defense Evasion",  "Word -> RunDLL32 [Macro LOLBin]"),
    ("winword.exe",   "regsvr32.exe"):    ("CRITICAL","T1566.001","Defense Evasion",  "Word -> Regsvr32 [Squiblydoo]"),
    ("winword.exe",   "certutil.exe"):    ("CRITICAL","T1566.001","Command & Control", "Word -> Certutil [Downloader]"),
    ("winword.exe",   "bitsadmin.exe"):   ("CRITICAL","T1566.001","Command & Control", "Word -> BITSAdmin [Downloader]"),
    ("winword.exe",   "wmic.exe"):        ("CRITICAL","T1566.001","Execution",        "Word -> WMIC [Macro Exec]"),
    ("excel.exe",     "powershell.exe"):  ("CRITICAL","T1566.001","Execution",        "Excel -> PowerShell [Macro Attack]"),
    ("excel.exe",     "pwsh.exe"):        ("CRITICAL","T1566.001","Execution",        "Excel -> PS Core [Macro Attack]"),
    ("excel.exe",     "cmd.exe"):         ("CRITICAL","T1566.001","Execution",        "Excel -> CMD [Macro Dropper]"),
    ("excel.exe",     "wscript.exe"):     ("CRITICAL","T1566.001","Execution",        "Excel -> WScript [Macro VBS]"),
    ("excel.exe",     "cscript.exe"):     ("CRITICAL","T1566.001","Execution",        "Excel -> CScript [Macro JS]"),
    ("excel.exe",     "mshta.exe"):       ("CRITICAL","T1566.001","Execution",        "Excel -> MSHTA [Macro HTA]"),
    ("excel.exe",     "rundll32.exe"):    ("CRITICAL","T1566.001","Defense Evasion",  "Excel -> RunDLL32 [Macro LOLBin]"),
    ("excel.exe",     "regsvr32.exe"):    ("CRITICAL","T1566.001","Defense Evasion",  "Excel -> Regsvr32 [Squiblydoo]"),
    ("excel.exe",     "certutil.exe"):    ("CRITICAL","T1566.001","Command & Control", "Excel -> Certutil [Downloader]"),
    ("excel.exe",     "wmic.exe"):        ("CRITICAL","T1566.001","Execution",        "Excel -> WMIC [Macro Exec]"),
    ("outlook.exe",   "powershell.exe"):  ("CRITICAL","T1566.001","Execution",        "Outlook -> PowerShell [Phishing]"),
    ("outlook.exe",   "pwsh.exe"):        ("CRITICAL","T1566.001","Execution",        "Outlook -> PS Core [Phishing]"),
    ("outlook.exe",   "cmd.exe"):         ("CRITICAL","T1566.001","Execution",        "Outlook -> CMD [Phishing]"),
    ("outlook.exe",   "wscript.exe"):     ("CRITICAL","T1566.001","Execution",        "Outlook -> WScript [Phishing VBS]"),
    ("outlook.exe",   "mshta.exe"):       ("CRITICAL","T1566.001","Execution",        "Outlook -> MSHTA [Phishing HTA]"),
    ("powerpnt.exe",  "powershell.exe"):  ("CRITICAL","T1566.001","Execution",        "PowerPoint -> PowerShell [Macro]"),
    ("powerpnt.exe",  "cmd.exe"):         ("CRITICAL","T1566.001","Execution",        "PowerPoint -> CMD [Macro]"),
    ("powerpnt.exe",  "wscript.exe"):     ("CRITICAL","T1566.001","Execution",        "PowerPoint -> WScript [Macro]"),
    ("onenote.exe",   "powershell.exe"):  ("CRITICAL","T1566.001","Execution",        "OneNote -> PowerShell [Phishing embed]"),
    ("onenote.exe",   "cmd.exe"):         ("CRITICAL","T1566.001","Execution",        "OneNote -> CMD [Phishing embed]"),
    ("onenote.exe",   "wscript.exe"):     ("CRITICAL","T1566.001","Execution",        "OneNote -> WScript [Phishing embed]"),
    ("onenote.exe",   "mshta.exe"):       ("CRITICAL","T1566.001","Execution",        "OneNote -> MSHTA [Phishing embed]"),
    ("mspub.exe",     "powershell.exe"):  ("CRITICAL","T1566.001","Execution",        "Publisher -> PowerShell [Macro]"),
    ("mspub.exe",     "cmd.exe"):         ("CRITICAL","T1566.001","Execution",        "Publisher -> CMD [Macro]"),
    # Browser Drive-by
    ("msedge.exe",    "powershell.exe"):  ("HIGH",    "T1189",    "Execution",        "Edge -> PowerShell [Drive-by]"),
    ("msedge.exe",    "cmd.exe"):         ("HIGH",    "T1189",    "Execution",        "Edge -> CMD [Drive-by]"),
    ("chrome.exe",    "powershell.exe"):  ("HIGH",    "T1189",    "Execution",        "Chrome -> PowerShell [Drive-by]"),
    ("chrome.exe",    "cmd.exe"):         ("HIGH",    "T1189",    "Execution",        "Chrome -> CMD [Drive-by]"),
    ("iexplore.exe",  "powershell.exe"):  ("CRITICAL","T1189",    "Execution",        "IE -> PowerShell [Drive-by exploit]"),
    ("iexplore.exe",  "cmd.exe"):         ("CRITICAL","T1189",    "Execution",        "IE -> CMD [Drive-by exploit]"),
    ("iexplore.exe",  "wscript.exe"):     ("CRITICAL","T1189",    "Execution",        "IE -> WScript [Drive-by exploit]"),
    ("iexplore.exe",  "mshta.exe"):       ("CRITICAL","T1189",    "Execution",        "IE -> MSHTA [Drive-by exploit]"),
    # LOLBin Chains
    ("mshta.exe",     "powershell.exe"):  ("CRITICAL","T1218.005","Defense Evasion",  "MSHTA -> PowerShell [HTA payload]"),
    ("mshta.exe",     "cmd.exe"):         ("HIGH",    "T1218.005","Defense Evasion",  "MSHTA -> CMD [HTA payload]"),
    ("mshta.exe",     "wscript.exe"):     ("HIGH",    "T1218.005","Defense Evasion",  "MSHTA -> WScript [HTA VBS]"),
    ("wscript.exe",   "powershell.exe"):  ("HIGH",    "T1059.005","Execution",        "WScript -> PowerShell [VBS->PS]"),
    ("wscript.exe",   "cmd.exe"):         ("HIGH",    "T1059.005","Execution",        "WScript -> CMD [VBS dropper]"),
    ("wscript.exe",   "mshta.exe"):       ("HIGH",    "T1059.005","Defense Evasion",  "WScript -> MSHTA [VBS->HTA]"),
    ("cscript.exe",   "powershell.exe"):  ("HIGH",    "T1059.005","Execution",        "CScript -> PowerShell [JS/VBS->PS]"),
    ("cscript.exe",   "cmd.exe"):         ("HIGH",    "T1059.005","Execution",        "CScript -> CMD [JS dropper]"),
    ("rundll32.exe",  "powershell.exe"):  ("HIGH",    "T1218.011","Defense Evasion",  "RunDLL32 -> PowerShell [LOLBin]"),
    ("rundll32.exe",  "cmd.exe"):         ("HIGH",    "T1218.011","Defense Evasion",  "RunDLL32 -> CMD [LOLBin]"),
    ("regsvr32.exe",  "powershell.exe"):  ("HIGH",    "T1218.010","Defense Evasion",  "Regsvr32 -> PowerShell [Squiblydoo]"),
    ("regsvr32.exe",  "cmd.exe"):         ("HIGH",    "T1218.010","Defense Evasion",  "Regsvr32 -> CMD [Squiblydoo]"),
    ("msiexec.exe",   "powershell.exe"):  ("HIGH",    "T1218.007","Defense Evasion",  "MSIExec -> PowerShell [MSI payload]"),
    ("msiexec.exe",   "cmd.exe"):         ("HIGH",    "T1218.007","Defense Evasion",  "MSIExec -> CMD [MSI payload]"),
    ("msbuild.exe",   "powershell.exe"):  ("CRITICAL","T1127.001","Defense Evasion",  "MSBuild -> PowerShell [inline task]"),
    ("msbuild.exe",   "cmd.exe"):         ("HIGH",    "T1127.001","Defense Evasion",  "MSBuild -> CMD [inline task]"),
    ("cmstp.exe",     "powershell.exe"):  ("CRITICAL","T1218.003","Defense Evasion",  "CMSTP -> PowerShell [UAC bypass]"),
    # Shell Self-Spawn — MEDIUM/HIGH (context-checked before firing)
    ("cmd.exe",       "powershell.exe"):  ("HIGH",    "T1059.001","Execution",        "CMD -> PowerShell [shell upgrade]"),
    ("cmd.exe",       "pwsh.exe"):        ("HIGH",    "T1059.001","Execution",        "CMD -> PS Core [shell upgrade]"),
    ("cmd.exe",       "wscript.exe"):     ("MEDIUM",  "T1059.005","Execution",        "CMD -> WScript [script drop]"),
    ("cmd.exe",       "mshta.exe"):       ("HIGH",    "T1218.005","Defense Evasion",  "CMD -> MSHTA [HTA from CMD]"),
    ("cmd.exe",       "certutil.exe"):    ("HIGH",    "T1140",    "Command & Control", "CMD -> Certutil [CMD downloader]"),
    ("cmd.exe",       "bitsadmin.exe"):   ("HIGH",    "T1197",    "Command & Control", "CMD -> BITSAdmin [CMD downloader]"),
    ("powershell.exe","powershell.exe"):  ("MEDIUM",  "T1059.001","Defense Evasion",  "PS -> PS [nested spawn]"),
    ("powershell.exe","pwsh.exe"):        ("MEDIUM",  "T1059.001","Defense Evasion",  "PS -> PS Core [nested spawn]"),
    ("powershell.exe","cmd.exe"):         ("MEDIUM",  "T1059.003","Execution",        "PS -> CMD [PS->CMD chain]"),
    ("powershell.exe","wscript.exe"):     ("HIGH",    "T1059.005","Execution",        "PS -> WScript [PS drop VBS]"),
    ("powershell.exe","mshta.exe"):       ("HIGH",    "T1218.005","Defense Evasion",  "PS -> MSHTA [PS->HTA chain]"),
    ("powershell.exe","rundll32.exe"):    ("HIGH",    "T1218.011","Defense Evasion",  "PS -> RunDLL32 [PS LOLBin]"),
    ("powershell.exe","regsvr32.exe"):    ("HIGH",    "T1218.010","Defense Evasion",  "PS -> Regsvr32 [PS Squiblydoo]"),
    ("powershell.exe","schtasks.exe"):    ("HIGH",    "T1053.005","Persistence",      "PS -> SchTasks [PS persistence]"),
    ("powershell.exe","reg.exe"):         ("HIGH",    "T1112",    "Persistence",      "PS -> reg.exe [PS registry write]"),
    ("powershell.exe","certutil.exe"):    ("HIGH",    "T1140",    "Command & Control", "PS -> Certutil [PS downloader]"),
    # Notepad / Benign-app Injection indicator
    ("notepad.exe",   "powershell.exe"):  ("HIGH",    "T1055",    "Defense Evasion",  "Notepad -> PowerShell [injection indicator]"),
    ("notepad.exe",   "cmd.exe"):         ("HIGH",    "T1055",    "Defense Evasion",  "Notepad -> CMD [injection indicator]"),
    ("notepad.exe",   "wscript.exe"):     ("HIGH",    "T1055",    "Defense Evasion",  "Notepad -> WScript [injection indicator]"),
    # PsExec Lateral Movement
    ("psexesvc.exe",  "powershell.exe"):  ("CRITICAL","T1569.002","Lateral Movement", "PsExecSvc -> PowerShell [remote exec]"),
    ("psexesvc.exe",  "cmd.exe"):         ("CRITICAL","T1569.002","Lateral Movement", "PsExecSvc -> CMD [remote exec]"),
    ("psexec.exe",    "powershell.exe"):  ("CRITICAL","T1569.002","Lateral Movement", "PsExec -> PowerShell [lateral move]"),
    ("psexec.exe",    "cmd.exe"):         ("HIGH",    "T1569.002","Lateral Movement", "PsExec -> CMD [lateral move]"),
    # Archive Tool Execution
    ("winrar.exe",    "powershell.exe"):  ("HIGH",    "T1204.002","Execution",        "WinRAR -> PowerShell [archive payload]"),
    ("winrar.exe",    "cmd.exe"):         ("HIGH",    "T1204.002","Execution",        "WinRAR -> CMD [archive payload]"),
    ("7z.exe",        "powershell.exe"):  ("HIGH",    "T1204.002","Execution",        "7Zip -> PowerShell [archive payload]"),
    ("7z.exe",        "cmd.exe"):         ("HIGH",    "T1204.002","Execution",        "7Zip -> CMD [archive payload]"),
    # PDF Reader Exploits
    ("acrord32.exe",  "powershell.exe"):  ("CRITICAL","T1189",    "Execution",        "Acrobat -> PowerShell [PDF exploit]"),
    ("acrord32.exe",  "cmd.exe"):         ("CRITICAL","T1189",    "Execution",        "Acrobat -> CMD [PDF exploit]"),
    ("acrord32.exe",  "wscript.exe"):     ("CRITICAL","T1189",    "Execution",        "Acrobat -> WScript [PDF exploit]"),
    # Scheduled Task / Service Spawns
    ("taskeng.exe",   "powershell.exe"):  ("HIGH",    "T1053.005","Persistence",      "TaskEng -> PowerShell [sched task]"),
    ("taskhostw.exe", "powershell.exe"):  ("HIGH",    "T1053.005","Persistence",      "TaskHostW -> PowerShell [sched task]"),
    ("svchost.exe",   "powershell.exe"):  ("HIGH",    "T1059.001","Execution",        "Svchost -> PowerShell [service exec]"),
    ("svchost.exe",   "wscript.exe"):     ("HIGH",    "T1059.005","Execution",        "Svchost -> WScript [service VBS]"),
}

# ─────────────────────────────────────────────────────────────
# FALSE POSITIVE SUPPRESSION
# ─────────────────────────────────────────────────────────────

# Chains that commonly fire as false positives for devs/admins.
# Before raising alert, cmdline is checked against these patterns.
# If ANY pattern matches → suppress the alert.
FP_SUPPRESSION = {
    # cmd -> powershell: common in development environments
    ("cmd.exe", "powershell.exe"): [
        r"vscode",
        r"code\.exe",
        r"devenv",            # Visual Studio
        r"jetbrains",         # IntelliJ, Rider etc.
        r"conda",             # Anaconda
        r"python.*setup",     # Python installers
        r"chocolatey",        # Package manager
        r"winget",            # Windows package manager
        r"scoop",             # Scoop package manager
        r"git.*hooks",        # Git hooks
        r"npm.*script",       # NPM scripts
        r"\.ps1.*-file",      # Running signed PS1 scripts
        r"powershell.*-file.*program files",  # Signed application scripts
    ],
    # powershell -> cmd: common in admin scripts
    ("powershell.exe", "cmd.exe"): [
        r"vscode",
        r"devenv",
        r"program files",
        r"windows\\system32\\cmd.*\/c.*git",
        r"conda",
        r"chocolatey",
    ],
    # ps -> ps: IDEs and test runners do this constantly
    ("powershell.exe", "powershell.exe"): [
        r"vscode",
        r"pester",            # PS test framework
        r"invoke-pester",
        r"psscriptanalyzer",  # PS linter
        r"devenv",
        r"code\.exe",
    ],
    # svchost -> powershell: Windows Update, Group Policy, etc.
    # These fire constantly in legitimate environments
    ("svchost.exe", "powershell.exe"): [
        r"windows\\system32\\windowspowershell",  # Signed system PS
        r"microsoft\.powershell",
        r"windows update",
        r"windowsupdate",
        r"group policy",
        r"trustedinstaller",
        r"\\system32\\",
        r"-noninteractive.*-executionpolicy",  # System automation
    ],
}

# Chain pairs where we also check if PARENT is running from System32
# (reduces FP for system-initiated processes)
SYSTEM32_PARENTS = {
    ("svchost.exe", "powershell.exe"),
    ("taskeng.exe", "powershell.exe"),
    ("taskhostw.exe", "powershell.exe"),
}

# ─────────────────────────────────────────────────────────────
# MULTI-HOP CHAIN DETECTION
# If parent is cmd/ps AND grandparent is an Office app,
# escalate to CRITICAL regardless of the parent-child pair.
# ─────────────────────────────────────────────────────────────

OFFICE_APPS = frozenset([
    "winword.exe","excel.exe","outlook.exe","powerpnt.exe",
    "onenote.exe","mspub.exe","msaccess.exe",
])

BROWSERS = frozenset([
    "chrome.exe","msedge.exe","iexplore.exe","firefox.exe",
    "opera.exe","brave.exe",
])

LOL_INTERMEDIATES = frozenset([
    "cmd.exe","powershell.exe","pwsh.exe","wscript.exe",
    "cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe",
])


def _proc_name(path: str) -> str:
    return str(path or "").lower().split("\\")[-1].split("/")[-1]


def _get_cmdline(proc) -> str:
    try:
        parts = proc.cmdline()
        return " ".join(parts)[:500] if parts else ""
    except Exception:
        return ""


def _is_fp_suppressed(chain: tuple, cmdline: str, parent_path: str) -> bool:
    """
    Returns True if this chain matches a known false-positive pattern.
    Only suppresses COMMON_FP chains — Office/browser chains NEVER suppressed.
    """
    if chain not in FP_SUPPRESSION:
        return False

    # If parent is running from a system path (not user-writable), be more lenient
    if chain in SYSTEM32_PARENTS:
        parent_lower = str(parent_path or "").lower()
        if "\\system32\\" in parent_lower or "\\syswow64\\" in parent_lower:
            # Still alert if cmdline has offensive patterns
            offensive = ["-enc","-encodedcommand","iex(","invoke-expression",
                         "downloadstring","downloadfile","bypass","amsi",
                         "meterpreter","mimikatz","4444"]
            if not any(o in cmdline.lower() for o in offensive):
                return True  # Suppress — looks like legitimate system task

    patterns = FP_SUPPRESSION.get(chain, [])
    cmdline_lower = cmdline.lower()
    for pat in patterns:
        try:
            if re.search(pat, cmdline_lower):
                return True
        except re.error:
            continue
    return False


def monitor_sysmon(alert_callback):
    """
    Monitor parent-child process chains using psutil.
    v2.5: Multi-hop detection + false positive suppression.
    """
    if not PSUTIL_OK:
        print("  [WARN] psutil not available — ancestry detector inactive")
        return

    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    seen_pids = set()
    # pid -> name mapping for grandparent lookup
    pid_name_cache: dict = {}

    # Seed baseline — don't alert on existing processes at startup
    try:
        for p in psutil.process_iter(["pid","name"]):
            pid = p.info.get("pid")
            if pid:
                seen_pids.add(pid)
                name = str(p.info.get("name") or "").lower()
                pid_name_cache[pid] = name
    except Exception:
        pass

    print("  Sysmon Ancestry (psutil) active — FP suppression + multi-hop v2.5")

    while True:
        try:
            for p in psutil.process_iter(["pid","name","ppid","cmdline","exe"]):
                pid = p.info.get("pid")
                if not pid or pid in seen_pids:
                    continue

                seen_pids.add(pid)
                # Cache name for future grandparent lookups
                child_name = str(p.info.get("name") or "").lower()
                pid_name_cache[pid] = child_name

                # Trim cache to avoid unbounded growth
                if len(pid_name_cache) > 10000:
                    # Keep only the most recent 5000
                    recent_pids = sorted(pid_name_cache.keys())[-5000:]
                    pid_name_cache.clear()
                    for k in recent_pids:
                        pid_name_cache[k] = pid_name_cache.get(k, "")

                ppid = p.info.get("ppid")
                if not ppid:
                    continue

                try:
                    parent_proc = psutil.Process(ppid)
                    parent_name = str(parent_proc.name() or "").lower()
                    parent_path = ""
                    try:
                        parent_path = parent_proc.exe() or ""
                    except Exception:
                        pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = pid_name_cache.get(ppid, "")
                    parent_path = ""

                chain = (parent_name, child_name)
                cmdline = _get_cmdline(p)

                # ── Multi-hop check ───────────────────────────────────
                # Get grandparent to detect 3-hop chains
                grandparent_name = ""
                try:
                    if ppid and parent_proc:
                        gppid = parent_proc.ppid()
                        if gppid:
                            gp = psutil.Process(gppid)
                            grandparent_name = str(gp.name() or "").lower()
                except Exception:
                    grandparent_name = pid_name_cache.get(
                        ppid - 1, "")  # fallback from cache

                # 3-hop escalation: Office/Browser → intermediate → child
                is_3hop_critical = (
                    grandparent_name in OFFICE_APPS and
                    parent_name in LOL_INTERMEDIATES
                )
                is_3hop_browser = (
                    grandparent_name in BROWSERS and
                    parent_name in LOL_INTERMEDIATES
                )

                # ── Primary chain detection ───────────────────────────
                if chain in ANCESTRY_CHAINS:
                    sev, mitre, tactic, desc = ANCESTRY_CHAINS[chain]

                    # FP suppression for noisy chains
                    if _is_fp_suppressed(chain, cmdline, parent_path):
                        continue

                    # Escalate severity for 3-hop chains
                    if is_3hop_critical and sev != "CRITICAL":
                        sev = "CRITICAL"
                        desc = desc + " [3-HOP: " + grandparent_name + " → " + parent_name + " → " + child_name + "]"
                    elif is_3hop_browser and sev not in ("CRITICAL","HIGH"):
                        sev = "HIGH"
                        desc = desc + " [3-HOP browser: " + grandparent_name + " → " + parent_name + " → " + child_name + "]"

                    detail_lines = [
                        desc,
                        "Parent  : " + parent_name,
                        "Child   : " + child_name,
                    ]
                    if grandparent_name and grandparent_name not in ("","system","init"):
                        detail_lines.insert(1, "Grandpa : " + grandparent_name)
                    if cmdline:
                        detail_lines.append("CMD     : " + cmdline[:300])
                    # CHAIN_HINT tells calculate_severity() Signal 13 (worth up
                    # to +40 — the single largest signal in the whole engine)
                    # what this detector already knows: the ANCESTRY_CHAINS
                    # table (plus any 3-hop escalation above) already computed
                    # the real severity in `sev`. Without this line the pipeline
                    # never sees it and re-derives a weaker score from generic
                    # keyword matches alone — this is the fix for that gap.
                    detail_lines.append("CHAIN_HINT:" + sev)

                    alert_callback({
                        "event":    "Process Ancestry Attack Detected",
                        "detail":   "\n".join(detail_lines),
                        "host":     host,
                        "user":     user,
                        "source":   "sysmon",
                        "log_source": "Sysmon",
                    })

                # ── 3-hop chain not in primary table ─────────────────
                # Catch grandparent=Office and child=anything suspicious
                # even if parent-child pair isn't in ANCESTRY_CHAINS
                elif (is_3hop_critical and
                      child_name in ("powershell.exe","pwsh.exe","cmd.exe",
                                     "wscript.exe","cscript.exe","mshta.exe",
                                     "rundll32.exe","regsvr32.exe","msbuild.exe")):
                    desc = (grandparent_name + " → " + parent_name +
                            " → " + child_name + " [3-hop Office chain]")
                    alert_callback({
                        "event":    "Process Ancestry Attack Detected",
                        "detail":   (
                            desc + "\n"
                            "Grandpa : " + grandparent_name + "\n"
                            "Parent  : " + parent_name + "\n"
                            "Child   : " + child_name + "\n"
                            "CMD     : " + cmdline[:300] + "\n"
                            "CHAIN_HINT:CRITICAL"  # Office-origin 3-hop chain not
                                                    # in ANCESTRY_CHAINS is still a
                                                    # confirmed macro/dropper pattern
                        ),
                        "host":     host,
                        "user":     user,
                        "source":   "sysmon",
                        "log_source": "Sysmon",
                    })

            time.sleep(1)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(1)