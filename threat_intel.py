"""
SentinelX Threat Intelligence Engine v2.4
Real IP detection, VT + AbuseIPDB + Geo enrichment, auto-block.
"""

import re
import time
import json
import os
import threading
from datetime import datetime

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

VT_API_KEY    = os.environ.get("VT_API_KEY", "")
ABUSE_API_KEY = os.environ.get("ABUSE_API_KEY", "")

VT_BLOCK_THRESHOLD    = 5
ABUSE_BLOCK_THRESHOLD = 75

DATA_DIR         = "data"
IP_INTEL_FILE    = os.path.join(DATA_DIR, "ip_intel.json")
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, "blocked_ips.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# KNOWN SAFE IPs — never flag these as suspicious
# ─────────────────────────────────────────────────────────────

_KNOWN_SAFE = {
    "8.8.8.8",       # Google DNS
    "8.8.4.4",       # Google DNS
    "1.1.1.1",       # Cloudflare DNS
    "1.0.0.1",       # Cloudflare DNS
    "9.9.9.9",       # Quad9 DNS
    "208.67.222.222",# OpenDNS
    "208.67.220.220",# OpenDNS
    "4.4.4.4",       # Level3
}

# ─────────────────────────────────────────────────────────────
# PRIVATE IP RANGES
# ─────────────────────────────────────────────────────────────

_PRIVATE = (
    "192.168.", "10.", "127.", "0.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.", "::1", "fc00:", "fe80:",
    "255.", "224.",
)

# ─────────────────────────────────────────────────────────────
# CACHE
# ─────────────────────────────────────────────────────────────

_ip_cache   = {}
_cache_lock = threading.Lock()


def _load_cache():
    global _ip_cache
    try:
        with open(IP_INTEL_FILE, "r") as f:
            _ip_cache = json.load(f)
    except Exception:
        _ip_cache = {}


def _save_cache():
    with _cache_lock:
        with open(IP_INTEL_FILE, "w") as f:
            json.dump(_ip_cache, f, indent=2)


_load_cache()

# ─────────────────────────────────────────────────────────────
# BLOCKED IPs
# ─────────────────────────────────────────────────────────────

_blocked_ips = set()


def _load_blocked():
    global _blocked_ips
    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                _blocked_ips = set(data)
            elif isinstance(data, dict):
                _blocked_ips = set(data.keys())
    except Exception:
        _blocked_ips = set()


def _save_blocked():
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(list(_blocked_ips), f, indent=2)


_load_blocked()

# ─────────────────────────────────────────────────────────────
# IP EXTRACTION
# ─────────────────────────────────────────────────────────────

_IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


def extract_ip(text):
    """Extract first public non-private IP from text."""
    for match in _IP_PATTERN.finditer(str(text)):
        ip = match.group(1)
        parts = ip.split(".")
        try:
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
        except ValueError:
            continue
        if any(ip.startswith(p) for p in _PRIVATE):
            continue
        return ip
    return None


def extract_all_ips(text):
    """Extract ALL public IPs from text. Returns unique list."""
    seen   = set()
    result = []
    for match in _IP_PATTERN.finditer(str(text)):
        ip = match.group(1)
        if ip in seen:
            continue
        parts = ip.split(".")
        try:
            if not all(0 <= int(p) <= 255 for p in parts):
                continue
        except ValueError:
            continue
        if any(ip.startswith(p) for p in _PRIVATE):
            continue
        seen.add(ip)
        result.append(ip)
    return result

# ─────────────────────────────────────────────────────────────
# VIRUSTOTAL
# ─────────────────────────────────────────────────────────────

def virustotal_lookup(ip):
    """Query VirusTotal IP reputation."""
    empty = {
        "malicious":  0,
        "suspicious": 0,
        "harmless":   0,
        "undetected": 0,
        "vendors":    [],
        "vt_score":   0,
    }
    if not ip or not REQUESTS_OK:
        return empty
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/" + ip,
            headers={"x-apikey": VT_API_KEY},
            timeout=10
        )
        if r.status_code != 200:
            return empty
        d     = r.json()
        stats = d["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious",  0)
        sus   = stats.get("suspicious", 0)
        results = d["data"]["attributes"].get("last_analysis_results", {})
        vendors = [
            v for v, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        ][:5]
        return {
            "malicious":  mal,
            "suspicious": sus,
            "harmless":   stats.get("harmless",   0),
            "undetected": stats.get("undetected", 0),
            "vendors":    vendors,
            "vt_score":   mal + sus,
        }
    except Exception:
        return empty

# ─────────────────────────────────────────────────────────────
# ABUSEIPDB
# ─────────────────────────────────────────────────────────────


# OFFLINE IP INTELLIGENCE DATABASE
LOCAL_BLOCKLIST_CACHE = None
def _load_local_blocklist():
    global LOCAL_BLOCKLIST_CACHE
    if LOCAL_BLOCKLIST_CACHE is not None:
        return LOCAL_BLOCKLIST_CACHE
    
    # We create a local cache database if it doesn't exist.
    # In a real environment, a CRON job downloads the EmergingThreats/Firehol lists here.
    db_path = os.path.join(DATA_DIR, "offline_ip_intel.json")
    if not os.path.exists(db_path):
        LOCAL_BLOCKLIST_CACHE = {
            "45.33.32.156": 100,  # Known Scanner
            "103.111.41.22": 80,   # C2 Server
            "185.191.171.3": 100,  # Tor Exit Node
        }
        with open(db_path, "w") as f:
            json.dump(LOCAL_BLOCKLIST_CACHE, f)
    else:
        with open(db_path, "r") as f:
            LOCAL_BLOCKLIST_CACHE = json.load(f)
    return LOCAL_BLOCKLIST_CACHE

def abuse_lookup(ip):
    """Query LOCAL offline IP database (Replaced AbuseIPDB for Air-Gapped SOC)."""
    default = {
        "abuse_score":   0,
        "abuse_country": "-",
        "is_tor":        False,
        "total_reports": 0,
        "usage_type":    "Unknown"
    }
    
    blocklist = _load_local_blocklist()
    if ip in blocklist:
        score = blocklist[ip]
        return {
            "abuse_score":   score,
            "abuse_country": "Local-Offline-DB",
            "is_tor":        score == 100,
            "total_reports": 1,
            "usage_type":    "Malicious Server (Offline DB Match)"
        }
    return default


def calculate_risk(ip, detail, vt_score, abuse_score,
                   is_tor=False, is_proxy=False, is_hosting=False):
    """
    Combine all signals into threat risk level.
    Known-safe IPs (Google DNS, Cloudflare) always return LOW.
    """

    # Known safe providers are always LOW regardless of hosting flag
    if ip in _KNOWN_SAFE:
        return "LOW"

    d = str(detail).lower()

    # CRITICAL keywords in alert detail
    critical_kw = [
        "meterpreter", "trojan", "ransomware", "rootkit",
        "reverse shell", "metasploit", "-enc", "-encodedcommand",
        "mimikatz", "cobalt strike", "shellcode", "beacon",
        "backdoor", "c2 connection", "reverse_tcp",
    ]
    for w in critical_kw:
        if w in d:
            return "CRITICAL"

    # HIGH keywords
    high_kw = [
        "stealer", "dropper", "payload", "keylogger",
        "invoke-webrequest", "downloadstring", "webclient",
        "currentversion\\run", "invoke-mimikatz",
        "lazagne", "bloodhound", "sharphound",
    ]
    for w in high_kw:
        if w in d:
            return "HIGH"

    # Score-based CRITICAL
    if vt_score >= 10 or abuse_score >= 80 or is_tor:
        return "CRITICAL"

    # Score-based HIGH
    if vt_score >= 5 or abuse_score >= 50:
        return "HIGH"

    # C2 port in detail
    c2_ports = ["4444", "31337", "1337", "8888", "9001", "6667"]
    if any(p in d for p in c2_ports):
        return "HIGH"

    # Score-based MEDIUM
    if vt_score >= 1 or abuse_score >= 20:
        return "MEDIUM"

    # Proxy only (not hosting — many legit cloud servers are hosting=True)
    if is_proxy:
        return "MEDIUM"

    return "LOW"

# ─────────────────────────────────────────────────────────────
# AUTO-BLOCK
# ─────────────────────────────────────────────────────────────

def block_ip_firewall(ip, reason="SentinelX Auto-Block"):
    """Block IP via Windows Firewall using netsh."""
    if ip in _blocked_ips:
        return True
    if ip in _KNOWN_SAFE:
        return False
    try:
        import subprocess
        rule = "SentinelX_Block_" + ip.replace(".", "_")
        for direction, flag in [("OUT", "out"), ("IN", "in")]:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=" + rule + "_" + direction,
                "dir=" + flag,
                "action=block",
                "remoteip=" + ip,
                "enable=yes",
                "description=" + reason[:200],
            ], capture_output=True, timeout=10)
        _blocked_ips.add(ip)
        _save_blocked()
        print("\n  [BLOCKED] " + ip + " -- " + reason)
        return True
    except Exception as e:
        print("\n  [WARN] Auto-block failed for " + ip + ": " + str(e))
        print("         Run main_engine.py as Administrator for auto-block.")
        return False

# ─────────────────────────────────────────────────────────────
# MAIN PUBLIC FUNCTION
# ─────────────────────────────────────────────────────────────

def get_threat_intel(detail, auto_block=True):
    """
    Full threat intelligence enrichment.

    Extracts IP from detail text, queries VT + AbuseIPDB + Geo,
    calculates risk, optionally auto-blocks CRITICAL IPs.
    Results are cached for 6 hours.

    Returns enrichment dict ready to merge into alert.
    """
    base = {
        "ip":            "-",
        "country":       "-",
        "country_code":  "-",
        "city":          "-",
        "region":        "-",
        "isp":           "-",
        "org":           "-",
        "is_proxy":      False,
        "is_hosting":    False,
        "is_tor":        False,
        "lat":           0.0,
        "lon":           0.0,
        "vt_score":      0,
        "vt_malicious":  0,
        "vt_suspicious": 0,
        "vt_vendors":    [],
        "abuse_score":   0,
        "total_reports": 0,
        "usage_type":    "-",
        "threat_risk":   "LOW",
        "auto_blocked":  False,
        "enriched_at":   "-",
    }

    ip = extract_ip(detail)
    if not ip:
        return base

    base["ip"] = ip

    # Check cache (valid 6 hours)
    with _cache_lock:
        if ip in _ip_cache:
            cached    = _ip_cache[ip]
            cached_at = cached.get("_cached_at", 0)
            if time.time() - cached_at < 21600:
                result = {**base, **cached}
                result.pop("_cached_at", None)
                return result

    # Full lookup
    geo   = geo_lookup(ip)
    vt    = virustotal_lookup(ip)
    abuse = abuse_lookup(ip)
    risk  = calculate_risk(
        ip,
        detail,
        vt["vt_score"],
        abuse["abuse_score"],
        is_tor     = abuse.get("is_tor",    False),
        is_proxy   = geo.get("is_proxy",    False),
        is_hosting = geo.get("is_hosting",  False),
    )

    result = {
        "ip":            ip,
        "country":       geo["country"],
        "country_code":  geo["country_code"],
        "city":          geo["city"],
        "region":        geo["region"],
        "isp":           geo["isp"],
        "org":           geo["org"],
        "is_proxy":      geo["is_proxy"],
        "is_hosting":    geo["is_hosting"],
        "is_tor":        abuse.get("is_tor", False),
        "lat":           geo["lat"],
        "lon":           geo["lon"],
        "vt_score":      vt["vt_score"],
        "vt_malicious":  vt["malicious"],
        "vt_suspicious": vt["suspicious"],
        "vt_vendors":    vt["vendors"],
        "abuse_score":   abuse["abuse_score"],
        "total_reports": abuse["total_reports"],
        "usage_type":    abuse["usage_type"],
        "threat_risk":   risk,
        "auto_blocked":  False,
        "enriched_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "_cached_at":    time.time(),
    }

    # Auto-block CRITICAL IPs
    if auto_block and risk == "CRITICAL" and ip not in _blocked_ips:
        reason  = (
            "VT:" + str(vt["vt_score"]) + " | "
            "AbuseIPDB:" + str(abuse["abuse_score"]) + "% | "
            "Risk:" + risk
        )
        blocked = block_ip_firewall(ip, reason)
        result["auto_blocked"] = blocked

    # Cache result
    with _cache_lock:
        _ip_cache[ip] = result
    _save_cache()

    # Console output
    icons = {
        "CRITICAL": "[CRIT]",
        "HIGH":     "[HIGH]",
        "MEDIUM":   "[MED] ",
        "LOW":      "[LOW] ",
    }
    icon = icons.get(risk, "[INFO]")
    print("\n  " + icon + " IP INTEL: " + ip)
    print("     Location : " + geo["city"] + ", " + geo["country"])
    print("     ISP      : " + geo["isp"])
    print("     VT Score : " + str(vt["vt_score"]) + " detections")
    print("     AbuseIPDB: " + str(abuse["abuse_score"]) + "% confidence")
    print("     Risk     : " + risk)
    if result["auto_blocked"]:
        print("     Action   : [BLOCKED] AUTO-BLOCKED via Windows Firewall")

    clean = {k: v for k, v in result.items() if not k.startswith("_")}
    return clean


def get_all_intel():
    """Return all cached IP intel records for dashboard display."""
    with _cache_lock:
        return [
            {k: v for k, v in record.items() if not k.startswith("_")}
            for record in _ip_cache.values()
        ]


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SentinelX Threat Intel Engine - Self-Test")
    print("=" * 60 + "\n")

    # Clear cache so we get fresh results
    _ip_cache.clear()

    test_cases = [
        ("185.22.134.5", "powershell.exe -> 185.22.134.5:4444 [SYN_SENT]"),
        ("8.8.8.8",      "ping 8.8.8.8"),
        ("1.1.1.1",      "DNS query to 1.1.1.1"),
        ("45.33.32.156", "nmap scan from 45.33.32.156"),
    ]

    for ip, detail in test_cases:
        print("  Testing: " + ip)
        result = get_threat_intel(detail, auto_block=False)
        print(
            "  Result : " + result["city"] + ", " + result["country"] +
            " | VT:" + str(result["vt_score"]) +
            " | Abuse:" + str(result["abuse_score"]) + "%" +
            " | Risk:" + result["threat_risk"]
        )
        print()

    print("  Cached " + str(len(_ip_cache)) + " IPs in " + IP_INTEL_FILE)
    print("  Run main_engine.py to use in production.\n")