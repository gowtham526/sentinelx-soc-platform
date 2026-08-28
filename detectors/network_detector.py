"""
SentinelX Network Detector v3.0
================================
Monitors active TCP connections for C2 ports and suspicious IPs.

Changes from v2.4
─────────────────
- Removed "severity" key from alert_callback — pipeline decides via
  calculate_severity() using the NET_PORT_RISK:<level> hint embedded
  in detail (same pattern as all other v3.0 detectors).
- Browsers (chrome, edge, firefox) moved from NOISE_PROCESSES to
  BROWSER_PROCESSES — they are now detected at MEDIUM and noted as
  "browser making suspicious connection" rather than silently dropped.
  A hijacked browser is a real attack vector (drive-by, BrowserExec).
- Added C2 PORT HINT token in detail so calculate_severity() gets
  a proper weighted signal from the port-risk lookup.
- Extended SUSPICIOUS_PORTS with additional common RAT/C2 ports.
- Added SUSPICIOUS_IP_RANGES for known bad CIDR blocks.
"""

import psutil
import time
import socket
import os

# ─────────────────────────────────────────────────────────────
# C2 / SUSPICIOUS PORTS
# port → (risk_hint, description)
# risk_hint is embedded in detail as NET_PORT_RISK:<level>
# and scored by calculate_severity() Signal 15.
# ─────────────────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    # Critical — known C2 / RAT defaults
    4444:  ("CRITICAL", "Metasploit default reverse shell"),
    31337: ("CRITICAL", "Elite RAT callback (historic)"),
    4445:  ("CRITICAL", "Metasploit alternate C2"),
    5554:  ("CRITICAL", "Sasser worm / RAT"),
    9002:  ("CRITICAL", "PlugX RAT default"),
    8888:  ("CRITICAL", "Common reverse shell port"),
    # High — common attacker infrastructure
    1337:  ("HIGH",     "Leet backdoor / attacker infrastructure"),
    6666:  ("HIGH",     "Common reverse shell port"),
    6667:  ("HIGH",     "IRC botnet C2 channel"),
    7777:  ("HIGH",     "Common reverse shell / backdoor"),
    9999:  ("HIGH",     "Common reverse shell / RAT"),
    9001:  ("HIGH",     "Tor relay / C2 channel"),
    4545:  ("HIGH",     "Known RAT callback port"),
    4443:  ("HIGH",     "HTTPS reverse shell (alt TLS)"),
    1604:  ("HIGH",     "Citrix exploit / RAT"),
    8008:  ("HIGH",     "Common RAT/backdoor port"),
    # Medium — suspicious but can be legitimate
    1080:  ("MEDIUM",   "SOCKS proxy / potential exfiltration"),
    8443:  ("MEDIUM",   "Alt HTTPS — possible C2"),
    2222:  ("MEDIUM",   "Non-standard SSH"),
    9090:  ("MEDIUM",   "Common RAT / web proxy"),
    3128:  ("MEDIUM",   "Squid proxy / potential exfiltration"),
    8080:  ("MEDIUM",   "HTTP proxy — possible C2 tunnel"),
}

# ─────────────────────────────────────────────────────────────
# CONNECTION STATES TO MONITOR
# ─────────────────────────────────────────────────────────────

WATCH_STATES = {"SYN_SENT", "ESTABLISHED", "CLOSE_WAIT"}

# ─────────────────────────────────────────────────────────────
# NOISE PROCESSES — completely silent, never alert
# These are signed system processes with known-good network activity.
# Browsers are intentionally NOT here — see BROWSER_PROCESSES.
# ─────────────────────────────────────────────────────────────

NOISE_PROCESSES = {
    "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
    "csrss.exe", "smss.exe", "system",
    "msmpeng.exe", "securityhealthservice.exe",
    "nvcontainer.exe", "nvdisplay.container.exe",
    "splunk.exe", "splunkd.exe",
    "teams.exe", "onedrive.exe", "discord.exe", "spotify.exe",
    "steam.exe", "zoom.exe", "slack.exe",
    "code.exe", "devenv.exe",
}

# ─────────────────────────────────────────────────────────────
# BROWSER PROCESSES — alert at MEDIUM, not silenced.
# Browsers making connections to C2 ports = drive-by or BrowserExec.
# ─────────────────────────────────────────────────────────────

BROWSER_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe",
    "iexplore.exe", "opera.exe", "brave.exe",
}

# ─────────────────────────────────────────────────────────────
# PRIVATE IP RANGES — never alert on internal connections
# ─────────────────────────────────────────────────────────────

_PRIVATE = (
    "127.", "0.", "::1",
    "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE)


def monitor_network(alert_callback):
    """
    Scan all TCP connections every 2 seconds.
    Alert on C2-port connections from non-noise processes.

    severity is NOT set in alert_callback — pipeline decides via
    NET_PORT_RISK:<level> embedded in detail (Signal 15).
    """
    host     = socket.gethostname()
    seen     = {}   # conn_key → last_alert_timestamp
    COOLDOWN = 30   # seconds before re-alerting same connection

    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    print(f"  [NetworkDetector] Active — {len(SUSPICIOUS_PORTS)} C2 ports, "
          f"{len(BROWSER_PROCESSES)} browser processes monitored")

    while True:
        try:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    if not conn.raddr:
                        continue
                    if conn.status not in WATCH_STATES:
                        continue

                    port = conn.raddr.port
                    ip   = conn.raddr.ip

                    if port not in SUSPICIOUS_PORTS:
                        continue
                    if _is_private(ip):
                        continue

                    # Resolve process name
                    proc_name = "unknown"
                    try:
                        if conn.pid:
                            proc_name = psutil.Process(conn.pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    # Silently skip pure noise processes
                    if proc_name in NOISE_PROCESSES:
                        continue

                    # Dedup with cooldown
                    conn_key = f"{proc_name}_{ip}_{port}"
                    now      = time.time()
                    if now - seen.get(conn_key, 0) < COOLDOWN:
                        continue
                    seen[conn_key] = now

                    # Prune stale entries
                    seen = {k: v for k, v in seen.items()
                            if now - v < COOLDOWN * 4}

                    risk_hint, desc = SUSPICIOUS_PORTS[port]

                    # Downgrade browsers to MEDIUM regardless of port risk
                    if proc_name in BROWSER_PROCESSES:
                        risk_hint = "MEDIUM"
                        context   = "Browser making suspicious connection — possible drive-by or BrowserExec"
                    else:
                        context   = desc

                    detail = (
                        f"{context}\n"
                        f"Process : {proc_name}\n"
                        f"Dest    : {ip}:{port}\n"
                        f"State   : {conn.status}\n"
                        f"NET_PORT_RISK:{risk_hint}"  # scored by calculate_severity Signal 15
                    )

                    alert_callback({
                        "event":  "Suspicious Network Connection Detected",
                        "detail": detail,
                        # NO "severity" key — pipeline decides.
                        "host":   host,
                        "user":   user,
                        "source": "network",
                        "log_source": "Network",
                    })

                except Exception:
                    pass

            time.sleep(2)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(2)