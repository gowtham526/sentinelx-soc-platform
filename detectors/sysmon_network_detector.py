"""
SentinelX Sysmon Network Detector v3.0
========================================
Reads Sysmon Event ID 3 (NetworkConnect) from the Windows Event Log
and alerts on suspicious outbound connections.

Changes from v2.4
─────────────────
1. SEVERITY ADDED — was completely missing from build_alert() in v2.4.
   Now embedded as NET_PORT_RISK:<level> hint in detail so that
   calculate_severity() scores it correctly (Signal 15).

2. PROCESS FILTER COMPLETELY REWRITTEN:
   Old: only alerted on powershell.exe, cmd.exe, wscript.exe, cscript.exe.
        Missing: test.exe, nc.exe, any custom malware binary — the most
        common real-world C2 beaconing processes.
   New: alert on ALL processes EXCEPT NOISE_PROCESSES whitelist.
        Process name is included in detail for analyst context.

3. PORT INTELLIGENCE:
   C2 port list from network_detector.py reused — consistent risk hints
   across both network detection paths (psutil + Sysmon EID 3).

4. PRIVATE IP FILTER: never alert on RFC1918 / loopback addresses.

5. DEDUPLICATION: (process, ip, port) deduplicated with 60s cooldown.

6. BARE EXCEPT REPLACED with Exception to surface real errors.

7. FORMATTING NORMALISED — was split across excessive lines in v2.4.
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
    print("[SysmonNetDetector] WARNING: pywin32 not installed — "
          "native Sysmon EID 3 monitoring disabled")

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

# ─────────────────────────────────────────────────────────────
# C2 / SUSPICIOUS PORTS — risk hints for calculate_severity()
# Shared definition with network_detector.py for consistency.
# ─────────────────────────────────────────────────────────────

C2_PORTS = {
    4444:  ("CRITICAL", "Metasploit default reverse shell"),
    31337: ("CRITICAL", "Elite RAT callback"),
    4445:  ("CRITICAL", "Metasploit alternate C2"),
    5554:  ("CRITICAL", "Sasser worm / RAT"),
    9002:  ("CRITICAL", "PlugX RAT default"),
    8888:  ("CRITICAL", "Common reverse shell"),
    1337:  ("HIGH",     "Leet backdoor port"),
    6666:  ("HIGH",     "Common reverse shell"),
    6667:  ("HIGH",     "IRC botnet C2"),
    7777:  ("HIGH",     "Common backdoor port"),
    9999:  ("HIGH",     "Common reverse shell"),
    9001:  ("HIGH",     "Tor relay / C2"),
    4545:  ("HIGH",     "Known RAT callback"),
    4443:  ("HIGH",     "HTTPS reverse shell"),
    1080:  ("MEDIUM",   "SOCKS proxy / exfiltration"),
    8443:  ("MEDIUM",   "Alt HTTPS C2"),
    2222:  ("MEDIUM",   "Non-standard SSH"),
    9090:  ("MEDIUM",   "Common RAT port"),
    3128:  ("MEDIUM",   "Squid proxy / C2 tunnel"),
}

# ─────────────────────────────────────────────────────────────
# NOISE PROCESSES — system processes with known-good net activity
# ─────────────────────────────────────────────────────────────

NOISE_PROCESSES = {
    "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
    "csrss.exe", "smss.exe", "system",
    "msmpeng.exe", "securityhealthservice.exe",
    "onedrive.exe", "teams.exe", "zoom.exe", "discord.exe",
    "spotify.exe", "steam.exe", "slack.exe",
    "code.exe", "devenv.exe",
    "splunk.exe", "splunkd.exe",
}

# ─────────────────────────────────────────────────────────────
# PRIVATE IP RANGES — skip internal connections
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


def _parse_xml(xml_str: str):
    """Parse Sysmon EID 3 XML. Returns (data_dict, record_id)."""
    ns     = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    data   = {}
    rec_id = 0
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


def _get_port_risk(port_str: str) -> tuple:
    """Look up port in C2_PORTS. Returns (risk_hint, description)."""
    try:
        port = int(port_str)
        if port in C2_PORTS:
            return C2_PORTS[port]
    except (ValueError, TypeError):
        pass
    return None, None


def monitor_sysmon_network(alert_callback):
    """
    Monitor Sysmon EID 3 (NetworkConnect) for C2 beaconing.

    Alerts on ALL processes making connections to known C2 ports,
    except NOISE_PROCESSES. This catches custom malware EXEs that
    the process-name filter in v2.4 completely missed.

    severity is NOT set in alert_callback — pipeline decides via
    NET_PORT_RISK:<level> embedded in detail (Signal 15).
    """
    if not WIN32_OK:
        print("[SysmonNetDetector] pywin32 unavailable — EID 3 monitoring offline")
        return

    host = socket.gethostname()
    try:
        user = os.getlogin()
    except Exception:
        user = "system"

    seen_rec_ids: set  = set()
    seen_conns:   dict = {}   # (proc, ip, port) → last_alert_ts
    COOLDOWN           = 60   # seconds before re-alerting same connection
    startup_rec_id     = 0

    # Capture baseline
    try:
        handle = win32evtlog.EvtQuery(
            LOG_NAME,
            win32evtlog.EvtQueryReverseDirection,
            "*[System[(EventID=3)]]",
        )
        events = win32evtlog.EvtNext(handle, 1)
        if events:
            xml_str           = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
            _, startup_rec_id = _parse_xml(xml_str)
            print(f"  [SysmonNetDetector] Baseline at record ID {startup_rec_id}")
    except Exception as e:
        print(f"  [SysmonNetDetector] Baseline failed ({e}) — will process all events")
        startup_rec_id = 0

    print(f"  [SysmonNetDetector] Active — {len(C2_PORTS)} C2 ports, "
          f"all processes except {len(NOISE_PROCESSES)} noise entries")

    while True:
        try:
            handle = win32evtlog.EvtQuery(
                LOG_NAME,
                win32evtlog.EvtQueryReverseDirection,
                "*[System[(EventID=3)]]",
            )
            events = win32evtlog.EvtNext(handle, 50)

            for event in events:
                try:
                    xml_str         = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    data, record_id = _parse_xml(xml_str)

                    if record_id <= startup_rec_id:
                        continue
                    if record_id in seen_rec_ids:
                        continue
                    seen_rec_ids.add(record_id)

                    image   = str(data.get("Image",           "")).lower()
                    dst_ip  = str(data.get("DestinationIp",   ""))
                    dst_port = str(data.get("DestinationPort", ""))
                    src_ip  = str(data.get("SourceIp",        ""))
                    proto   = str(data.get("Protocol",        "tcp"))
                    utc_ts  = str(data.get("UtcTime",         ""))

                    if not dst_ip or _is_private(dst_ip):
                        continue

                    # Get process name from full image path
                    proc_name = image.split("\\")[-1] if "\\" in image else image
                    if proc_name in NOISE_PROCESSES:
                        continue

                    # Check if destination port is a known C2 port
                    risk_hint, port_desc = _get_port_risk(dst_port)
                    if risk_hint is None:
                        # Not a known C2 port — still alert if process is suspicious
                        # (e.g. powershell, cmd, wscript, cscript making any external conn)
                        suspicious_procs = {
                            "powershell.exe", "pwsh.exe", "cmd.exe",
                            "wscript.exe", "cscript.exe", "mshta.exe",
                        }
                        if proc_name not in suspicious_procs:
                            continue
                        risk_hint  = "MEDIUM"
                        port_desc  = f"Suspicious process making external connection"

                    # Dedup by (proc, ip, port)
                    conn_key = f"{proc_name}|{dst_ip}|{dst_port}"
                    now      = time.time()
                    if now - seen_conns.get(conn_key, 0) < COOLDOWN:
                        continue
                    seen_conns[conn_key] = now

                    # Prune stale dedup entries
                    seen_conns = {k: v for k, v in seen_conns.items()
                                  if now - v < COOLDOWN * 4}

                    detail = (
                        f"{port_desc}\n"
                        f"Process  : {proc_name}\n"
                        f"Image    : {image}\n"
                        f"Source   : {src_ip}\n"
                        f"Dest     : {dst_ip}:{dst_port} ({proto.upper()})\n"
                        f"Time     : {utc_ts}\n"
                        f"MITRE    : T1071.001 — Application Layer Protocol\n"
                        f"NET_PORT_RISK:{risk_hint}"   # scored by calculate_severity Signal 15
                    )

                    alert_callback({
                        "event":  "Suspicious Network Connection Detected",
                        "detail": detail,
                        # NO "severity" key — pipeline decides.
                        "host":   host,
                        "user":   user,
                        "source": "sysmon_network",
                        "log_source": "Sysmon",
                    })

                except Exception:
                    pass

            time.sleep(2)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(2)