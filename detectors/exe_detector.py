"""
SentinelX EXE Detector v3.0
Monitors Temp and AppData folders for new malicious executables.
Connects to alert_pipeline.fire() for full enrichment.
"""

import os
import time
import hashlib
import socket

# ─────────────────────────────────────────────────────────────
# WATCH DIRECTORIES — all possible temp/appdata paths
# ─────────────────────────────────────────────────────────────

def _get_watch_dirs():
    dirs = []
    for env_var in ["TEMP", "TMP"]:
        d = os.environ.get(env_var, "")
        if d and os.path.isdir(d):
            dirs.append(d)

    # Also check common user paths
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        extra = [
            os.path.join(userprofile, "AppData", "Local", "Temp"),
            os.path.join(userprofile, "AppData", "Roaming"),
            os.path.join(userprofile, "Downloads"),
        ]
        for d in extra:
            if os.path.isdir(d) and d not in dirs:
                dirs.append(d)

    # ProgramData
    pd = os.environ.get("ProgramData", "C:\\ProgramData")
    if os.path.isdir(pd):
        dirs.append(pd)

    return list(set(dirs))

# ─────────────────────────────────────────────────────────────
# SAFE KEYWORDS — never alert on these
# ─────────────────────────────────────────────────────────────

SAFE_KEYWORDS = [
    "setup", "installer", "install", "update", "updater",
    "chrome", "firefox", "edge", "discord", "steam",
    "zoom", "teams", "python", "git", "docker",
    "vmware", "virtualbox", "vscode", "dotnet",
    "mediacreationtool", "proteus", "logmein",
    "winrar", "7z", "office", "microsoft", "adobe",
    "acrobat", "vlc", "notepad++", "nvidia", "amd",
]

# ─────────────────────────────────────────────────────────────
# MALWARE KEYWORDS — raise score significantly
# ─────────────────────────────────────────────────────────────

MALWARE_KEYWORDS = [
    "payload", "evil", "malware", "virus", "trojan",
    "hack", "mimikatz", "meterpreter", "rat", "shell",
    "beacon", "stealer", "inject", "dropper", "exploit",
    "backdoor", "stager", "loader", "c2", "pwn",
    "ransomware", "crypter", "keylogger",
]


def _risk_score(fname, folder):
    """Score a filename 0–100. Higher = more suspicious."""
    lower = fname.lower()

    # Safe keyword match → skip entirely
    if any(kw in lower for kw in SAFE_KEYWORDS):
        return -1

    score = 20  # base: any exe in temp

    # Malware keyword match
    for kw in MALWARE_KEYWORDS:
        if kw in lower:
            score += 55

    # In a temp/appdata folder
    folder_lower = folder.lower()
    if "temp" in folder_lower or "tmp" in folder_lower:
        score += 20
    if "appdata" in folder_lower:
        score += 15
    if "downloads" in folder_lower:
        score += 10
    if "programdata" in folder_lower:
        score += 15

    # Very short random-looking name
    name_no_ext = os.path.splitext(fname)[0]
    if len(name_no_ext) <= 8 and name_no_ext.isalnum():
        score += 15

    # All digits or random hex
    if name_no_ext.isdigit():
        score += 20

    return min(score, 100)


def _severity_from_score(score):
    if score >= 75:  return "CRITICAL"
    if score >= 55:  return "HIGH"
    if score >= 35:  return "MEDIUM"
    return "LOW"


def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unavailable"


def monitor_exe(alert_callback):
    """
    Monitor watch directories for new .exe files.
    Seeds baseline at startup so existing files never alert.
    """
    watch_dirs  = _get_watch_dirs()
    known_files = set()
    host        = socket.gethostname()

    # Seed baseline — ignore everything that already exists
    for folder in watch_dirs:
        try:
            for fname in os.listdir(folder):
                if fname.lower().endswith(".exe"):
                    known_files.add(os.path.join(folder, fname))
        except Exception:
            pass

    print("  EXE baseline seeded -- " + str(len(known_files)) + " existing files ignored")
    print("  Watching: " + str(len(watch_dirs)) + " directories")

    while True:
        try:
            for folder in watch_dirs:
                try:
                    for fname in os.listdir(folder):
                        if not fname.lower().endswith(".exe"):
                            continue

                        full_path = os.path.join(folder, fname)

                        if full_path in known_files:
                            continue

                        known_files.add(full_path)

                        score = _risk_score(fname, folder)
                        if score < 0:
                            continue  # safe keyword match

                        severity = _severity_from_score(score)
                        sha      = _sha256(full_path)

                        detail = (
                            "Suspicious EXE detected in untrusted path\n"
                            "File   : " + full_path + "\n"
                            "SHA256 : " + sha[:32] + "...\n"
                            "Score  : " + str(score) + "\n"
                            "FILE_RISK:" + severity
                        )

                        alert_callback({
                            "event":    "Suspicious EXE File Detected",
                            "detail":   detail,
                            # NO "severity" key — core.alert_pipeline.calculate_severity() decides
                            "host":     host,
                            "user":     os.getlogin(),
                            "source":   "exe",
                            "log_source": "Application",
                        })

                except PermissionError:
                    pass
                except Exception:
                    pass

            time.sleep(3)

        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(3)