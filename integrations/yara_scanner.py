"""
SentinelX YARA Scanner
=========================
Real file/malware pattern matching via YARA, the industry-standard
signature format. This is a genuine capability upgrade for
detectors/sysmon_file_detector.py, which currently only checks filenames
and drop paths against a keyword list (_score_file() — see that file) and
has no visibility into what's actually IN a dropped file.

REQUIRES: pip install yara-python
This is a compiled extension but has prebuilt wheels for Windows/Mac/Linux
— `pip install yara-python` should not require a C compiler on a normal
Windows machine. If the import fails, this module degrades the same way
every other optional connector in this app does: prints one line, stays
inactive, never crashes anything that imports it.

RULES: drop .yar/.yml files in yara_rules/ (created automatically with a
small starter set covering a few well-known, safe-to-ship patterns —
these are NOT a substitute for a real curated ruleset; add your own or
pull a known-good public set like the Neo23x0/signature-base or Yara
Rules Project repos for real coverage).

CONFIGURATION (.env)
---------------------
YARA_ENABLED       "true"/"false" — default true.
YARA_RULES_DIR      Default: yara_rules/ (relative to project root).
YARA_MAX_FILE_MB    Default 50 — skip scanning anything larger (YARA on
                    huge files can be slow; this bounds worst case).
"""

import os
import glob

try:
    import yara
    YARA_OK = True
except ImportError:
    YARA_OK = False
    print("[YaraScanner] WARNING: yara-python not installed "
          "(pip install yara-python) — YARA scanning disabled")


def _load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

_load_dotenv()

ENABLED    = os.environ.get("YARA_ENABLED", "true").strip().lower() != "false"
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR  = os.environ.get("YARA_RULES_DIR", "").strip() or os.path.join(_PROJECT_ROOT, "yara_rules")
MAX_MB     = int(os.environ.get("YARA_MAX_FILE_MB", "50") or 50)

_STARTER_RULES = """\
// SentinelX starter YARA rules — a small, safe-to-ship starting point.
// This is NOT a real threat-hunting ruleset. Replace/extend with a
// curated public set (e.g. Neo23x0/signature-base, YARA Rules Project)
// for genuine detection coverage — these exist so the scanner has
// something to actually match against out of the box.

rule Suspicious_Base64_PowerShell_In_File
{
    meta:
        description = "File contains a long base64 blob near a PowerShell reference"
        severity = "MEDIUM"
    strings:
        $ps = "powershell" nocase
        $b64 = /[A-Za-z0-9+\\/]{100,}={0,2}/
    condition:
        $ps and $b64
}

rule Embedded_EXE_Header_In_NonExe
{
    meta:
        description = "MZ/PE header found inside a file that isn't a .exe/.dll"
        severity = "HIGH"
    strings:
        $mz = { 4D 5A }
        $pe = "PE\\x00\\x00"
    condition:
        $mz at 0 and $pe
}

rule Known_Ransomware_Note_Strings
{
    meta:
        description = "Common ransom-note phrasing"
        severity = "CRITICAL"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "bitcoin" nocase
        $s4 = "restore your files" nocase
    condition:
        2 of ($s1, $s2, $s3, $s4)
}

rule Mimikatz_Strings
{
    meta:
        description = "Strings commonly present in Mimikatz builds"
        severity = "CRITICAL"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "mimikatz" nocase
        $s3 = "gentilkiwi" nocase
    condition:
        any of them
}
"""

_compiled = None
_compiled_mtime = 0.0


def _ensure_rules_dir():
    if not os.path.isdir(RULES_DIR):
        os.makedirs(RULES_DIR, exist_ok=True)
        starter_path = os.path.join(RULES_DIR, "starter_rules.yar")
        with open(starter_path, "w", encoding="utf-8") as f:
            f.write(_STARTER_RULES)
        print(f"[YaraScanner] created {RULES_DIR} with a small starter ruleset — "
              f"add your own .yar files there for real coverage")


def _get_compiled():
    """Recompiles only when a rule file has changed (checked via directory
    mtime) — scanning is potentially called on every file-creation event,
    so this avoids recompiling the whole ruleset every single time."""
    global _compiled, _compiled_mtime
    if not YARA_OK or not ENABLED:
        return None
    _ensure_rules_dir()
    try:
        current_mtime = max(
            (os.path.getmtime(p) for p in glob.glob(os.path.join(RULES_DIR, "*.yar*"))),
            default=0.0
        )
    except OSError:
        current_mtime = 0.0

    if _compiled is None or current_mtime > _compiled_mtime:
        rule_files = glob.glob(os.path.join(RULES_DIR, "*.yar")) + \
                     glob.glob(os.path.join(RULES_DIR, "*.yara"))
        if not rule_files:
            return None
        try:
            filepaths = {f"r{i}": p for i, p in enumerate(rule_files)}
            _compiled = yara.compile(filepaths=filepaths)
            _compiled_mtime = current_mtime
        except yara.Error as e:
            print(f"[YaraScanner] WARNING: failed to compile rules: {e}")
            return None
    return _compiled


def scan_file(path: str) -> dict:
    """
    Returns {"scanned": bool, "matches": [...], "error": str|None}.
    Never raises. `matches` is a list of {"rule": name, "severity": meta,
    "description": meta} for whatever fired.
    """
    if not YARA_OK:
        return {"scanned": False, "matches": [], "error": "yara-python not installed"}
    if not ENABLED:
        return {"scanned": False, "matches": [], "error": "YARA_ENABLED is false"}
    if not path or not os.path.isfile(path):
        return {"scanned": False, "matches": [], "error": "file not found"}

    try:
        if os.path.getsize(path) > MAX_MB * 1024 * 1024:
            return {"scanned": False, "matches": [],
                     "error": f"file exceeds YARA_MAX_FILE_MB ({MAX_MB}MB), skipped"}
    except OSError as e:
        return {"scanned": False, "matches": [], "error": str(e)}

    rules = _get_compiled()
    if rules is None:
        return {"scanned": False, "matches": [], "error": "no compiled rules available"}

    try:
        raw_matches = rules.match(path, timeout=10)
        matches = [{
            "rule": m.rule,
            "severity": m.meta.get("severity", "MEDIUM"),
            "description": m.meta.get("description", ""),
        } for m in raw_matches]
        return {"scanned": True, "matches": matches, "error": None}
    except yara.TimeoutError:
        return {"scanned": False, "matches": [], "error": "scan timed out"}
    except Exception as e:
        return {"scanned": False, "matches": [], "error": str(e)}


def highest_match_severity(matches: list) -> str:
    """Reduces a list of YARA matches to one severity hint (CRITICAL/HIGH/MEDIUM),
    for feeding into calculate_severity() as a YARA_RISK:<level> hint."""
    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    best = "LOW"
    for m in matches:
        sev = (m.get("severity") or "MEDIUM").upper()
        if order.get(sev, 1) > order.get(best, 0):
            best = sev
    return best
