"""
SentinelX IOC Feed Puller
===========================
Downloads free, open IOC (Indicator of Compromise) feeds and checks
alerts against them locally — this is PROACTIVE matching against known-bad
indicators, complementary to (not a replacement for) the existing
reactive VT/AbuseIPDB lookups in threat_intel.py:
  - threat_intel.py answers "is this specific IP/hash bad?" when an
    analyst manually checks one, using paid-tier-limited per-lookup APIs.
  - This module answers "does anything in today's alerts match a known-bad
    indicator?" automatically, using bulk-downloaded free feeds that don't
    consume VT/AbuseIPDB's rate limits at all.

Feeds used (all free, no API key required):
  - abuse.ch ThreatFox   — recent IOCs (IPs, domains, hashes) tagged with
                            malware family and confidence
  - abuse.ch URLhaus     — malicious URLs/domains actively serving malware

Feeds refresh on an interval (default 1 hour) and are cached in memory;
refreshing doesn't block alert processing — if a refresh is in progress
or fails, checks just use whatever was loaded last.

CONFIGURATION (.env)
---------------------
IOC_FEEDS_ENABLED       "true"/"false" — default true. Set false to
                        disable entirely (e.g. if you have no outbound
                        internet from wherever this runs).
IOC_REFRESH_MINUTES     Default 60.
"""

import os
import time
import threading

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


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

ENABLED          = os.environ.get("IOC_FEEDS_ENABLED", "true").strip().lower() != "false"
REFRESH_MINUTES  = int(os.environ.get("IOC_REFRESH_MINUTES", "60") or 60)

_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_URL   = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

_lock  = threading.Lock()
_state = {
    "last_refresh": 0.0,
    "ips":     set(),   # known-bad IPs (ThreatFox)
    "domains": set(),   # known-bad domains (ThreatFox + URLhaus)
    "hashes":  set(),   # known-bad file hashes (ThreatFox)
    "meta":    {},       # indicator -> {"malware": "...", "confidence": N}
}


def refresh_feeds(force: bool = False) -> dict:
    """
    Pull fresh IOC data. Safe to call often — it no-ops if the last
    refresh was recent, unless force=True. Never raises; on any failure
    it just keeps whatever was loaded before.
    """
    if not ENABLED:
        return {"success": False, "error": "IOC_FEEDS_ENABLED is false"}
    if not REQUESTS_OK:
        return {"success": False, "error": "'requests' package not available"}

    with _lock:
        if not force and (time.time() - _state["last_refresh"]) < REFRESH_MINUTES * 60:
            return {"success": True, "skipped": True, "reason": "recent refresh still fresh"}

        new_ips, new_domains, new_hashes, new_meta = set(), set(), set(), {}

        try:
            resp = requests.post(_THREATFOX_URL, json={"query": "get_iocs", "days": 3}, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []) or []:
                    ioc_type  = item.get("ioc_type", "")
                    ioc_value = item.get("ioc", "")
                    malware   = item.get("malware_printable", item.get("malware", "unknown"))
                    conf      = item.get("confidence_level", 50)
                    if not ioc_value:
                        continue
                    if "ip" in ioc_type:
                        ip = ioc_value.split(":")[0]  # ThreatFox sometimes includes :port
                        new_ips.add(ip)
                        new_meta[ip] = {"malware": malware, "confidence": conf, "source": "ThreatFox"}
                    elif "domain" in ioc_type:
                        new_domains.add(ioc_value.lower())
                        new_meta[ioc_value.lower()] = {"malware": malware, "confidence": conf, "source": "ThreatFox"}
                    elif ioc_type in ("md5_hash", "sha1_hash", "sha256_hash"):
                        new_hashes.add(ioc_value.lower())
                        new_meta[ioc_value.lower()] = {"malware": malware, "confidence": conf, "source": "ThreatFox"}
        except Exception as e:
            print(f"[IOCFeeds] ThreatFox refresh failed (non-fatal, keeping old data): {e}")

        try:
            resp = requests.get(_URLHAUS_URL, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("urls", []) or []:
                    host = (item.get("host") or "").lower()
                    if host:
                        new_domains.add(host)
                        new_meta.setdefault(host, {"malware": item.get("threat", "malware_url"),
                                                     "confidence": 75, "source": "URLhaus"})
        except Exception as e:
            print(f"[IOCFeeds] URLhaus refresh failed (non-fatal, keeping old data): {e}")

        # Only replace if we got at least something — a total-failure
        # refresh should leave the previous, still-useful data in place
        if new_ips or new_domains or new_hashes:
            _state["ips"], _state["domains"], _state["hashes"] = new_ips, new_domains, new_hashes
            _state["meta"] = new_meta
        _state["last_refresh"] = time.time()

        return {"success": True, "ips": len(_state["ips"]), "domains": len(_state["domains"]),
                "hashes": len(_state["hashes"]), "refreshed_at": _state["last_refresh"]}


def check_ioc(value: str, kind: str = None) -> dict:
    """
    Check a single value against the cached feed data.
    kind: "ip" | "domain" | "hash" | None (checks all three sets)
    Returns {"match": bool, "malware": str|None, "confidence": int|None, "source": str|None}
    """
    if not value:
        return {"match": False}
    value = value.strip().lower()
    with _lock:
        sets_to_check = (
            [_state["ips"]] if kind == "ip" else
            [_state["domains"]] if kind == "domain" else
            [_state["hashes"]] if kind == "hash" else
            [_state["ips"], _state["domains"], _state["hashes"]]
        )
        for s in sets_to_check:
            if value in s:
                meta = _state["meta"].get(value, {})
                return {"match": True, "malware": meta.get("malware"),
                        "confidence": meta.get("confidence"), "source": meta.get("source")}
    return {"match": False}


def feed_status() -> dict:
    with _lock:
        return {
            "enabled": ENABLED,
            "last_refresh": _state["last_refresh"],
            "ips": len(_state["ips"]), "domains": len(_state["domains"]),
            "hashes": len(_state["hashes"]),
        }


def start_background_refresh():
    """Call once from main_engine.py — refreshes on a loop in a daemon thread."""
    if not ENABLED:
        print("  [IOC Feeds] IOC_FEEDS_ENABLED is false — connector idle")
        return

    def _loop():
        while True:
            result = refresh_feeds(force=True)
            if result.get("success") and not result.get("skipped"):
                print(f"  [IOC Feeds] refreshed: {result.get('ips',0)} IPs, "
                      f"{result.get('domains',0)} domains, {result.get('hashes',0)} hashes")
            time.sleep(REFRESH_MINUTES * 60)

    t = threading.Thread(target=_loop, daemon=True, name="IOCFeedRefresh")
    t.start()
