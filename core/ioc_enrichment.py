"""Bulk IOC Enrichment Engine.

Accepts a list of IOCs (IPs, domains, hashes) and queries all configured
threat intelligence sources in parallel. Results are cached to avoid
hitting API rate limits.
"""
import json
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_CACHE_FILE = os.path.join(_DIR, "ioc_cache.json")
_lock = threading.Lock()
_CACHE_TTL = 3600  # 1 hour
_MAX_IOCS = 50

# IOC type detection patterns
_IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")


def classify_ioc(value: str) -> str:
    """Determine the type of an IOC."""
    value = value.strip()
    if _IPV4_RE.match(value):
        return "ipv4"
    if _SHA256_RE.match(value):
        return "sha256"
    if _SHA1_RE.match(value):
        return "sha1"
    if _MD5_RE.match(value):
        return "md5"
    if _DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def _load_cache() -> dict:
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict):
    os.makedirs(os.path.dirname(_CACHE_FILE), exist_ok=True)
    # Prune expired entries
    now = time.time()
    cache = {k: v for k, v in cache.items() if v.get("cached_at", 0) + _CACHE_TTL > now}
    with _lock:
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)


def _enrich_single_ioc(ioc: str, ioc_type: str) -> dict:
    """Enrich a single IOC from all available sources."""
    result = {
        "ioc": ioc,
        "type": ioc_type,
        "vt_score": None,
        "abuse_score": None,
        "ioc_feed_hits": [],
        "tags": [],
        "enriched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    # Try VirusTotal
    if ioc_type in ("ipv4", "domain", "sha256", "sha1", "md5"):
        try:
            from threat_intel import vt_lookup
            vt = vt_lookup(ioc)
            if vt and isinstance(vt, dict):
                result["vt_score"] = vt.get("score") or vt.get("positives")
                result["vt_details"] = vt.get("verbose_msg", "")
        except Exception:
            pass
    
    # Try AbuseIPDB (IPs only)
    if ioc_type == "ipv4":
        try:
            from threat_intel import abuse_lookup
            abuse = abuse_lookup(ioc)
            if abuse and isinstance(abuse, dict):
                result["abuse_score"] = abuse.get("abuseConfidenceScore") or abuse.get("score")
                result["abuse_country"] = abuse.get("countryCode", "")
                result["abuse_isp"] = abuse.get("isp", "")
        except Exception:
            pass
    
    # Try IOC feeds
    try:
        from integrations.ioc_feeds import check_ioc
        hits = check_ioc(ioc)
        if hits:
            result["ioc_feed_hits"] = hits if isinstance(hits, list) else [hits]
            result["tags"].append("ioc_feed_match")
    except Exception:
        pass
    
    # Auto-tag based on scores
    if result["vt_score"] and result["vt_score"] > 5:
        result["tags"].append("malicious_vt")
    if result["abuse_score"] and result["abuse_score"] > 50:
        result["tags"].append("malicious_abuse")
    
    return result


def enrich_iocs(iocs: list) -> list:
    """Bulk-enrich a list of IOC strings.
    
    Uses cache to avoid redundant API calls. Queries run in parallel.
    Max 50 IOCs per request.
    """
    if len(iocs) > _MAX_IOCS:
        iocs = iocs[:_MAX_IOCS]
    
    cache = _load_cache()
    now = time.time()
    results = []
    to_enrich = []
    
    for ioc in iocs:
        ioc = ioc.strip()
        if not ioc:
            continue
        
        # Check cache
        if ioc in cache and cache[ioc].get("cached_at", 0) + _CACHE_TTL > now:
            results.append(cache[ioc])
            continue
        
        ioc_type = classify_ioc(ioc)
        to_enrich.append((ioc, ioc_type))
    
    # Enrich uncached IOCs in parallel
    if to_enrich:
        with ThreadPoolExecutor(max_workers=min(5, len(to_enrich))) as executor:
            futures = {
                executor.submit(_enrich_single_ioc, ioc, ioc_type): ioc
                for ioc, ioc_type in to_enrich
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    result["cached_at"] = now
                    results.append(result)
                    cache[result["ioc"]] = result
                except Exception:
                    ioc = futures[future]
                    results.append({"ioc": ioc, "type": "error", "error": "enrichment failed"})
    
    # Save updated cache
    _save_cache(cache)
    
    return results


def extract_iocs_from_text(text: str) -> list:
    """Extract IOCs (IPs, domains, hashes) from free text."""
    iocs = set()
    
    # IPv4 addresses
    for match in re.finditer(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", text):
        ip = match.group()
        # Skip private/reserved ranges
        if not ip.startswith(("10.", "127.", "192.168.", "0.")):
            iocs.add(ip)
    
    # SHA256 hashes
    for match in re.finditer(r"\b[a-fA-F0-9]{64}\b", text):
        iocs.add(match.group().lower())
    
    # Domains (basic extraction)
    for match in re.finditer(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk)\b", text):
        domain = match.group().lower()
        # Skip common benign domains
        if domain not in ("github.com", "google.com", "microsoft.com", "windows.com"):
            iocs.add(domain)
    
    return list(iocs)


def enrich_alert(alert: dict) -> list:
    """Auto-extract IOCs from an alert and enrich them."""
    text_fields = [
        str(alert.get("detail", "")),
        str(alert.get("event", "")),
        str(alert.get("host", "")),
    ]
    combined_text = " ".join(text_fields)
    iocs = extract_iocs_from_text(combined_text)
    
    if not iocs:
        return []
    return enrich_iocs(iocs)
