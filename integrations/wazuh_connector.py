"""
SentinelX Wazuh Connector v1.0
===============================
Polls Wazuh for alerts and agent health, feeding alerts into the same
process_alert() pipeline every other detector uses.

WAZUH HAS TWO SEPARATE APIs — THIS CONNECTOR USES BOTH
--------------------------------------------------------
1. Manager API (default port 55000, JWT auth via POST /security/user/authenticate)
   — inventory/control-plane: agents, rules, decoders, cluster status. This
   connector uses it for agent health only (get_wazuh_agents below).

2. Indexer API (OpenSearch, default port 9200, basic auth) — this is where
   actual alert DOCUMENTS live, in an index pattern like `wazuh-alerts-4.x-*`.
   There is no "give me alerts" endpoint on the Manager API itself; alert
   search happens here. This connector's main loop polls this API.

   If you're not sure of your indexer host/port, it's very often the same
   host as your Wazuh manager/dashboard, port 9200 — check your Wazuh
   deployment's docker-compose.yml or ossec.conf if unsure.

Because API paths and field names can shift slightly between Wazuh
versions, if polling ever returns 0 alerts despite the deployment being
active, check WAZUH_INDEXER_HOST/PORT and confirm the index name below
(`_ALERT_INDEX_PATTERN`) matches what your Wazuh version actually writes to
— that's the single most likely thing to need adjusting per-deployment.

CONFIGURATION (.env)
---------------------
WAZUH_INDEXER_HOST     Required to enable this connector at all.
WAZUH_INDEXER_PORT     Default 9200.
WAZUH_INDEXER_USER     Default "admin" (Wazuh's common default — change it).
WAZUH_INDEXER_PASS     Required if your indexer isn't using the default.
WAZUH_INDEXER_VERIFY_SSL   "true"/"false" — default false, since Wazuh's
                           default install uses a self-signed cert.
WAZUH_POLL_SECONDS     Default 15.
WAZUH_MIN_LEVEL        Default 3. Wazuh rule levels run 0-15 and a stock
                       deployment produces a LOT of level-0-2 informational
                       noise (logins, config changes, etc.) — this floor
                       exists specifically so this connector doesn't drown
                       your alert feed the way a raw unfiltered Wazuh feed
                       would. Raise it if you still see too much noise,
                       lower it (down to 0) if you want everything.

Optional, for agent inventory (get_wazuh_agents):
WAZUH_MANAGER_HOST, WAZUH_MANAGER_PORT (default 55000),
WAZUH_API_USER, WAZUH_API_PASS
"""

import os
import time
import base64

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass


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
            v = v.strip()
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1]
            os.environ.setdefault(k.strip(), v)

_load_dotenv()

INDEXER_HOST   = os.environ.get("WAZUH_INDEXER_HOST", "").strip().strip('"').strip("'")
INDEXER_PORT   = os.environ.get("WAZUH_INDEXER_PORT", "9200").strip().strip('"').strip("'")
INDEXER_USER   = os.environ.get("WAZUH_INDEXER_USER", "admin").strip().strip('"').strip("'")
INDEXER_PASS   = os.environ.get("WAZUH_INDEXER_PASS", "").strip().strip('"').strip("'")
VERIFY_SSL     = os.environ.get("WAZUH_INDEXER_VERIFY_SSL", "false").strip().strip('"').strip("'").lower() == "true"
POLL_SECONDS   = int(os.environ.get("WAZUH_POLL_SECONDS", "15").strip().strip('"').strip("'") or 15)
MIN_LEVEL      = int(os.environ.get("WAZUH_MIN_LEVEL", "3").strip().strip('"').strip("'") or 3)

MANAGER_HOST = os.environ.get("WAZUH_MANAGER_HOST", "").strip()
MANAGER_PORT = os.environ.get("WAZUH_MANAGER_PORT", "55000").strip()
API_USER     = os.environ.get("WAZUH_API_USER", "").strip()
API_PASS     = os.environ.get("WAZUH_API_PASS", "").strip()

# Adjust this if your Wazuh version writes to a different index pattern —
# see the module docstring. 4.x default shown here.
_ALERT_INDEX_PATTERN = "wazuh-alerts-*"


def _level_to_risk(level: int) -> str:
    """
    Wazuh rule levels: 0-15. Wazuh's own docs bucket 12-15 as the most
    severe and 7-11 as medium-ish; this mapping follows that convention.
    Adjust the thresholds below if your environment's rule tuning runs
    hotter or cooler than stock.
    """
    if level >= 12: return "CRITICAL"
    if level >= 9:  return "HIGH"
    if level >= 5:  return "MEDIUM"
    return "LOW"


def _extract_user(source: dict) -> str:
    """Wazuh alerts carry the OS username in different fields depending on
    which log source produced them — check the common ones in order."""
    data = source.get("data", {}) or {}
    for path in (
        ("win", "eventdata", "targetUserName"),
        ("win", "eventdata", "subjectUserName"),
    ):
        node = data
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        if node:
            return node
    return data.get("srcuser") or data.get("dstuser") or data.get("audit", {}).get("user") or "unknown"


def _extract_mitre_override(rule: dict) -> dict | None:
    """
    Wazuh tags a large fraction of its ruleset with real MITRE ATT&CK
    metadata (rule.mitre.id / rule.mitre.tactic) — when present, that's
    more reliable than SentinelX's own keyword-guess, so this becomes the
    `mitre_override` the pipeline's map_mitre() now knows how to accept.
    """
    mitre = rule.get("mitre") or {}
    ids     = mitre.get("id") or []
    tactics = mitre.get("tactic") or []
    techs   = mitre.get("technique") or []
    if not ids:
        return None
    return {
        "mitre_id":     ids[0] if ids else None,
        "mitre_name":   techs[0] if techs else None,
        "mitre_tactic": tactics[0] if tactics else None,
    }


def monitor_wazuh(alert_callback):
    """
    Poll the Wazuh indexer for new alerts above WAZUH_MIN_LEVEL and feed
    them into the pipeline. Tracks the last-seen timestamp across polls so
    each cycle only asks for alerts newer than the previous one.
    """
    if not INDEXER_HOST:
        print("  [Wazuh] WAZUH_INDEXER_HOST not set in .env — connector idle")
        return
    if not REQUESTS_OK:
        print("  [Wazuh] 'requests' package not available — connector idle")
        return

    base_url = f"https://{INDEXER_HOST}:{INDEXER_PORT}/{_ALERT_INDEX_PATTERN}/_search"
    auth = (INDEXER_USER, INDEXER_PASS)
    seen_ids: set = set()
    # Start from 5 minutes ago to avoid the 2600-alert historical backlog 
    # but still catch recent test alerts
    last_ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 300))

    def dbg(msg):
        with open("C:/SOC_AUTOMATION_PROJECT_FINAL/wazuh_debug.log", "a") as f:
            f.write(time.strftime("%H:%M:%S ") + msg + "\n")
        print(msg)

    dbg(f"  [Wazuh] Polling {base_url} every {POLL_SECONDS}s (min level {MIN_LEVEL})")

    while True:
        try:
            query = {
                "size": 200,
                "sort": [{"timestamp": {"order": "asc", "unmapped_type": "date"}}],
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"timestamp": {"gt": last_ts}}},
                            {"range": {"rule.level": {"gte": MIN_LEVEL}}},
                        ]
                    }
                },
            }
            resp = requests.get(base_url, json=query, auth=auth,
                                 verify=VERIFY_SSL, timeout=10)

            if resp.status_code == 401:
                dbg("  [Wazuh] auth failed (401) — check WAZUH_INDEXER_USER/PASS")
                time.sleep(POLL_SECONDS)
                continue
            if resp.status_code == 404:
                dbg(f"  [Wazuh] index pattern '{_ALERT_INDEX_PATTERN}' not found (404) "
                      f"— your Wazuh version may use a different index name, see this "
                      f"module's docstring")
                time.sleep(POLL_SECONDS)
                continue
            if resp.status_code != 200:
                dbg(f"  [Wazuh] unexpected status {resp.status_code}: {resp.text[:200]}")
                time.sleep(POLL_SECONDS)
                continue

            hits = resp.json().get("hits", {}).get("hits", [])
            if len(hits) > 0:
                dbg(f"  [Wazuh] Found {len(hits)} hits matching filter > {last_ts}")

            for hit in hits:
                doc_id = hit.get("_id")
                if not doc_id or doc_id in seen_ids:
                    continue
                seen_ids.add(doc_id)
                if len(seen_ids) > 5000:  # bounded, same spirit as sysmon_detector's pid cache trim
                    seen_ids = set(list(seen_ids)[-2500:])

                source = hit.get("_source", {}) or {}
                rule   = source.get("rule", {}) or {}
                agent  = source.get("agent", {}) or {}
                level  = rule.get("level", 0)

                # Accept both raw Wazuh 'timestamp' and Filebeat's '@timestamp'
                ts = source.get("timestamp") or source.get("@timestamp")
                if ts and ts > last_ts:
                    last_ts = ts

                risk = _level_to_risk(level)
                mitre_override = _extract_mitre_override(rule)

                detail = (
                    f"{rule.get('description', 'Wazuh Alert')}\n"
                    f"Rule ID   : {rule.get('id', '?')} (level {level})\n"
                    f"Agent     : {agent.get('name', 'unknown')} ({agent.get('id', '?')})\n"
                    f"Log       : {str(source.get('full_log', ''))[:300]}\n"
                    f"WAZUH_RISK:{risk}"
                )

                payload = {
                    "event":  f"Wazuh: {rule.get('groups', ['alert'])[0] if rule.get('groups') else 'Alert'}",
                    "detail": detail,
                    "host":   agent.get("name", "unknown"),
                    "user":   _extract_user(source),
                }
                if mitre_override:
                    payload["mitre_override"] = mitre_override

                dbg(f"  [Wazuh] Feeding alert {rule.get('id')} to pipeline")
                alert_callback(payload)

        except requests.exceptions.RequestException as e:
            dbg(f"  [Wazuh] connection error: {e} — retrying in {POLL_SECONDS}s")
        except Exception as e:
            dbg(f"  [Wazuh] unexpected error: {e}")

        time.sleep(POLL_SECONDS)


# ─────────────────────────────────────────────────────────────
# OPTIONAL: agent inventory from the Manager API (JWT auth). Not part of
# the alert stream — call this separately (e.g. from a Flask route) to
# power an "Endpoint Coverage" panel showing which hosts Wazuh sees.
# ─────────────────────────────────────────────────────────────

_jwt_token = {"value": None, "expires": 0}


def _get_wazuh_jwt() -> str | None:
    if not (MANAGER_HOST and API_USER and API_PASS and REQUESTS_OK):
        return None
    if _jwt_token["value"] and time.time() < _jwt_token["expires"]:
        return _jwt_token["value"]
    try:
        url = f"https://{MANAGER_HOST}:{MANAGER_PORT}/security/user/authenticate"
        basic = base64.b64encode(f"{API_USER}:{API_PASS}".encode()).decode()
        resp = requests.post(url, headers={"Authorization": f"Basic {basic}"},
                              verify=VERIFY_SSL, timeout=10)
        if resp.status_code == 200:
            token = resp.json().get("data", {}).get("token")
            _jwt_token["value"] = token
            _jwt_token["expires"] = time.time() + 800  # Wazuh JWTs default ~900s; refresh a bit early
            return token
    except Exception as e:
        print(f"  [Wazuh] manager auth failed: {e}")
    return None


def get_wazuh_agents() -> dict:
    """Returns {"success": bool, "agents": [...]} — agent inventory/health
    from the Wazuh Manager API. Independent of the alert-polling loop
    above; safe to call on demand from a Flask route."""
    if not MANAGER_HOST:
        return {"success": False, "error": "WAZUH_MANAGER_HOST not configured"}
    token = _get_wazuh_jwt()
    if not token:
        return {"success": False, "error": "could not authenticate to Wazuh manager API"}
    try:
        url = f"https://{MANAGER_HOST}:{MANAGER_PORT}/agents"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                             verify=VERIFY_SSL, timeout=10)
        if resp.status_code == 200:
            items = resp.json().get("data", {}).get("affected_items", [])
            return {"success": True, "agents": items}
        return {"success": False, "error": f"status {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}
