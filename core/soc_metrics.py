"""SOC Metrics & KPI Engine.

Computes operational metrics from existing alert and case data:
MTTA, MTTR, alert volumes, false positive rates, analyst workload,
and detection coverage.
"""
import json
import os
import time
from collections import defaultdict

_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_ALERTS_FILE = os.path.join(_DIR, "alerts.json")
_CASES_FILE = os.path.join(_DIR, "cases.json")
_SLA_FILE = os.path.join(_DIR, "sla_state.json")


def _load(path, default=None):
    if default is None:
        default = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def get_summary(days: int = 7) -> dict:
    """Key KPI summary for the dashboard."""
    cutoff = time.time() - (days * 86400)
    alerts = _load(_ALERTS_FILE)
    cases = _load(_CASES_FILE)
    sla_state = _load(_SLA_FILE, {})
    
    recent_alerts = [a for a in alerts if a.get("ts", 0) > cutoff]
    
    # Alert volume by severity
    by_severity = defaultdict(int)
    by_source = defaultdict(int)
    by_mitre = defaultdict(int)
    for a in recent_alerts:
        by_severity[a.get("severity", "low")] += 1
        by_source[a.get("source", a.get("host", "unknown"))] += 1
        tactic = a.get("mitre_tactic", "unknown")
        if tactic and tactic != "unknown":
            by_mitre[tactic] += 1
    
    # MTTA / MTTR from SLA state
    mtta_values = []
    mttr_values = []
    fp_count = 0
    resolved_count = 0
    
    if isinstance(sla_state, dict):
        for aid, info in sla_state.items():
            if info.get("created_at", 0) < cutoff:
                continue
            if info.get("resolved_at"):
                resolved_count += 1
                created = info["created_at"]
                ack = info.get("acknowledged_at", created)
                resolved = info["resolved_at"]
                mtta_values.append((ack - created) / 60)
                mttr_values.append((resolved - created) / 60)
                if info.get("disposition") == "false_positive":
                    fp_count += 1
    
    avg_mtta = round(sum(mtta_values) / len(mtta_values), 1) if mtta_values else None
    avg_mttr = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None
    fp_rate = round(fp_count / resolved_count * 100, 1) if resolved_count else None
    
    # Open cases count
    open_cases = len([c for c in cases if c.get("status", "open") not in ("closed", "resolved")])
    
    # Top noisy sources (hosts generating most alerts)
    top_noisy = sorted(by_source.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return {
        "period_days": days,
        "total_alerts": len(recent_alerts),
        "alerts_by_severity": dict(by_severity),
        "alerts_per_day": round(len(recent_alerts) / max(days, 1), 1),
        "open_cases": open_cases,
        "total_cases": len(cases),
        "avg_mtta_minutes": avg_mtta,
        "avg_mttr_minutes": avg_mttr,
        "false_positive_rate_pct": fp_rate,
        "resolved_count": resolved_count,
        "top_noisy_sources": [{"source": s, "count": c} for s, c in top_noisy],
        "mitre_tactic_coverage": dict(by_mitre),
    }


def get_trends(days: int = 7, bucket_hours: int = 24) -> dict:
    """Time-series alert volume data for charts."""
    cutoff = time.time() - (days * 86400)
    alerts = _load(_ALERTS_FILE)
    recent = [a for a in alerts if a.get("ts", 0) > cutoff]
    
    bucket_seconds = bucket_hours * 3600
    buckets = defaultdict(lambda: defaultdict(int))
    
    for a in recent:
        ts = a.get("ts", 0)
        bucket_start = int(ts // bucket_seconds) * bucket_seconds
        sev = a.get("severity", "low")
        buckets[bucket_start][sev] += 1
        buckets[bucket_start]["total"] += 1
    
    timeline = []
    for ts in sorted(buckets.keys()):
        entry = {"timestamp": time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))}
        entry.update(dict(buckets[ts]))
        timeline.append(entry)
    
    return {"period_days": days, "bucket_hours": bucket_hours, "timeline": timeline}


def get_analyst_metrics(username: str = None, days: int = 7) -> dict | list:
    """Per-analyst performance metrics."""
    cutoff = time.time() - (days * 86400)
    sla_state = _load(_SLA_FILE, {})
    cases = _load(_CASES_FILE)
    
    analyst_stats = defaultdict(lambda: {
        "cases_assigned": 0, "cases_resolved": 0,
        "alerts_acknowledged": 0, "alerts_resolved": 0,
        "mttr_values": [], "dispositions": defaultdict(int),
    })
    
    # From SLA state
    if isinstance(sla_state, dict):
        for aid, info in sla_state.items():
            if info.get("created_at", 0) < cutoff:
                continue
            ack_by = info.get("acknowledged_by")
            res_by = info.get("resolved_by")
            if ack_by:
                analyst_stats[ack_by]["alerts_acknowledged"] += 1
            if res_by and info.get("resolved_at"):
                analyst_stats[res_by]["alerts_resolved"] += 1
                mttr = (info["resolved_at"] - info["created_at"]) / 60
                analyst_stats[res_by]["mttr_values"].append(mttr)
                disp = info.get("disposition", "resolved")
                analyst_stats[res_by]["dispositions"][disp] += 1
    
    # From cases
    for c in cases:
        assigned = c.get("assigned_to")
        if assigned:
            analyst_stats[assigned]["cases_assigned"] += 1
            if c.get("status") in ("closed", "resolved"):
                analyst_stats[assigned]["cases_resolved"] += 1
    
    # Build output
    result = []
    for analyst, stats in analyst_stats.items():
        mttr_vals = stats["mttr_values"]
        result.append({
            "analyst": analyst,
            "cases_assigned": stats["cases_assigned"],
            "cases_resolved": stats["cases_resolved"],
            "alerts_acknowledged": stats["alerts_acknowledged"],
            "alerts_resolved": stats["alerts_resolved"],
            "avg_mttr_minutes": round(sum(mttr_vals) / len(mttr_vals), 1) if mttr_vals else None,
            "dispositions": dict(stats["dispositions"]),
        })
    
    result.sort(key=lambda x: x["alerts_resolved"], reverse=True)
    
    if username:
        match = [r for r in result if r["analyst"] == username]
        return match[0] if match else {"analyst": username, "cases_assigned": 0, "alerts_resolved": 0}
    return result
