"""
SentinelX Anomaly Baseline v1.0
==================================
Real statistical anomaly detection — a rolling z-score per (host, event)
pair, computed against that exact pair's own history. Not a keyword or
hint-forwarding signal like every other detector in this project: this one
runs on every single alert, updates its own baseline, and injects an
ANOMALY_HINT into `detail` when the CURRENT window's rate for that pair is
a statistical outlier vs. its own past.

HOOK POINT
-----------
Called from core/alert_pipeline.py's process_alert(), Stage 3b — BEFORE
Stage 4 (calculate_severity), because it has to inject the hint into
`detail` before that function ever reads it, the same way a detector
embeds CHAIN_HINT/EXE_RISK_SCORE/etc. before calling fire(). Every other
hint is produced by the detector that noticed the raw event; this one has
to be produced centrally, because it needs a shared, evolving baseline
across every detector for the same (host, event) pair — no single
detector has that view on its own.

METHOD
-------
Time is split into fixed-size windows (ANOMALY_WINDOW_MINUTES, default 10).
For a given (host, event) key:
  - `window_count` = occurrences seen so far in the CURRENT (still open)
    window — checked against the baseline on every single call, so a
    burst is caught in real time, not only after the window closes.
  - When the window rolls over, its final count becomes one more data
    point folded into the pair's baseline mean/variance (Welford's
    online algorithm — no need to store full history to keep an
    accurate running mean/stdev).
  - Below ANOMALY_MIN_SAMPLES completed windows, there simply isn't
    enough history to call anything "normal" yet, so nothing is ever
    flagged (cold start is inert by design, not by accident).

`now` is an injectable parameter (epoch seconds) purely so tests can
simulate window rollovers without sleeping in real time — production
callers never need to pass it.

DATA MODEL
-----------
data/behavior_baseline.json — one entry per "{host}|{event}" key:
  {"window_start": <epoch>, "window_count": int,
   "baseline_n": int, "baseline_mean": float, "baseline_m2": float}
"""

import os
import json
import time
import threading

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR      = os.path.join(BASE_DIR, "data")
BASELINE_FILE = os.path.join(DATA_DIR, "behavior_baseline.json")

_file_lock = threading.Lock()

WINDOW_SECONDS       = float(os.environ.get("ANOMALY_WINDOW_MINUTES", "10")) * 60
MIN_BASELINE_SAMPLES = int(os.environ.get("ANOMALY_MIN_SAMPLES", "5"))
Z_HIGH               = float(os.environ.get("ANOMALY_Z_HIGH", "4"))
Z_MEDIUM             = float(os.environ.get("ANOMALY_Z_MEDIUM", "2.5"))


def _load_state() -> dict:
    if not os.path.exists(BASELINE_FILE):
        return {}
    with _file_lock:
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}


def _save_state(state: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with _file_lock:
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)


def _welford_update(n: int, mean: float, m2: float, new_value: float):
    """One step of Welford's online mean/variance algorithm — lets us
    keep an accurate running mean + variance per key without storing
    every historical window count."""
    n += 1
    delta = new_value - mean
    mean += delta / n
    delta2 = new_value - mean
    m2 += delta * delta2
    return n, mean, m2


def _stdev(n: int, m2: float) -> float:
    if n < 2:
        return 0.0
    variance = m2 / (n - 1)
    return variance ** 0.5


def reset_all():
    """Wipe the baseline entirely. Not called anywhere in the app itself —
    exists for tests, and for an analyst who wants to deliberately
    re-baseline after a known-good change in normal traffic patterns."""
    _save_state({})


def get_summary() -> list:
    """All tracked (host, event) pairs with their current stats — read
    -only, records nothing. Backs /api/anomaly/summary."""
    state = _load_state()
    out = []
    for key, entry in state.items():
        host, _, event = key.partition("|")
        n  = entry.get("baseline_n", 0)
        sd = _stdev(n, entry.get("baseline_m2", 0.0))
        out.append({
            "host":                 host,
            "event":                event,
            "current_window_count": entry.get("window_count", 0),
            "baseline_mean":        round(entry.get("baseline_mean", 0.0), 2),
            "baseline_stdev":       round(sd, 2),
            "baseline_samples":     n,
            "has_enough_baseline":  n >= MIN_BASELINE_SAMPLES,
        })
    out.sort(key=lambda r: (r["host"], r["event"]))
    return out


def record_and_check(host: str, event: str, now: float | None = None) -> str | None:
    """Record one occurrence of (host, event) and return an anomaly hint
    — "HIGH", "MEDIUM", or None — for the CURRENT window's count vs. this
    pair's own baseline.

    `now` (epoch seconds) is injectable for tests; production callers
    should never pass it.
    """
    now = time.time() if now is None else now
    key = f"{host}|{event}"

    state = _load_state()
    entry = state.get(key) or {
        "window_start": now, "window_count": 0,
        "baseline_n": 0, "baseline_mean": 0.0, "baseline_m2": 0.0,
    }

    if now - entry["window_start"] >= WINDOW_SECONDS:
        # Window closed — fold its final count into the baseline before
        # starting a fresh window. A window that just opened this same
        # call (window_count == 0, i.e. we're about to start it, not
        # close a lived-in one) never reaches here since the elapsed
        # check above only trips once WINDOW_SECONDS has actually passed.
        closed_count = entry["window_count"]
        n, mean, m2 = _welford_update(
            entry["baseline_n"], entry["baseline_mean"], entry["baseline_m2"], closed_count
        )
        entry["baseline_n"], entry["baseline_mean"], entry["baseline_m2"] = n, mean, m2
        entry["window_start"] = now
        entry["window_count"] = 0

    entry["window_count"] += 1

    hint = None
    if entry["baseline_n"] >= MIN_BASELINE_SAMPLES:
        sd = _stdev(entry["baseline_n"], entry["baseline_m2"])
        if sd > 0:
            z = (entry["window_count"] - entry["baseline_mean"]) / sd
            if z >= Z_HIGH:
                hint = "HIGH"
            elif z >= Z_MEDIUM:
                hint = "MEDIUM"

    state[key] = entry
    _save_state(state)
    return hint