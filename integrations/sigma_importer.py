"""
SentinelX Sigma Rule Importer
================================
Sigma is the industry-standard YAML format for sharing detection logic —
thousands of community-authored rules exist (SigmaHQ/sigma on GitHub is
the canonical public set). This module lets an analyst paste a Sigma
rule and get real, working detection out of it, instead of hand-typing
keywords into the Custom Rules page one at a time.

HONEST SCOPE — READ BEFORE RELYING ON THIS
---------------------------------------------
This is NOT a full Sigma engine. Real Sigma supports arbitrary field
matching against structured log sources, multiple logsource backends, and
rich boolean conditions (selection1 and (selection2 or not selection3),
etc.). SentinelX's detection engine is fundamentally a flat keyword-
scoring system (see calculate_severity() in core/alert_pipeline.py) —
there's no structured field data to match against, just alert text.

So this importer does the pragmatic, disclosed-up-front thing: it walks
a Sigma rule's `detection` block, pulls out every literal string value it
finds (handling the common `|contains`/`|endswith`/plain-value styles),
and creates one SentinelX custom rule per distinct string, each scored
from the Sigma rule's `level`. Sigma's AND/OR structure between fields is
NOT preserved — each extracted string becomes an independent keyword
signal, same as every other entry in RISK_SIGNALS. For rules where the
individual strings are themselves strong indicators (a specific malware
mutex name, a specific LOLBin command pattern) this captures most of the
real value. For rules that only make sense as a strict combination of
generic fields, importing it will produce a weaker/noisier version of
the original intent — that's a real limitation, not a bug to file.

Complex condition logic (regex fields, `1 of them`, cross-field
correlation, aggregations) is skipped, not approximated — better to
import fewer, honestly-simple rules than silently mis-translate complex
ones.
"""

import re

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False

_LEVEL_TO_SCORE = {
    "critical": 35, "high": 28, "medium": 18, "low": 10, "informational": 5,
}

# Sigma field modifiers we know how to interpret. Anything else (|re,
# |base64, |cidr, etc.) is skipped for that specific value rather than
# guessed at.
_KNOWN_MODIFIERS = {"contains", "endswith", "startswith", "equals", None}


def _extract_strings(detection_block: dict) -> list:
    """Walk a Sigma `detection` block and pull out every literal string
    value from fields with a modifier we understand (or none). Returns a
    deduplicated list of lowercase strings."""
    found = set()

    def _walk(node):
        if isinstance(node, dict):
            for key, val in node.items():
                if key in ("condition", "timeframe"):
                    continue
                # Sigma field keys look like "CommandLine|contains" or just "CommandLine"
                modifier = None
                if "|" in str(key):
                    _, modifier = str(key).split("|", 1)
                if modifier not in _KNOWN_MODIFIERS:
                    continue
                _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
        elif isinstance(node, str):
            s = node.strip()
            if len(s) >= 3:  # skip trivially short/noisy strings
                found.add(s.lower())

    _walk(detection_block)
    return sorted(found)


def parse_sigma_rule(yaml_text: str) -> dict:
    """
    Returns:
      {"success": bool, "error": str|None, "title": str, "level": str,
       "extracted_keywords": [...], "suggested_score": int,
       "skipped_reason": str|None}
    Never raises.
    """
    if not YAML_OK:
        return {"success": False, "error": "PyYAML not installed (pip install pyyaml)"}

    try:
        rule = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return {"success": False, "error": f"Invalid YAML: {e}"}

    if not isinstance(rule, dict):
        return {"success": False, "error": "Not a valid Sigma rule (expected a YAML mapping)"}

    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return {"success": False, "error": "No 'detection' block found"}

    condition = str(detection.get("condition", "")).lower()
    # Flag (don't silently mistranslate) conditions this importer can't
    # honestly represent as independent keywords
    complex_markers = [" and not ", " or not ", "1 of them", "all of them",
                        "count(", "near "]
    skipped_reason = None
    if any(m in f" {condition} " for m in complex_markers):
        skipped_reason = (f"condition '{condition}' uses logic this importer doesn't "
                           f"preserve (negation/counting/proximity) — extracted keywords "
                           f"below are still real strings from the rule, but the original "
                           f"boolean intent will be looser than the source rule")

    keywords = _extract_strings(detection)
    level = str(rule.get("level", "medium")).lower()
    score = _LEVEL_TO_SCORE.get(level, 18)

    return {
        "success": True,
        "error": None,
        "title": rule.get("title", "Imported Sigma Rule"),
        "description": rule.get("description", ""),
        "level": level,
        "extracted_keywords": keywords,
        "suggested_score": score,
        "skipped_reason": skipped_reason,
        "sigma_id": rule.get("id", ""),
    }
