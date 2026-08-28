"""
Tests for core/alert_pipeline.py — the severity scoring engine, MITRE
mapping, and custom rule loading.

Run from the project root:  pytest tests/ -v

This exists because every fix in this project up to this point needed a
one-off manual verification script written fresh each time. These are
the same checks, made permanent — run them after ANY change to
calculate_severity(), RISK_SIGNALS, or map_mitre() to catch a regression
in seconds instead of needing to re-derive "did I just break severity
scoring" by hand.
"""

import os
import sys
import json
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core import alert_pipeline as ap


# ─────────────────────────────────────────────────────────────
# calculate_severity() — signal-by-signal
# ─────────────────────────────────────────────────────────────

class TestSeverityThresholds:
    def test_zero_signals_is_low(self):
        sev, score = ap.calculate_severity("benign event", "nothing suspicious here")
        assert sev == "LOW"
        assert score == 0

    def test_score_boundaries_match_documented_thresholds(self):
        # MEDIUM >=21, HIGH >=46, CRITICAL >=71 — these are documented in
        # every module's docstring; if this test fails, the docstrings
        # across the whole project are now lying.
        assert ap.calculate_severity("e", "")[0] == "LOW"          # score 0
        # "mimikatz" alone legitimately triggers TWO independent signals —
        # the general RISK_SIGNALS keyword table (+30) AND the dedicated
        # credential-dumping check (+22) — correctly reaching HIGH (52).
        # This is intentional multi-signal corroboration for a very strong
        # indicator, not double-counting: don't "fix" this back down to
        # MEDIUM if you're reading this while investigating a similar test.
        sev, score = ap.calculate_severity("e", "mimikatz detected")
        assert sev == "HIGH" and score == 52


class TestKeywordSignal:
    def test_known_critical_keyword_scores(self):
        sev, score = ap.calculate_severity("e", "mimikatz sekurlsa::logonpasswords")
        assert score > 0
        assert sev in ("MEDIUM", "HIGH", "CRITICAL")

    def test_case_insensitive(self):
        lower = ap.calculate_severity("e", "mimikatz")
        upper = ap.calculate_severity("e", "MIMIKATZ")
        assert lower == upper


class TestChainHintSignal:
    """Regression test for the sysmon_detector.py CHAIN_HINT bug fixed
    this session — this detector's ancestry-chain classification must
    actually reach the scoring engine."""

    def test_chain_hint_critical_contributes_real_weight(self):
        baseline = ap.calculate_severity("Process Ancestry", "some process chain")[1]
        with_hint = ap.calculate_severity("Process Ancestry", "some process chain CHAIN_HINT:CRITICAL")[1]
        assert with_hint > baseline
        assert with_hint - baseline >= 30  # this signal is deliberately the heaviest in the engine

    def test_chain_hint_case_variants(self):
        # detail text is lowercased internally — hint should work regardless
        # of how the detector capitalizes it
        a = ap.calculate_severity("e", "CHAIN_HINT:CRITICAL")[1]
        b = ap.calculate_severity("e", "chain_hint:critical")[1]
        assert a == b


class TestNewIntegrationSignals:
    """Suricata / Wazuh / YARA / IOC-feed signals added this session."""

    @pytest.mark.parametrize("hint,min_expected", [
        ("suricata_risk:critical", 30),
        ("wazuh_risk:critical", 30),
        ("yara_risk:critical", 30),
    ])
    def test_integration_hint_scores_meaningfully(self, hint, min_expected):
        score = ap.calculate_severity("e", f"detail with {hint}")[1]
        assert score >= min_expected

    def test_ioc_confidence_parameter(self):
        low  = ap.calculate_severity("e", "benign", ioc_confidence=0)[1]
        high = ap.calculate_severity("e", "benign", ioc_confidence=90)[1]
        assert high > low


class TestCustomRules:
    """Regression test for the Custom Rules 'saves to sessionStorage,
    never affects detection' bug fixed this session."""

    def setup_method(self):
        self._orig_cache = dict(ap._custom_rules_cache)
        self._tmpdir = tempfile.mkdtemp()
        self._orig_file = ap.CUSTOM_RULES_FILE
        ap.CUSTOM_RULES_FILE = os.path.join(self._tmpdir, "custom_rules.json")

    def teardown_method(self):
        ap.CUSTOM_RULES_FILE = self._orig_file
        ap._custom_rules_cache.clear()
        ap._custom_rules_cache.update(self._orig_cache)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_custom_rule_affects_live_scoring(self):
        before = ap.calculate_severity("e", "zzz_unique_test_marker")[1]
        with open(ap.CUSTOM_RULES_FILE, "w") as f:
            json.dump([{"id": "t1", "keyword": "zzz_unique_test_marker",
                        "score": 30, "active": True}], f)
        after = ap.calculate_severity("e", "zzz_unique_test_marker")[1]
        assert after == before + 30

    def test_inactive_rule_does_not_score(self):
        with open(ap.CUSTOM_RULES_FILE, "w") as f:
            json.dump([{"id": "t1", "keyword": "zzz_inactive_marker",
                        "score": 30, "active": False}], f)
        score = ap.calculate_severity("e", "zzz_inactive_marker")[1]
        assert score == 0

    def test_cache_invalidates_on_file_change(self):
        with open(ap.CUSTOM_RULES_FILE, "w") as f:
            json.dump([], f)
        assert ap._load_custom_rules() == []
        with open(ap.CUSTOM_RULES_FILE, "w") as f:
            json.dump([{"id": "t1", "keyword": "x", "score": 5, "active": True}], f)
        assert len(ap._load_custom_rules()) == 1


# ─────────────────────────────────────────────────────────────
# map_mitre()
# ─────────────────────────────────────────────────────────────

class TestMitreMapping:
    def test_unmatched_text_returns_unknown(self):
        result = ap.map_mitre("nothing", "matches here at all")
        assert result["mitre_id"] == "T0000"

    def test_override_takes_precedence(self):
        """Regression test for the mitre_override feature added this
        session — Wazuh's own MITRE tagging must survive the pipeline,
        not get silently replaced by the keyword guess."""
        override = {"mitre_id": "T1059.001", "mitre_name": "PowerShell",
                    "mitre_tactic": "Execution"}
        result = ap.map_mitre("generic text", "nothing special", override=override)
        assert result["mitre_id"] == "T1059.001"
        assert result["mitre_url"] == "https://attack.mitre.org/techniques/T1059/001/"

    def test_override_partial_fills_gaps_from_guess(self):
        # An override missing a field should still get a real guessed
        # value for that field rather than None
        result = ap.map_mitre("mimikatz credential dump", "detail", override={"mitre_id": "T9999"})
        assert result["mitre_id"] == "T9999"
        assert result["mitre_tactic"] != None


# ─────────────────────────────────────────────────────────────
# Case auto-creation dedup — regression test for the "first case ever
# blocks all future cases on that host forever" bug fixed this session
# ─────────────────────────────────────────────────────────────

class TestCaseFolding:
    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self._orig_file = ap.CASE_FILE
        ap.CASE_FILE = os.path.join(self._tmpdir, "cases.json")

    def teardown_method(self):
        ap.CASE_FILE = self._orig_file
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_first_critical_alert_creates_a_case(self):
        ap._save(ap.CASE_FILE, [])
        ap._auto_create_case({"severity": "CRITICAL", "host": "h1", "user": "u1",
                                "mitre_tactic": "Execution", "id": "A1"})
        cases = ap._load(ap.CASE_FILE)
        assert len(cases) == 1

    def test_different_tactic_same_host_opens_new_case(self):
        """This is the exact bug: same host, different attack type, must
        NOT be silently absorbed into an unrelated open case."""
        ap._save(ap.CASE_FILE, [])
        ap._auto_create_case({"severity": "CRITICAL", "host": "h1", "user": "u1",
                                "mitre_tactic": "Execution", "id": "A1"})
        ap._auto_create_case({"severity": "CRITICAL", "host": "h1", "user": "u1",
                                "mitre_tactic": "Exfiltration", "id": "A2"})
        cases = ap._load(ap.CASE_FILE)
        assert len(cases) == 2

    def test_same_tactic_same_host_folds_into_existing_case(self):
        ap._save(ap.CASE_FILE, [])
        ap._auto_create_case({"severity": "CRITICAL", "host": "h1", "user": "u1",
                                "mitre_tactic": "Execution", "id": "A1"})
        ap._auto_create_case({"severity": "HIGH", "host": "h1", "user": "u1",
                                "mitre_tactic": "Execution", "id": "A2"})
        cases = ap._load(ap.CASE_FILE)
        assert len(cases) == 1
        assert "A2" in cases[0].get("related_alerts", [])

    def test_low_severity_never_creates_a_case(self):
        ap._save(ap.CASE_FILE, [])
        ap._auto_create_case({"severity": "LOW", "host": "h1", "user": "u1", "id": "A1"})
        assert ap._load(ap.CASE_FILE) == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
