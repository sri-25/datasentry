"""
Regression tests for the DataSentry detection pipeline.

Covers:
  - Layer 1 regex: each keyword-gated pattern matches real examples
    and does NOT match adjacent-looking non-PII strings
  - Layer 1 merge behaviour: overlapping matches resolve by
    confidence then span length (keyword-gated patterns win)
  - End-to-end: a small set of realistic inputs return expected
    entity types (without requiring a live Claude connection)

Run with:   pytest tests/

Tests that require a live Claude API key are marked @pytest.mark.live
and skipped by default — run them with `pytest -m live`.
"""
import os
import re
import pytest
from dataclasses import is_dataclass

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.patterns import REGEX_PATTERNS
from src.detector import DataSentryDetector, Entity, DetectionResult

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def detector():
    """In-memory detector — no audit DB file created."""
    return DataSentryDetector(spacy_model="en_core_web_sm", audit_db=":memory:")


# ── Layer 1: regex pattern coverage ───────────────────────────────────────────

REGEX_CASES = [
    # (pattern_name, input_text, should_match)
    ("SSN",              "SSN: 432-56-7890",                          True),
    ("SSN",              "Phone: 432-56-7890",                        False),  # no keyword
    ("EMAIL",            "contact me at alice@example.com please",    True),
    ("PHONE_US",         "Call (415) 555-2847 anytime",               True),
    ("CREDIT_CARD",      "card 4532015112830366",                     True),
    ("MRN",              "MRN: ABC-2024-99182",                       True),
    ("NPI",              "NPI 1234567893",                            True),
    ("DEA_NUMBER",       "DEA AB1234567",                             True),
    ("ICD_CODE",         "E11.9",                                     True),
    ("UK_NHS_NUMBER",    "NHS Number: 943 476 5919",                  True),
    ("UK_NIN",           "NI: AB 12 34 56 C",                         True),
    ("CANADIAN_SIN",     "SIN: 123-456-789",                          True),
    ("INDIAN_AADHAAR",   "Aadhaar 1234 5678 9012",                    True),
    ("INDIAN_PAN",       "PAN ABCDE1234F",                            True),
    ("AUSTRALIAN_TFN",   "TFN: 123 456 782",                          True),
    ("EU_VAT",           "VAT DE123456789",                           True),
    ("ROUTING_NUMBER",   "routing 021000021",                         True),
    ("ROUTING_NUMBER",   "serial 021000021",                          False),  # no keyword
    ("ZIP_CODE",         "zip 94107",                                 True),
    ("ZIP_CODE",         "order 94107",                               False),  # no keyword
    ("DATE_OF_BIRTH",    "DOB: 03/15/1978",                           True),
    ("BANK_ACCOUNT",     "account number 8834291055",                 True),
    ("DRIVERS_LICENSE_US", "Driver's License CA: D8847291",           True),
]


@pytest.mark.parametrize("entity_type,text,should_match", REGEX_CASES)
def test_regex_pattern_matches(entity_type, text, should_match):
    """Each keyword-gated pattern matches its target and rejects bare numbers."""
    pattern_def = next((p for p in REGEX_PATTERNS if p["entity_type"] == entity_type), None)
    assert pattern_def is not None, f"Pattern {entity_type} not defined"

    match = re.search(pattern_def["pattern"], text, re.IGNORECASE)
    if should_match:
        assert match is not None, f"{entity_type} should match {text!r}"
    else:
        assert match is None, f"{entity_type} should NOT match {text!r} (keyword gate failed)"


# ── Layer 1: specific regex shape regression tests ────────────────────────────

def test_phone_us_keeps_leading_paren():
    """Regression: PHONE_US used to strip the leading `(`."""
    pattern = next(p["pattern"] for p in REGEX_PATTERNS if p["entity_type"] == "PHONE_US")
    match = re.search(pattern, "Call (415) 555-2847 now", re.IGNORECASE)
    assert match is not None
    assert match.group().startswith("(")


def test_drivers_license_captures_id_not_just_keyword():
    """Regression: DRIVERS_LICENSE used to match only the keyword + colon."""
    pattern = next(p["pattern"] for p in REGEX_PATTERNS if p["entity_type"] == "DRIVERS_LICENSE_US")
    match = re.search(pattern, "Driver's License CA: D8847291", re.IGNORECASE)
    assert match is not None
    assert "D8847291" in match.group(), f"match should include the actual ID, got: {match.group()!r}"


def test_ssn_requires_keyword_context():
    """SSN pattern must not fire on bare 9-digit sequences (phone numbers etc.)."""
    pattern = next(p["pattern"] for p in REGEX_PATTERNS if p["entity_type"] == "SSN")
    # Bare digits that look like SSN but no keyword
    assert re.search(pattern, "Serial: 432-56-7890", re.IGNORECASE) is None
    # With keyword: should match
    assert re.search(pattern, "SSN: 432-56-7890", re.IGNORECASE) is not None


# ── Merge/overlap behaviour ───────────────────────────────────────────────────

def test_nhs_number_beats_phone_us_on_overlap(detector):
    """
    Regression: "NHS Number: 943 476 5919" used to be classified as PHONE_US
    because PHONE_US was listed first in REGEX_PATTERNS and won the tie.
    The length-tiebreak in _merge_entities should now prefer the longer
    keyword-gated NHS match.
    """
    text = "Patient from UK office. NHS Number: 943 476 5919. Employee."
    # Run layer 1 only (skip Claude to avoid API dep)
    raw_entities = detector._layer1_regex(text)
    merged = detector._merge_entities(raw_entities)
    nhs = [e for e in merged if e.entity_type == "UK_NHS_NUMBER"]
    phones = [e for e in merged if e.entity_type == "PHONE_US"]
    assert len(nhs) == 1, f"expected 1 NHS match in merged, got {len(nhs)}"
    assert len(phones) == 0, f"expected 0 PHONE_US matches after merge, got {len(phones)}"


def test_merge_prefers_higher_confidence(detector):
    """Confidence is primary sort key — higher confidence wins."""
    e1 = Entity(entity_id="a", text="x", entity_type="A", category="PII",
                start=0, end=10, confidence=0.9, detection_layer="regex", rationale="")
    e2 = Entity(entity_id="b", text="x", entity_type="B", category="PII",
                start=2, end=8, confidence=0.95, detection_layer="regex", rationale="")
    merged = detector._merge_entities([e1, e2])
    assert len(merged) == 1
    assert merged[0].entity_type == "B"  # higher confidence wins


def test_merge_length_tiebreak_on_equal_confidence(detector):
    """On confidence tie, longer span wins."""
    short = Entity(entity_id="a", text="x", entity_type="SHORT", category="PII",
                   start=5, end=10, confidence=0.9, detection_layer="regex", rationale="")
    long = Entity(entity_id="b", text="xx", entity_type="LONG", category="PII",
                  start=0, end=20, confidence=0.9, detection_layer="regex", rationale="")
    merged = detector._merge_entities([short, long])
    assert len(merged) == 1
    assert merged[0].entity_type == "LONG"


# ── Data model sanity ─────────────────────────────────────────────────────────

def test_entity_is_dataclass():
    assert is_dataclass(Entity)


def test_detection_result_is_dataclass():
    assert is_dataclass(DetectionResult)


# ── Integration: end-to-end without Claude (regex + spacy only) ───────────────
#
# These don't require ANTHROPIC_API_KEY. They assert that high-confidence
# regex matches flow through the pipeline and land in the final entities.

def test_end_to_end_email_detected(detector):
    result = detector.detect("Contact alice@example.com for details.", source_label="test")
    emails = [e for e in result.entities if e.entity_type == "EMAIL"]
    assert len(emails) == 1
    assert emails[0].text == "alice@example.com"


def test_end_to_end_ssn_and_email_together(detector):
    text = "Employee SSN: 432-56-7890, email hr@corp.com"
    result = detector.detect(text, source_label="test")
    types = {e.entity_type for e in result.entities}
    assert "SSN" in types
    assert "EMAIL" in types


def test_end_to_end_international_ids(detector):
    text = (
        "NHS Number: 943 476 5919. Aadhaar 1234 5678 9012. "
        "PAN ABCDE1234F. SIN: 123-456-789."
    )
    result = detector.detect(text, source_label="test")
    types = {e.entity_type for e in result.entities}
    assert "UK_NHS_NUMBER" in types
    assert "INDIAN_AADHAAR" in types
    assert "INDIAN_PAN" in types
    assert "CANADIAN_SIN" in types
    # Must NOT have been reclassified as PHONE_US
    assert "PHONE_US" not in types


def test_end_to_end_phone_keeps_paren(detector):
    result = detector.detect("Call me at (415) 555-2847 today.", source_label="test")
    phones = [e for e in result.entities if e.entity_type == "PHONE_US"]
    assert len(phones) == 1
    assert phones[0].text.startswith("("), (
        f"phone should include leading '(', got {phones[0].text!r}"
    )


# ── Budget cap behaviour ──────────────────────────────────────────────────────

def test_budget_counter_starts_at_zero(detector):
    # Fresh :memory: DB each module — starting count should be 0
    assert detector.audit.get_api_call_count("claude") == 0


def test_budget_counter_increments(detector):
    # Reset by calling twice and comparing
    before = detector.audit.get_api_call_count("claude")
    detector.audit.increment_api_call("claude")
    after = detector.audit.get_api_call_count("claude")
    assert after == before + 1


def test_budget_exhausted_flag_set_when_over_limit(monkeypatch):
    """When today's Claude count is ≥ budget, pipeline sets the skipped flag."""
    from src import detector as det_mod
    monkeypatch.setattr(det_mod, "CLAUDE_DAILY_BUDGET", 2)

    d = det_mod.DataSentryDetector(spacy_model="en_core_web_sm", audit_db=":memory:")
    # Pre-fill the counter to the cap
    d.audit.increment_api_call("claude")
    d.audit.increment_api_call("claude")
    assert d.audit.get_api_call_count("claude") == 2

    # spaCy-only input so no regex fires — forces the Claude-eligible path
    result = d.detect("John had a meeting last Tuesday.", source_label="budget_test")
    assert result.claude_skipped_budget is True
    assert result.claude_calls_today >= result.claude_budget_daily


def test_budget_not_exhausted_under_limit(monkeypatch):
    from src import detector as det_mod
    monkeypatch.setattr(det_mod, "CLAUDE_DAILY_BUDGET", 100)
    d = det_mod.DataSentryDetector(spacy_model="en_core_web_sm", audit_db=":memory:")
    result = d.detect("contact me at alice@example.com", source_label="budget_test")
    assert result.claude_skipped_budget is False


# ── Live Claude tests (opt-in) ────────────────────────────────────────────────
#
# Run with:  pytest tests/ -m live
# Skipped by default.

@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"),
                    reason="ANTHROPIC_API_KEY not set")
def test_live_claude_rejects_medication_in_research_context(detector):
    """
    Regression: metformin in a marketing/research blog should NOT be flagged.
    Requires a live Claude call.
    """
    text = (
        "Boston Medical Center recently published a study on metformin's effect "
        "on long-term outcomes. The research community has responded positively."
    )
    result = detector.detect(text, source_label="live_test")
    meds = [e for e in result.entities if e.entity_type.startswith("MEDICATION")]
    assert len(meds) == 0, (
        f"metformin should not be flagged in research context; got: "
        f"{[(e.text, e.entity_type, e.rationale) for e in meds]}"
    )


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("ANTHROPIC_API_KEY"),
                    reason="ANTHROPIC_API_KEY not set")
def test_live_claude_keeps_medication_in_patient_record(detector):
    """
    Counterpart to the above: metformin WITH a named patient should stay flagged.
    """
    text = (
        "Patient John Smith, DOB 03/15/1978, was prescribed metformin 500mg BID "
        "after his E11.9 diagnosis."
    )
    result = detector.detect(text, source_label="live_test")
    meds = [e for e in result.entities if e.entity_type.startswith("MEDICATION")]
    assert len(meds) >= 1, "metformin should be flagged when tied to a named patient"
