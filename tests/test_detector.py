"""
test_detector.py
-----------------
Unit tests covering the detection pipeline, parsers, compliance summary,
audit logger, risk scoring, redaction, and QA intent matching.

Run with:

    python -m pytest tests/ -v

(or `python tests/test_detector.py` to run without pytest)
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import validators
from core.detector import detect, group_by_category
from core.redactor import mask_value, redact_document
from core.risk_engine import assess
from core.parsers import parse_document
from core.compliance_mapper import build_summary, get_notes
from core import audit_logger
from qa import rag_engine


# ---------------------------------------------------------------------------
# Checksum / structural validators
# ---------------------------------------------------------------------------

def test_verhoeff_valid_aadhaar():
    # Generated to have a correct Verhoeff check digit (see README for how).
    assert validators.is_valid_aadhaar("234689074180") is True


def test_verhoeff_rejects_random_12_digits():
    assert validators.is_valid_aadhaar("123456789999") is False


def test_luhn_valid_test_card():
    assert validators.luhn_is_valid("4111111111111111") is True


def test_luhn_rejects_broken_card():
    assert validators.luhn_is_valid("4111111111111112") is False


def test_pan_format():
    assert validators.is_valid_pan_format("FLPZS5678K") is True
    assert validators.is_valid_pan_format("NOTAPAN123") is False


def test_ifsc_format():
    assert validators.is_valid_ifsc_format("HDFC0001234") is True
    assert validators.is_valid_ifsc_format("INVALID") is False
    assert validators.is_valid_ifsc_format("ABCD1234567") is False  # 5th char must be '0'


def test_shannon_entropy_high_vs_low():
    high = validators.shannon_entropy("aK9$xZ2!mP7qR4wL")
    low = validators.shannon_entropy("aaaaaaaaaa")
    assert high > low
    assert low < 1.0  # near-zero entropy for repeated chars


# ---------------------------------------------------------------------------
# Detection pipeline
# ---------------------------------------------------------------------------

def test_email_detection():
    dets = detect("Contact us at hello@example.com for more info.")
    categories = {d.category for d in dets}
    assert "EMAIL" in categories


def test_false_positive_keyword_boundary():
    # "nda" (an NDA-related keyword) must not match inside "Secondary".
    dets = detect("Secondary contact information is listed below.")
    values = [d.value for d in dets]
    assert not any("Seco" in v for v in values)


def test_generic_secret_entropy_filtering():
    low_entropy = detect("password = 1234")
    high_entropy = detect("api_key: secret_key_aK9xZ2mP7qR4wLbN3cD5eF8gH0jJ1kK")
    # Low-entropy match should still be detected but with low confidence
    low_confs = [d.confidence for d in low_entropy if d.category == "GENERIC_SECRET"]
    high_confs = [d.confidence for d in high_entropy if d.category == "GENERIC_SECRET"]
    if low_confs and high_confs:
        assert max(high_confs) > max(low_confs)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def test_redaction_preserves_card_last_four():
    masked = mask_value("CREDIT_CARD", "4111111111111111")
    assert masked.endswith("1111")
    assert "4111111111111111" not in masked


def test_redact_document_replaces_all_spans():
    text = "Email: a@b.com, phone: 9876543210"
    dets = detect(text)
    redacted = redact_document(text, dets)
    assert "a@b.com" not in redacted
    assert "9876543210" not in redacted


def test_email_masking_preserves_domain():
    masked = mask_value("EMAIL", "user@example.com")
    assert "@example.com" in masked
    assert "user@example.com" not in masked


def test_aadhaar_masking_shows_last_four():
    masked = mask_value("AADHAAR_NUMBER", "2346 8907 4180")
    assert "4180" in masked
    assert "2346" not in masked


def test_pan_masking_keeps_edges():
    masked = mask_value("PAN_NUMBER", "FLPZS5678K")
    assert masked.startswith("FL")
    assert masked.endswith("8K")
    assert "FLPZS5678K" not in masked


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def test_risk_score_increases_with_more_high_severity_findings():
    low_text = "Contact: a@b.com"
    high_text = "Aadhaar: 234689074180. Card: 4111111111111111. Card: 5500005555555559."
    low_dets = detect(low_text)
    high_dets = detect(high_text)
    low_risk = assess(low_dets, word_count=len(low_text.split()))
    high_risk = assess(high_dets, word_count=len(high_text.split()))
    assert high_risk.score > low_risk.score


def test_risk_empty_document():
    risk = assess([], word_count=100)
    assert risk.score == 0.0
    assert risk.level == "Low"
    assert risk.breakdown == []


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def test_parse_txt():
    doc = parse_document(b"Hello world, this is a test.", "test.txt")
    assert doc.file_type == "txt"
    assert doc.word_count == 6
    assert "Hello world" in doc.full_text


def test_parse_csv_structure():
    csv_bytes = b"name,email\nAlice,alice@example.com\nBob,bob@example.com\n"
    doc = parse_document(csv_bytes, "test.csv")
    assert doc.file_type == "csv"
    assert doc.csv_header == ["name", "email"]
    assert len(doc.csv_rows) == 2
    assert len(doc.csv_cells) == 4  # 2 rows x 2 columns


def test_parse_csv_column_mismatch_warning():
    csv_bytes = b"name,email\nAlice,alice@example.com,extra_value\n"
    doc = parse_document(csv_bytes, "test.csv")
    assert len(doc.warnings) >= 1
    assert "col_" in doc.warnings[0] or "columns" in doc.warnings[0].lower()


def test_parse_csv_no_warnings_when_aligned():
    csv_bytes = b"name,email\nAlice,alice@example.com\n"
    doc = parse_document(csv_bytes, "test.csv")
    assert doc.warnings == []


# ---------------------------------------------------------------------------
# Compliance summary
# ---------------------------------------------------------------------------

def test_compliance_summary_has_structure():
    dets = detect("Aadhaar: 234689074180. Email: test@example.com")
    grouped = group_by_category(dets)
    risk = assess(dets, word_count=10)
    notes = get_notes(list(grouped.keys()))
    summary = build_summary(risk.level, risk.breakdown, notes)
    # The enhanced summary should contain structured sections
    assert "Executive Summary" in summary
    assert "Remediation" in summary
    assert "Data Handling" in summary


def test_compliance_summary_empty_document():
    summary = build_summary("Low", [], [])
    assert "No sensitive data" in summary
    assert "low compliance risk" in summary


def test_compliance_summary_severity_grouping():
    dets = detect("Card: 4111111111111111. Email: a@b.com")
    grouped = group_by_category(dets)
    risk = assess(dets, word_count=10)
    notes = get_notes(list(grouped.keys()))
    summary = build_summary(risk.level, risk.breakdown, notes)
    # High-severity (credit card) and low-severity (email) should be grouped
    assert "High-Severity" in summary or "Low-Severity" in summary


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

def test_audit_logger_timestamp_format():
    """Verify timestamps use ISO 8601 format ending with Z."""
    test_session = "__test_session__"
    audit_logger.log_event(test_session, "test.txt", "TEST", "unit test event")
    events = audit_logger.get_events(test_session)
    assert len(events) >= 1
    ts = events[0]["timestamp"]
    assert ts.endswith("Z")
    assert "T" in ts  # ISO 8601 separator
    # Clean up
    audit_logger.clear_events(test_session)


def test_audit_logger_stores_and_retrieves():
    test_session = "__test_session_2__"
    audit_logger.log_event(test_session, "doc.pdf", "UPLOAD", "500 bytes")
    audit_logger.log_event(test_session, "doc.pdf", "DETECTION_RUN", "3 findings")
    events = audit_logger.get_events(test_session)
    assert len(events) >= 2
    event_types = {e["event_type"] for e in events}
    assert "UPLOAD" in event_types
    assert "DETECTION_RUN" in event_types
    # Clean up
    audit_logger.clear_events(test_session)


# ---------------------------------------------------------------------------
# QA engine — Tier 1 intent matching
# ---------------------------------------------------------------------------

def test_qa_count_question():
    dets = detect("Emails: a@b.com, c@d.com, e@f.com")
    grouped = group_by_category(dets)
    risk = assess(dets, word_count=10)
    answer = rag_engine.answer_from_detections(
        "How many email addresses are present?", dets, risk, grouped
    )
    assert answer is not None
    assert "3" in answer


def test_qa_list_sensitive_data():
    dets = detect("Card: 4111111111111111. PAN: FLPZS5678K")
    grouped = group_by_category(dets)
    risk = assess(dets, word_count=10)
    answer = rag_engine.answer_from_detections(
        "What sensitive data exists in the document?", dets, risk, grouped
    )
    assert answer is not None
    assert "Credit" in answer or "Card" in answer
    assert "PAN" in answer or "Pan" in answer


def test_qa_compliance_question():
    dets = detect("Aadhaar: 234689074180")
    grouped = group_by_category(dets)
    risk = assess(dets, word_count=5)
    answer = rag_engine.answer_from_detections(
        "What compliance risks are identified?", dets, risk, grouped
    )
    assert answer is not None
    assert "Risk Level" in answer


def test_qa_returns_none_for_unknown_intent():
    dets = detect("Hello world")
    grouped = group_by_category(dets)
    risk = assess(dets, word_count=2)
    answer = rag_engine.answer_from_detections(
        "What is the weather today?", dets, risk, grouped
    )
    assert answer is None  # should fall through to Tier 2


# ---------------------------------------------------------------------------
# Runner (allows `python tests/test_detector.py` without pytest)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS: {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {t.__name__} -- {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
