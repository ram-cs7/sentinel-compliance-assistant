"""
detector.py
-----------
Orchestrates the multi-layer detection pipeline:

    1. Regex pass         -> candidate matches per category (recall-first)
    2. Validator pass      -> checksum / structural confirmation where
                              available (Aadhaar Verhoeff, card Luhn, PAN
                              format, IFSC format) -> confidence score
    3. Entropy pass         -> for generic secrets, filters low-entropy
                              placeholder values ("password=changeme")
    4. NER pass (optional)  -> flags PERSON/ORG/MONEY near confidentiality
                              keywords as "Confidential Business Information"
    5. Dedup + confidence   -> merges overlapping spans, keeps highest
                              confidence match per span

Each detection carries a `confidence` in [0, 1] and a `masked_value`
(via redactor) rather than ever exposing the raw sensitive value further
than necessary in logs/UI previews.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict
import re

from core.patterns import PATTERNS, CONFIDENTIAL_KEYWORDS, PatternSpec
from core import validators
from core import ner_detector
from core.redactor import mask_value


@dataclass
class Detection:
    category: str
    label: str
    value: str
    masked_value: str
    start: int
    end: int
    confidence: float          # 0.0 - 1.0
    validated: bool            # did a checksum/structural validator confirm it?
    severity_weight: float
    context: str = ""          # small text snippet around the match
    source_location: str = ""  # e.g. "page 2" or "row 14, column 'email'"


_VALIDATOR_MAP = {
    "AADHAAR_NUMBER": validators.is_valid_aadhaar,
    "CREDIT_CARD": validators.luhn_is_valid,
    "PAN_NUMBER": validators.is_valid_pan_format,
    "IFSC_CODE": validators.is_valid_ifsc_format,
}


def _context_snippet(text: str, start: int, end: int, radius: int = 30) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ")
    return ("…" if lo > 0 else "") + snippet + ("…" if hi < len(text) else "")


def _regex_pass(text: str) -> list[Detection]:
    detections: list[Detection] = []
    for spec in PATTERNS:
        for m in spec.pattern.finditer(text):
            value = m.group(spec.group)
            if value is None:
                continue
            start, end = m.span(spec.group)

            validator_fn = _VALIDATOR_MAP.get(spec.category)
            validated = False
            confidence = 0.55  # baseline for an unvalidated regex hit

            if spec.category == "GENERIC_SECRET":
                entropy = validators.shannon_entropy(value)
                # Short/low-entropy values are almost always placeholders
                # like "password=1234" or "token=test" in sample configs.
                if len(value) < 8 or entropy < 2.5:
                    confidence = 0.25
                else:
                    confidence = min(0.95, 0.5 + entropy / 8)
                validated = entropy >= 3.0

            elif validator_fn is not None:
                try:
                    validated = bool(validator_fn(value))
                except Exception:
                    validated = False
                confidence = 0.97 if validated else 0.35

            else:
                confidence = 0.8  # e.g. email/phone/AWS key: regex is already tight

            detections.append(
                Detection(
                    category=spec.category,
                    label=spec.label,
                    value=value,
                    masked_value=mask_value(spec.category, value),
                    start=start,
                    end=end,
                    confidence=confidence,
                    validated=validated,
                    severity_weight=spec.severity_weight,
                    context=_context_snippet(text, start, end),
                )
            )
    return detections


def _confidential_business_pass(text: str) -> list[Detection]:
    """Flags spans as 'Confidential Business Information' when a
    confidentiality keyword co-occurs with a person/org/money entity
    detected by spaCy NER, within a small window. Falls back to
    keyword-only detection (lower confidence) if NER isn't available."""
    detections: list[Detection] = []
    lower = text.lower()

    keyword_spans = []
    for kw in CONFIDENTIAL_KEYWORDS:
        for m in re.finditer(r"\b" + re.escape(kw) + r"\b", lower):
            keyword_spans.append((m.start(), m.end(), kw))

    if not keyword_spans:
        return detections

    ner_hits = ner_detector.extract_entities(text)
    window = 200

    if ner_hits:
        for kw_start, kw_end, kw in keyword_spans:
            nearby = [
                h for h in ner_hits
                if abs(h.start - kw_start) < window or abs(h.end - kw_end) < window
            ]
            for h in nearby:
                detections.append(
                    Detection(
                        category="CONFIDENTIAL_BUSINESS_INFO",
                        label="Confidential Business Information",
                        value=h.text,
                        masked_value=mask_value("CONFIDENTIAL_BUSINESS_INFO", h.text),
                        start=h.start,
                        end=h.end,
                        confidence=0.75,
                        validated=True,
                        severity_weight=6,
                        context=_context_snippet(text, kw_start, kw_end),
                    )
                )
    else:
        # Degraded mode: no NER model available, just surface the
        # keyword hit itself with lower confidence.
        for kw_start, kw_end, kw in keyword_spans:
            detections.append(
                Detection(
                    category="CONFIDENTIAL_BUSINESS_INFO",
                    label="Confidential Business Information",
                    value=text[kw_start:kw_end],
                    masked_value="[REDACTED]",
                    start=kw_start,
                    end=kw_end,
                    confidence=0.4,
                    validated=False,
                    severity_weight=6,
                    context=_context_snippet(text, kw_start, kw_end),
                )
            )
    return detections


def _dedupe(detections: list[Detection]) -> list[Detection]:
    """When multiple categories match overlapping spans (e.g. a 12-digit
    number matches both AADHAAR and a loose phone pattern), keep the
    highest-confidence detection for that span."""
    detections.sort(key=lambda d: (d.start, -(d.end - d.start)))
    kept: list[Detection] = []
    occupied: list[tuple[int, int, Detection]] = []

    for d in detections:
        overlap = None
        for i, (s, e, existing) in enumerate(occupied):
            if d.start < e and s < d.end:  # overlapping ranges
                overlap = i
                break
        if overlap is None:
            occupied.append((d.start, d.end, d))
            kept.append(d)
        else:
            s, e, existing = occupied[overlap]
            if d.confidence > existing.confidence:
                kept.remove(existing)
                kept.append(d)
                occupied[overlap] = (d.start, d.end, d)
    kept.sort(key=lambda d: d.start)
    return kept


def detect(text: str, min_confidence: float = 0.3) -> list[Detection]:
    """Run the full detection pipeline over `text` and return a deduped,
    confidence-filtered list of Detections sorted by position."""
    if not text:
        return []
    detections = _regex_pass(text)
    detections.extend(_confidential_business_pass(text))
    detections = _dedupe(detections)
    return [d for d in detections if d.confidence >= min_confidence]


def group_by_category(detections: list[Detection]) -> dict[str, list[Detection]]:
    grouped: dict[str, list[Detection]] = defaultdict(list)
    for d in detections:
        grouped[d.category].append(d)
    return dict(grouped)
