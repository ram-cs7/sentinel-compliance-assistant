"""
redactor.py
-----------
Format-preserving masking. Rather than collapsing every finding to a
generic "[REDACTED]", we preserve enough shape to be useful for a human
compliance reviewer (e.g. "last 4 digits of a card") while still hiding
the sensitive value -- the same convention banks/e-commerce sites use on
receipts. This also makes the risk report readable without ever printing
raw PII into logs, screenshots, or this tool's own audit trail.
"""

from __future__ import annotations
import re


def _mask_middle(value: str, keep_start: int = 2, keep_end: int = 2, ch: str = "•") -> str:
    if len(value) <= keep_start + keep_end:
        return ch * len(value)
    tail = value[-keep_end:] if keep_end > 0 else ""
    return value[:keep_start] + ch * (len(value) - keep_start - keep_end) + tail


def mask_email(value: str) -> str:
    m = re.match(r"^(.)(.*)(@.*)$", value)
    if not m:
        return "•" * len(value)
    first, middle, domain = m.groups()
    return f"{first}{'•' * max(1, len(middle))}{domain}"


def mask_card(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "•" * len(digits)
    return "•" * (len(digits) - 4) + digits[-4:]


def mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "•" * len(digits)
    return "•" * (len(digits) - 4) + digits[-4:]


def mask_aadhaar(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) < 4:
        return "•" * len(digits)
    return "XXXX XXXX " + digits[-4:]


def mask_pan(value: str) -> str:
    if len(value) < 4:
        return "•" * len(value)
    return value[:2] + "•" * (len(value) - 4) + value[-2:]


def mask_secret(value: str) -> str:
    return "•" * min(len(value), 24) + (" (truncated)" if len(value) > 24 else "")


_MASKERS = {
    "AADHAAR_NUMBER": mask_aadhaar,
    "PAN_NUMBER": mask_pan,
    "EMAIL": mask_email,
    "PHONE_NUMBER": mask_phone,
    "CREDIT_CARD": mask_card,
    "BANK_ACCOUNT": mask_card,
    "IFSC_CODE": lambda v: _mask_middle(v, 4, 0),
    "AWS_ACCESS_KEY": mask_secret,
    "GOOGLE_API_KEY": mask_secret,
    "SLACK_TOKEN": mask_secret,
    "JWT": mask_secret,
    "GENERIC_SECRET": mask_secret,
    "EMPLOYEE_ID": lambda v: _mask_middle(v, 3, 0),
    "CONFIDENTIAL_BUSINESS_INFO": lambda v: "[REDACTED]",
}


def mask_value(category: str, value: str) -> str:
    masker = _MASKERS.get(category)
    if masker is None:
        return _mask_middle(value)
    try:
        return masker(value)
    except Exception:
        return "[REDACTED]"


def redact_document(text: str, detections: list) -> str:
    """Return a copy of `text` with every detected span replaced by its
    masked value. `detections` is a list of core.detector.Detection,
    expected to be non-overlapping and sorted (detector.detect() already
    guarantees this)."""
    if not detections:
        return text
    out = []
    cursor = 0
    for d in sorted(detections, key=lambda d: d.start):
        if d.start < cursor:
            continue  # skip any residual overlap defensively
        out.append(text[cursor:d.start])
        out.append(d.masked_value)
        cursor = d.end
    out.append(text[cursor:])
    return "".join(out)
