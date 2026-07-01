"""
patterns.py
-----------
Central registry of regex patterns per sensitive-data category.

Each entry is a `PatternSpec`. Keeping this data-driven (a list of specs)
rather than hardcoding logic in the detector means adding a new category
is a one-line change -- useful if an interviewer asks "how would you add
GSTIN or passport numbers?".
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Optional
import re


@dataclass
class PatternSpec:
    category: str                       # e.g. "AADHAAR_NUMBER"
    label: str                          # human readable, e.g. "Aadhaar Number"
    pattern: re.Pattern
    severity_weight: float              # used by risk_engine (0-10 scale)
    validator: Optional[Callable[[str], bool]] = None   # optional checksum fn
    group: int = 0                      # regex group holding the actual match


# NOTE: patterns are intentionally permissive at the regex stage; precision
# is recovered downstream via `validator` (checksum) functions where one
# exists. This two-stage "recall-first regex -> precision-boosting
# validator" design is the same pattern used by tools like gitleaks/detect-secrets.

PATTERNS: list[PatternSpec] = [
    PatternSpec(
        category="AADHAAR_NUMBER",
        label="Aadhaar Number",
        pattern=re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        severity_weight=10,
    ),
    PatternSpec(
        category="PAN_NUMBER",
        label="PAN Number",
        pattern=re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        severity_weight=8,
    ),
    PatternSpec(
        category="EMAIL",
        label="Email Address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        severity_weight=3,
    ),
    PatternSpec(
        category="PHONE_NUMBER",
        label="Phone Number",
        pattern=re.compile(
            r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"          # Indian mobile (incl. 5+5 grouping)
            r"|(?<!\d)0\d{1,4}[\s-]\d{3,4}[\s-]?\d{3,4}(?!\d)"             # Indian STD-code landline
            r"|(?<!\d)\+\d{1,3}[\s-]?\d{3,4}[\s-]?\d{3,4}[\s-]?\d{0,4}(?!\d)"  # generic international
        ),
        severity_weight=4,
    ),
    PatternSpec(
        category="CREDIT_CARD",
        label="Credit / Debit Card Number",
        pattern=re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        severity_weight=10,
    ),
    PatternSpec(
        category="BANK_ACCOUNT",
        label="Bank Account Number",
        pattern=re.compile(
            r"\b(?:bank\s+)?(?:a/?c|acc(?:ount)?)\.?\s*(?:no\.?|number)?\s*[:\-]?\s*(\d{9,18})\b",
            re.IGNORECASE,
        ),
        severity_weight=8,
        group=1,
    ),
    PatternSpec(
        category="IFSC_CODE",
        label="Bank IFSC Code",
        pattern=re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        severity_weight=6,
    ),
    PatternSpec(
        category="AWS_ACCESS_KEY",
        label="AWS Access Key",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity_weight=9,
    ),
    PatternSpec(
        category="GOOGLE_API_KEY",
        label="Google API Key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        severity_weight=9,
    ),
    PatternSpec(
        category="SLACK_TOKEN",
        label="Slack Token",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        severity_weight=9,
    ),
    PatternSpec(
        category="JWT",
        label="JWT / Bearer Token",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity_weight=9,
    ),
    PatternSpec(
        category="GENERIC_SECRET",
        label="Generic API Key / Password",
        pattern=re.compile(
            r"(?im)^[ \t]*(api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9/+_\-\.@#$%^&*]{6,})['\"]?"
        ),
        severity_weight=9,
        group=2,
    ),
    PatternSpec(
        category="EMPLOYEE_ID",
        label="Employee ID",
        pattern=re.compile(r"\b(?:EMP|EID|EMPID)[-_ ]?\d{3,8}\b", re.IGNORECASE),
        severity_weight=2,
    ),
]


CONFIDENTIAL_KEYWORDS = [
    "confidential", "strictly confidential", "internal use only",
    "do not distribute", "not for external distribution", "trade secret",
    "proprietary and confidential", "nda", "non-disclosure",
    "restricted circulation", "company confidential", "privileged and confidential",
]
