"""
validators.py
--------------
Checksum / structural validators used to turn a raw regex "maybe-match"
into a confidence-scored detection.

Why this file exists (design rationale):
Most take-home PII detectors stop at "does this look like a 12-digit
number -> flag as Aadhaar". That produces a huge false-positive rate
(order IDs, phone extensions, timestamps, invoice numbers all match).
Aadhaar numbers and credit card numbers are *not* arbitrary digit
strings -- they carry a real checksum digit. Validating that checksum
turns "plausible" into "structurally confirmed", which is the single
biggest lever for reducing false positives without an LLM call.

References:
- Verhoeff algorithm: J. Verhoeff, "Error Detecting Decimal Codes" (1969).
  UIDAI's Aadhaar number uses a Verhoeff check digit as its 12th digit.
- Luhn algorithm (ISO/IEC 7812): standard check-digit scheme used by all
  major payment card networks (Visa, Mastercard, Amex, RuPay, etc).
"""

from __future__ import annotations
import re


# ---------------------------------------------------------------------------
# Verhoeff algorithm (used to validate Aadhaar numbers)
# ---------------------------------------------------------------------------

_D_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_P_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_INV_TABLE = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_is_valid(number: str) -> bool:
    """Return True if `number` (a string of digits) satisfies the Verhoeff
    checksum, i.e. the rightmost digit is a valid check digit for the rest."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) != len(number) or not digits:
        return False
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = _D_TABLE[c][_P_TABLE[i % 8][item]]
    return c == 0


def is_valid_aadhaar(number: str) -> bool:
    """Structural + checksum validation for a 12-digit Aadhaar number.
    UIDAI reserves the first digit as non-zero/non-one, so we check that too."""
    digits = re.sub(r"\D", "", number)
    if len(digits) != 12:
        return False
    if digits[0] in ("0", "1"):
        return False
    return verhoeff_is_valid(digits)


# ---------------------------------------------------------------------------
# Luhn algorithm (used to validate credit / debit card numbers)
# ---------------------------------------------------------------------------

def luhn_is_valid(number: str) -> bool:
    digits = re.sub(r"\D", "", number)
    if not (12 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# IIN / BIN prefix ranges -> card network. Used purely for the friendly
# "type" label shown in the UI, not for validation.
_CARD_NETWORKS = [
    ("Visa", re.compile(r"^4")),
    ("Mastercard", re.compile(r"^(5[1-5]|2[2-7])")),
    ("American Express", re.compile(r"^3[47]")),
    ("RuPay", re.compile(r"^(60|65|81|82|508)")),
    ("Discover", re.compile(r"^6011")),
    ("Diners Club", re.compile(r"^3(0[0-5]|[68])")),
]


def card_network(number: str) -> str:
    digits = re.sub(r"\D", "", number)
    for name, pattern in _CARD_NETWORKS:
        if pattern.match(digits):
            return name
    return "Unknown"


# ---------------------------------------------------------------------------
# PAN (Indian Permanent Account Number) structural decode
# ---------------------------------------------------------------------------

_PAN_HOLDER_TYPES = {
    "A": "Association of Persons",
    "B": "Body of Individuals",
    "C": "Company",
    "F": "Firm / LLP",
    "G": "Government",
    "H": "Hindu Undivided Family",
    "J": "Artificial Judicial Person",
    "L": "Local Authority",
    "P": "Individual",
    "T": "Trust",
}


def is_valid_pan_format(pan: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", pan.strip().upper()))


def pan_holder_type(pan: str) -> str:
    pan = pan.strip().upper()
    if not is_valid_pan_format(pan):
        return "Unknown"
    return _PAN_HOLDER_TYPES.get(pan[3], "Unknown")


# ---------------------------------------------------------------------------
# IFSC (Indian bank branch code) structural check
# ---------------------------------------------------------------------------

def is_valid_ifsc_format(code: str) -> bool:
    # 4 letters (bank code) + '0' (reserved) + 6 alphanumeric (branch code)
    return bool(re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", code.strip().upper()))


# ---------------------------------------------------------------------------
# Shannon entropy — used by the secrets/API-key detector to separate
# "SECRET_KEY = 12345" (low entropy, probably a placeholder) from a real
# high-entropy token.
# ---------------------------------------------------------------------------

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
