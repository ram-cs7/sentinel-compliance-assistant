"""
risk_engine.py
--------------
Turns a flat list of Detections into an explainable risk score.

Design rationale:
A naive approach is "if any high-severity category is present -> High
Risk". That collapses a document with one stray email address and a
document with 40 valid credit card numbers into different buckets only
by luck of which categories happened to match, and it can't be defended
in an interview beyond "I picked thresholds that felt right".

Instead we compute a continuous 0-100 score as a sum, over categories,
of:

    contribution(category) = severity_weight
                              * log2(1 + validated_count)
                              * confidence_avg
                              * density_multiplier

- log2(1 + count) gives diminishing returns per additional match (the
  5th email address shouldn't count as much as the 1st) while still
  letting volume matter.
- confidence_avg pulls the contribution down for a category where most
  matches failed checksum validation (protects against a regex-only
  category, e.g. unvalidated bank accounts, dominating the score).
- density_multiplier boosts the score slightly when sensitive matches
  are dense relative to document length (a 200-word file that's mostly
  PII is riskier than the same PII buried in a 50,000-word report).

The final sum is squashed with a soft cap so a handful of high-severity
categories can't overflow past 100, then mapped to Low/Medium/High with
explicit, visible thresholds -- not a black box.
"""

from __future__ import annotations
from dataclasses import dataclass
import math

from core.detector import Detection


@dataclass
class CategoryContribution:
    category: str
    label: str
    count: int
    validated_count: int
    avg_confidence: float
    severity_weight: float
    contribution: float


@dataclass
class RiskAssessment:
    score: float                 # 0-100
    level: str                   # "Low" | "Medium" | "High"
    breakdown: list[CategoryContribution]
    density_per_1000_words: float
    total_findings: int


LOW_MAX = 30
MEDIUM_MAX = 65


def assess(detections: list[Detection], word_count: int) -> RiskAssessment:
    word_count = max(word_count, 1)

    by_category: dict[str, list[Detection]] = {}
    for d in detections:
        by_category.setdefault(d.category, []).append(d)

    density = (len(detections) / word_count) * 1000
    density_multiplier = 1.0 + min(0.5, density / 40)  # up to +50% for very dense docs

    breakdown: list[CategoryContribution] = []
    raw_total = 0.0

    for category, items in by_category.items():
        validated_count = sum(1 for d in items if d.validated)
        avg_conf = sum(d.confidence for d in items) / len(items)
        weight = items[0].severity_weight
        label = items[0].label

        contribution = weight * math.log2(1 + len(items)) * avg_conf * density_multiplier
        raw_total += contribution

        breakdown.append(
            CategoryContribution(
                category=category,
                label=label,
                count=len(items),
                validated_count=validated_count,
                avg_confidence=round(avg_conf, 2),
                severity_weight=weight,
                contribution=round(contribution, 2),
            )
        )

    # Soft cap: asymptotically approaches 100 rather than hard-clipping,
    # so "extremely bad" documents are still distinguishable from
    # "moderately bad" ones near the top of the range.
    score = 100 * (1 - math.exp(-raw_total / 60))

    if score <= LOW_MAX:
        level = "Low"
    elif score <= MEDIUM_MAX:
        level = "Medium"
    else:
        level = "High"

    breakdown.sort(key=lambda c: c.contribution, reverse=True)

    return RiskAssessment(
        score=round(score, 1),
        level=level,
        breakdown=breakdown,
        density_per_1000_words=round(density, 2),
        total_findings=len(detections),
    )
