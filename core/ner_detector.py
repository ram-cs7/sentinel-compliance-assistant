"""
ner_detector.py
----------------
Thin wrapper around spaCy NER, used as a *complementary* detection layer
for things regex is bad at: person names, organizations, and locations
that constitute "Confidential Business Information" when they appear near
confidentiality keywords (see risk_engine / detector for how the two
signals are combined).

Design choice: this layer is fully optional. If spaCy or the English
model isn't installed (e.g. a fresh clone without `python -m spacy
download en_core_web_sm`), the app must still run end-to-end using the
regex + validator layer alone -- it just won't get the NER-based
"Confidential Business Information" boost. This graceful-degradation
matters because pip installs / model downloads are exactly the kind of
thing that breaks silently on someone else's machine during a live demo.
"""

from __future__ import annotations
from typing import NamedTuple

_NLP = None
_LOAD_ATTEMPTED = False
_AVAILABLE = False

RELEVANT_LABELS = {"PERSON", "ORG", "GPE", "MONEY", "LAW"}


class NerHit(NamedTuple):
    text: str
    label: str
    start: int
    end: int


def _ensure_loaded():
    global _NLP, _LOAD_ATTEMPTED, _AVAILABLE
    if _LOAD_ATTEMPTED:
        return
    _LOAD_ATTEMPTED = True
    try:
        import spacy
        try:
            _NLP = spacy.load("en_core_web_sm")
            _AVAILABLE = True
        except OSError:
            # Model not downloaded on this machine.
            _NLP = None
            _AVAILABLE = False
    except ImportError:
        _NLP = None
        _AVAILABLE = False


def is_available() -> bool:
    _ensure_loaded()
    return _AVAILABLE


def extract_entities(text: str, max_chars: int = 200_000) -> list[NerHit]:
    """Run spaCy NER over `text`. Returns [] if spaCy/model unavailable
    so callers never need a try/except."""
    _ensure_loaded()
    if not _AVAILABLE or not text:
        return []
    doc = _NLP(text[:max_chars])
    hits = []
    for ent in doc.ents:
        if ent.label_ in RELEVANT_LABELS:
            hits.append(NerHit(ent.text, ent.label_, ent.start_char, ent.end_char))
    return hits
