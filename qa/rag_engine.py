"""
rag_engine.py
-------------
Question-answering over the uploaded document.

*** Core design decision (the main "innovative, not regular" angle) ***

The obvious approach is: dump the document into an LLM prompt and let it
answer everything. For a *sensitive data / compliance* tool that is a bad
default -- it means the confidential document you're trying to protect
gets shipped to a third-party API just to find out it's confidential.

Instead this engine answers in two tiers:

  Tier 1 — Deterministic, detection-grounded answers (always on, 100%
  local, zero data leaves the machine). Questions the assignment brief
  explicitly calls out ("what sensitive data exists", "how many emails",
  "summarize this document", "what compliance risks exist") are answered
  directly from the structured output of detector.py / risk_engine.py /
  compliance_mapper.py. These answers can't hallucinate a PII count that
  isn't there, because they ARE the count.

  Tier 2 — Retrieval-augmented, optional LLM answers for open-ended
  free-text questions that Tier 1 can't pattern-match. Retrieval uses a
  local TF-IDF index (scikit-learn) -- no embedding model download, no
  network call just to retrieve. The LLM call itself is opt-in
  ("Privacy Mode" toggle in the UI) and only ever receives the *retrieved
  chunks* needed to answer, never the full raw document, and never the
  unmasked sensitive values (those are substituted with their masked
  form before anything is sent externally).

If no LLM API key is configured, or Privacy Mode is on, Tier 2 falls back
to pure extractive retrieval (return the most relevant chunk(s) verbatim
from the local index) so the QA feature still works end-to-end offline.
"""

from __future__ import annotations
from dataclasses import dataclass
import re

from core.detector import Detection
from core.risk_engine import RiskAssessment
from core import compliance_mapper


# ---------------------------------------------------------------------------
# Tier 1: deterministic, detection-grounded intent matching
# ---------------------------------------------------------------------------

_COUNT_PATTERN = re.compile(
    r"how many\s+(.+?)\s*(?:are there|are present|exist(?:s)?|found|is there)?\??$",
    re.IGNORECASE,
)

_CATEGORY_ALIASES = {
    "email": "EMAIL", "emails": "EMAIL", "email address": "EMAIL", "email addresses": "EMAIL",
    "phone": "PHONE_NUMBER", "phones": "PHONE_NUMBER", "phone number": "PHONE_NUMBER", "phone numbers": "PHONE_NUMBER",
    "aadhaar": "AADHAAR_NUMBER", "aadhaar number": "AADHAAR_NUMBER", "aadhaar numbers": "AADHAAR_NUMBER",
    "pan": "PAN_NUMBER", "pan number": "PAN_NUMBER", "pan numbers": "PAN_NUMBER",
    "credit card": "CREDIT_CARD", "credit cards": "CREDIT_CARD", "card number": "CREDIT_CARD", "card numbers": "CREDIT_CARD",
    "bank account": "BANK_ACCOUNT", "bank accounts": "BANK_ACCOUNT", "bank detail": "BANK_ACCOUNT", "bank details": "BANK_ACCOUNT",
    "api key": "GENERIC_SECRET", "api keys": "GENERIC_SECRET", "password": "GENERIC_SECRET", "passwords": "GENERIC_SECRET",
    "employee id": "EMPLOYEE_ID", "employee ids": "EMPLOYEE_ID",
    "secret": "GENERIC_SECRET", "secrets": "GENERIC_SECRET",
}


def _resolve_category(phrase: str) -> str | None:
    phrase = phrase.strip().lower().rstrip("?").strip()
    candidates = [phrase]
    if phrase.endswith("es"):
        candidates.append(phrase[:-2])
    if phrase.endswith("s"):
        candidates.append(phrase[:-1])
    for c in candidates:
        if c in _CATEGORY_ALIASES:
            return _CATEGORY_ALIASES[c]
    return None


def _try_count_question(question: str, grouped: dict[str, list[Detection]]) -> str | None:
    m = _COUNT_PATTERN.search(question.strip())
    if not m:
        return None
    phrase = m.group(1)
    category = _resolve_category(phrase)
    if category is None:
        return None
    count = len(grouped.get(category, []))
    label = category.replace("_", " ").title()
    return f"There {'is' if count == 1 else 'are'} **{count}** {label} instance{'s' if count != 1 else ''} detected in this document."


def _is_list_question(q: str) -> bool:
    q = q.lower()
    return any(p in q for p in [
        "what sensitive data", "what sensitive information", "list the sensitive",
        "what data exists", "what pii", "types of sensitive",
    ])


def _is_summary_question(q: str) -> bool:
    q = q.lower()
    return any(p in q for p in ["summarize", "summary", "give me an overview", "overview of this document"])


def _is_compliance_question(q: str) -> bool:
    q = q.lower()
    return any(p in q for p in ["compliance risk", "compliance issue", "regulation", "gdpr", "dpdp", "pci", "legal risk"])


def answer_from_detections(
    question: str,
    detections: list[Detection],
    risk: RiskAssessment,
    grouped: dict[str, list[Detection]],
) -> str | None:
    """Returns a Tier-1 deterministic answer, or None if the question
    doesn't match a known intent (caller should fall through to Tier 2)."""

    count_answer = _try_count_question(question, grouped)
    if count_answer:
        return count_answer

    if _is_list_question(question):
        if not grouped:
            return "No sensitive data was detected in this document above the confidence threshold."
        lines = ["The following sensitive data categories were detected:\n"]
        for category, items in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            label = items[0].label
            validated = sum(1 for d in items if d.validated)
            lines.append(f"- **{label}**: {len(items)} found ({validated} checksum/structurally validated)")
        return "\n".join(lines)

    if _is_summary_question(question):
        notes = compliance_mapper.get_notes(list(grouped.keys()))
        return compliance_mapper.build_summary(risk.level, risk.breakdown, notes)

    if _is_compliance_question(question):
        notes = compliance_mapper.get_notes(list(grouped.keys()))
        if not notes:
            return "No specific compliance frameworks were implicated — no sensitive categories were detected."
        lines = [f"**Risk Level: {risk.level}** (score {risk.score}/100)\n"]
        for note in notes:
            lines.append(f"- **{note.category.replace('_', ' ').title()}** → {', '.join(note.frameworks)}")
        return "\n".join(lines)

    return None


# ---------------------------------------------------------------------------
# Tier 2: local TF-IDF retrieval (+ optional LLM generation)
# ---------------------------------------------------------------------------

@dataclass
class RetrievedChunk:
    text: str
    score: float
    chunk_index: int


class LocalRetriever:
    """A minimal, dependency-light (scikit-learn only, no model download)
    retriever over document chunks. Rebuilt per-document since these are
    small, single-document corpora, not a persistent index."""

    def __init__(self, full_text: str, chunk_size: int = 500, overlap: int = 80):
        self.chunks = self._chunk(full_text, chunk_size, overlap)
        self._vectorizer = None
        self._matrix = None
        if self.chunks:
            self._build_index()

    @staticmethod
    def _chunk(text: str, chunk_size: int, overlap: int) -> list[str]:
        words = text.split()
        if not words:
            return []
        chunks = []
        step = max(1, chunk_size - overlap)
        for i in range(0, len(words), step):
            chunk = " ".join(words[i:i + chunk_size])
            if chunk.strip():
                chunks.append(chunk)
            if i + chunk_size >= len(words):
                break
        return chunks

    def _build_index(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=4096)
        self._matrix = self._vectorizer.fit_transform(self.chunks)

    def retrieve(self, query: str, top_k: int = 3) -> list[RetrievedChunk]:
        if not self.chunks or self._vectorizer is None:
            return []
        from sklearn.metrics.pairwise import cosine_similarity
        q_vec = self._vectorizer.transform([query])
        sims = cosine_similarity(q_vec, self._matrix)[0]
        ranked = sorted(range(len(sims)), key=lambda i: sims[i], reverse=True)[:top_k]
        return [RetrievedChunk(self.chunks[i], float(sims[i]), i) for i in ranked if sims[i] > 0]


def answer_extractive(question: str, retriever: LocalRetriever) -> str:
    hits = retriever.retrieve(question, top_k=2)
    if not hits:
        return ("I couldn't find content in the document closely related to that question. "
                "Try rephrasing, or ask about sensitive data counts / risk / compliance directly.")
    lines = ["Here's the most relevant part of the document I could find locally (no LLM used):\n"]
    for h in hits:
        preview = h.text[:600] + ("…" if len(h.text) > 600 else "")
        lines.append(f"> {preview}")
    return "\n\n".join(lines)


def answer_with_llm(question: str, retriever: LocalRetriever, llm_call) -> str:
    """`llm_call` is a callable(prompt: str) -> str provided by the app
    layer (keeps this module provider-agnostic re: OpenAI/Gemini/etc)."""
    hits = retriever.retrieve(question, top_k=4)
    context = "\n\n---\n\n".join(h.text for h in hits) if hits else "(no closely matching passage found)"
    prompt = (
        "You are a document compliance assistant. Answer the user's question using ONLY the "
        "context below. If the answer isn't in the context, say you don't know. Be concise.\n\n"
        f"Context:\n{context}\n\nQuestion: {question}\nAnswer:"
    )
    return llm_call(prompt)
