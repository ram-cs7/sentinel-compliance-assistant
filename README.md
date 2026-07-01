# Sentinel — Sensitive Data Detection & Compliance Assistant

Built for the Proteccio Data AI Research Innovation Internship assignment.

> Upload a PDF, TXT, or CSV. The app detects sensitive data (Aadhaar, PAN,
> cards, emails, API keys, etc.), gives you an explainable risk score,
> maps findings to real regulatory frameworks, lets you ask questions about
> the document, and exports a redacted copy — all running locally by
> default, no API key needed.

---

## What makes this different from the obvious approach

The straightforward way to build this is: regex everything, pipe the
document into ChatGPT, ask it to summarize. That works, but it has two
problems I wanted to solve properly:

1. **Regex alone produces too many false positives.** Any 12-digit number
   matches an Aadhaar pattern; any 16-digit number matches a card. A
   compliance tool needs to separate "plausible" from "actually valid."
   So I added a checksum/structural validation layer — Verhoeff for
   Aadhaar, Luhn for cards, format rules for PAN/IFSC — on top of the
   regex, and the UI shows both a confidence score and whether each
   finding passed checksum validation.

2. **Sending a confidential document to a third-party LLM to check if
   it's confidential defeats the purpose.** So detection, risk scoring,
   redaction, and most Q&A run 100% locally (regex + validators + spaCy
   NER + TF-IDF retrieval). An LLM is only involved if you explicitly
   opt in and bring your own API key, and even then it only sees
   retrieved text chunks, not the raw file.

---

## Features

| Requirement | How it's implemented |
|---|---|
| Upload PDF / TXT / CSV | `core/parsers.py` — per-page (PDF) and per-cell (CSV) extraction |
| Detect Aadhaar, PAN, email, phone, card, bank details, API keys, employee IDs, confidential business info | `core/patterns.py` + `core/validators.py` + `core/ner_detector.py` |
| Risk classification (Low / Medium / High) | `core/risk_engine.py` — continuous 0-100 score, not a hardcoded lookup |
| Compliance/security summary | `core/compliance_mapper.py` — structured report grounded in detection results |
| Q&A over the document | `qa/rag_engine.py` — deterministic answers for common questions, TF-IDF retrieval for open-ended ones, optional LLM |
| Streamlit interface | `app.py` |
| **Bonus:** data masking/redaction | `core/redactor.py` — format-preserving (e.g. card shows last 4 digits) |
| **Bonus:** RAG implementation | `qa/rag_engine.py` — TF-IDF retrieval, no model download needed |
| **Bonus:** multi-document support | Portfolio overview, upload and compare multiple files |
| **Bonus:** dashboard/UI | Risk metrics, bar chart breakdown, per-category contribution table |
| **Bonus:** Dockerization | `Dockerfile` |
| **Bonus:** audit logging | `core/audit_logger.py` — SQLite, logs actions but never raw PII |

---

## Setup Instructions

```bash
git clone https://github.com/ram-cs7/sentinel-compliance-assistant.git
cd sentinel-compliance-assistant
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Optional — enables the NER-based "Confidential Business Information" detector.
# The app works fine without it (falls back to keyword-only detection).
python -m spacy download en_core_web_sm

streamlit run app.py
```

Open the URL Streamlit prints (usually `http://localhost:8501`).
Click **Try sample document** for a quick demo with synthetic data.

### Running tests

```bash
python -m pytest tests/ -v
# or without pytest:
python tests/test_detector.py
```

The test suite covers validators (Verhoeff, Luhn, PAN, IFSC, entropy),
the detection pipeline, redaction, risk scoring, parsers (including CSV
column-mismatch warnings), the compliance summary generator, audit
logging, and QA intent matching — 28 tests total.

### Docker

```bash
docker build -t sentinel .
docker run -p 8501:8501 sentinel
```

---

## Architecture Overview

```
                        +---------------+
   PDF / TXT / CSV ---> |  parsers.py   |  per-format text extraction
                        +-------+-------+  (page/row structure preserved)
                                |
                        +-------v-------+
                        |  pipeline.py  |  orchestrates per file type
                        +-------+-------+
             +------------------+------------------+
      +------v------+   +------v------+   +--------v-------+
      | patterns.py |   |validators.py|   | ner_detector.py|
      | (regex,     |-->| (Verhoeff,  |   | (spaCy NER,    |
      |  recall-    |   |  Luhn, PAN/ |   |  optional,     |
      |  first)     |   |  IFSC, ent- |   |  graceful      |
      +------+------+   |  ropy)      |   |  fallback)     |
             |          +------+------+   +--------+-------+
             +--------+--------+---------+---------+
                +------v------+
                | detector.py |  merges, dedupes, scores confidence
                +------+------+
        +--------------+---------------+----------------+
 +------v------+ +-----v-------+ +----v--------+  +----v----------+
 |risk_engine  | |compliance_  | |redactor.py  |  | qa/rag_engine |
 |.py          | |mapper.py    | |(format-     |  |.py            |
 |(0-100 score)| |(regulation  | | preserving  |  |(tier 1: deter-|
 |             | | mapping)    | | masking)    |  | ministic;     |
 +-------------+ +-------------+ +-------------+  | tier 2: TF-IDF|
                                                   | + optional LLM)|
                                                   +---------------+
                               |
                        +------v------+
                        |   app.py    |  Streamlit UI, 6 tabs
                        +------+------+
                        +------v------+
                        |audit_logger |  SQLite, append-only
                        +-------------+
```

**Why per-file-type detection?**
CSVs are scanned per cell, not as one flattened string — this avoids
regex spanning two adjacent cells, and gives a precise "row 14,
column `contact_email`" location. PDFs are scanned per page for the
same reason. TXT is scanned over the full text with line-number
attribution. See `core/pipeline.py` for the three code paths.

---

## AI/ML Approach

This is a hybrid, mostly-classical pipeline rather than "send everything
to an LLM." Here's why each layer exists:

- **Regex + pattern matching** for structured identifiers (email, phone,
  card, Aadhaar, API keys). Designed to be recall-first — cast a wide
  net, then filter.
- **Checksum / structural validation** (Verhoeff, Luhn, PAN format,
  IFSC format) converts "plausible match" into "confirmed match." This
  is the main false-positive reduction lever, and it's deterministic
  and explainable — important for a compliance tool where you need to
  justify findings to an auditor.
- **Shannon entropy** on generic `key=value` patterns, to separate a
  real high-entropy API key from a placeholder like `password=changeme`.
  Same technique used by tools like gitleaks and detect-secrets.
- **spaCy NER** (pretrained `en_core_web_sm`) as a complementary
  signal for "Confidential Business Information" — names, orgs, monetary
  amounts near confidentiality keywords. Regex can't help here because
  business confidentiality isn't a fixed format.
- **TF-IDF + cosine similarity** (scikit-learn) for retrieval in Q&A.
  Chosen over sentence-embedding models because it needs no model
  download, works fully offline, and is transparent about why a chunk
  was retrieved.
- **Optional LLM** (OpenAI / Gemini) for open-ended questions the local
  engine can't handle. Opt-in only, and only retrieved chunks are sent,
  never the raw document.

**Risk scoring:** instead of `if aadhaar_found: risk = "High"`, the
score is a continuous function —
`severity_weight * log2(1+count) * avg_confidence * density_multiplier`,
summed per category — so two documents with different amounts of the
same sensitive data get meaningfully different scores. The UI shows
exactly how each category contributed.

---

## Challenges Faced

- **Regex boundary issues.** Early versions flagged "Secondary" as
  confidential because `"nda"` (for NDA) matched as a substring without
  word boundaries. Fixed with boundary-aware regex; caught by the
  `test_false_positive_keyword_boundary` test.
- **Indian phone number formatting is inconsistent.** Mobile numbers
  appear as one 10-digit block, as 5+5 grouping (`98765 43210`), and
  landlines use STD codes with varying grouping (`022-4567-8899`).
  Needed three alternation branches in one pattern.
- **CSV redaction needs real reconstruction.** You can't just do
  string replacement on the flattened text and get back a valid CSV.
  The pipeline preserves the original row/column structure so a redacted
  CSV can be rebuilt with `csv.writer` and still opens cleanly in Excel.
- **Balancing recall-first regex against false positives** without an
  LLM — solved by pushing precision into checksum validators and
  confidence scoring rather than writing ever-more-specific regex.
- **Making the RAG layer work without a model download.** TF-IDF
  retrieval works fully offline at the cost of missing synonym matches,
  which is a reasonable trade-off for a document-scoped retrieval problem.

---

## Future Improvements

- OCR support (`pytesseract` / `pdf2image`) for scanned PDFs.
- A local sentence-embedding model (e.g. `sentence-transformers`) as an
  optional upgrade from TF-IDF for better recall on paraphrased questions.
- Named-entity linking so "Ananya Sharma" and "A. Sharma" are recognized
  as the same entity.
- GSTIN, passport, and voter ID detectors (same validator pattern as
  Aadhaar/PAN, just additional check-digit rules).
- Batch/API mode (FastAPI endpoint) for programmatic integration.
- Multi-tenant deployment with per-user auth and isolated audit logs.

---

## Deploying a live prototype

**Streamlit Community Cloud** (free, fastest):
1. Push this repo to GitHub.
2. Go to [share.streamlit.io](https://share.streamlit.io) → New app.
3. Select your repo, set main file to `app.py`, deploy.
4. You get a URL like `https://<your-app>.streamlit.app`.

**Hugging Face Spaces** (alternative):
1. Create a new Space with SDK: Streamlit.
2. Push this repo's contents to the Space's git remote.
3. Builds automatically and gives you a `hf.space` URL.

---

## Project Structure

```
sentinel-compliance-assistant/
├── app.py                     # Streamlit UI
├── requirements.txt
├── Dockerfile
├── core/
│   ├── parsers.py             # PDF/TXT/CSV text extraction
│   ├── patterns.py            # regex pattern registry
│   ├── validators.py          # Verhoeff, Luhn, PAN/IFSC, entropy
│   ├── ner_detector.py        # spaCy NER wrapper (optional)
│   ├── detector.py            # detection orchestration + confidence
│   ├── risk_engine.py         # explainable 0-100 risk scoring
│   ├── compliance_mapper.py   # regulation mapping + remediation
│   ├── redactor.py            # format-preserving masking
│   ├── audit_logger.py        # SQLite audit trail
│   └── pipeline.py            # per-file-type orchestration
├── qa/
│   └── rag_engine.py          # tier-1 deterministic + tier-2 RAG Q&A
├── sample_data/
│   └── sample_document.txt    # synthetic demo data (no real PII)
└── tests/
    └── test_detector.py       # 28 tests across all modules
```

---

## Disclaimer

Sample data in `sample_data/` is entirely synthetic — Aadhaar/PAN/card
numbers are either invalid or well-known test values. Compliance
framework references are for demo purposes, not legal advice.
