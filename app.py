"""
app.py
------
Sentinel — Sensitive Data Detection & Compliance Assistant
Streamlit front-end. See README.md for architecture notes.

Local-first by default: detection, risk scoring, redaction, and most
Q&A run entirely on-device (regex + checksum validators + spaCy NER +
TF-IDF retrieval). An LLM is only called when the user explicitly turns
off Privacy Mode and supplies their own API key, and even then only
receives retrieved text chunks — never the raw uploaded file.
"""

from __future__ import annotations
import os
import uuid
import io

import streamlit as st
import pandas as pd

from core.pipeline import build_report, DocumentReport
from core import audit_logger
from qa import rag_engine

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_PATH = os.path.join(APP_DIR, "sample_data", "sample_document.txt")

st.set_page_config(
    page_title="Sentinel — Sensitive Data Detection & Compliance Assistant",
    page_icon="shield",
    layout="wide",
)

RISK_COLORS = {"Low": "#22c55e", "Medium": "#f59e0b", "High": "#ef4444"}


# ---------------------------------------------------------------------------
# Session state setup
# ---------------------------------------------------------------------------

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())[:8]
if "reports" not in st.session_state:
    st.session_state.reports: dict[str, DocumentReport] = {}
if "retrievers" not in st.session_state:
    st.session_state.retrievers = {}
if "chat_history" not in st.session_state:
    st.session_state.chat_history: dict[str, list[tuple[str, str]]] = {}
if "active_doc" not in st.session_state:
    st.session_state.active_doc = None


def get_retriever(filename: str, full_text: str) -> rag_engine.LocalRetriever:
    if filename not in st.session_state.retrievers:
        st.session_state.retrievers[filename] = rag_engine.LocalRetriever(full_text)
    return st.session_state.retrievers[filename]


def make_llm_call(provider: str, api_key: str):
    """Returns a callable(prompt) -> str for the chosen provider. Kept as
    a small isolated function so swapping/adding providers doesn't touch
    the RAG engine at all."""
    import requests

    if provider == "OpenAI":
        def _call(prompt: str) -> str:
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                },
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        return _call

    if provider == "Gemini":
        def _call(prompt: str) -> str:
            resp = requests.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return _call

    raise ValueError("Unknown provider")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### Sentinel")
    st.caption("Sensitive Data Detection & Compliance Assistant")
    st.divider()

    st.markdown("**Privacy Mode**")
    privacy_mode = st.toggle(
        "Keep everything local (recommended)",
        value=True,
        help="When ON, no document content is ever sent to a third-party API — "
             "detection, risk scoring, redaction, and Q&A all run on-device.",
    )

    llm_provider, llm_api_key = None, None
    if not privacy_mode:
        st.info("Privacy Mode is off — free-text questions the local engine can't "
                "already answer will be sent (as retrieved snippets, not the raw file) to your chosen LLM.")
        llm_provider = st.selectbox("LLM provider", ["OpenAI", "Gemini"])
        llm_api_key = st.text_input(f"{llm_provider} API key", type="password")

    st.divider()
    st.caption(f"Session ID: `{st.session_state.session_id}`")
    if st.button("Clear session"):
        for key in ["reports", "retrievers", "chat_history", "active_doc"]:
            st.session_state.pop(key, None)
        st.rerun()

    st.divider()
    st.caption(
        "Note: This is a demo tool, not legal advice. Compliance "
        "framework references are informational only."
    )


# ---------------------------------------------------------------------------
# Header + upload
# ---------------------------------------------------------------------------

st.title("Sentinel")
st.markdown(
    "**Upload a document to detect sensitive data, score compliance risk, "
    "and ask questions about it — without your data ever leaving this machine "
    "unless you explicitly turn that off.**"
)

col_upload, col_sample = st.columns([3, 1])
with col_upload:
    uploaded_files = st.file_uploader(
        "Upload PDF / TXT / CSV (multiple files supported)",
        type=["pdf", "txt", "csv"],
        accept_multiple_files=True,
    )
with col_sample:
    st.write("")
    st.write("")
    use_sample = st.button("Try sample document", use_container_width=True)

if use_sample and SAMPLE_PATH:
    with open(SAMPLE_PATH, "rb") as f:
        sample_bytes = f.read()
    if "sample_document.txt" not in st.session_state.reports:
        with st.spinner("Analyzing sample document..."):
            report = build_report(sample_bytes, "sample_document.txt")
        st.session_state.reports["sample_document.txt"] = report
        audit_logger.log_event(st.session_state.session_id, "sample_document.txt", "UPLOAD",
                                f"{report.parsed.word_count} words, synthetic demo data")
        audit_logger.log_event(st.session_state.session_id, "sample_document.txt", "DETECTION_RUN",
                                f"{len(report.detections)} findings, risk={report.risk.level}")
    st.session_state.active_doc = "sample_document.txt"

if uploaded_files:
    for uf in uploaded_files:
        if uf.name not in st.session_state.reports:
            with st.spinner(f"Analyzing {uf.name}..."):
                try:
                    file_bytes = uf.getvalue()
                    report = build_report(file_bytes, uf.name)
                    st.session_state.reports[uf.name] = report
                    audit_logger.log_event(st.session_state.session_id, uf.name, "UPLOAD",
                                            f"{len(file_bytes)} bytes")
                    audit_logger.log_event(st.session_state.session_id, uf.name, "DETECTION_RUN",
                                            f"{len(report.detections)} findings, risk={report.risk.level}")
                except Exception as e:
                    st.error(f"Failed to process {uf.name}: {e}")
    st.session_state.active_doc = uploaded_files[-1].name


# ---------------------------------------------------------------------------
# Portfolio overview (multi-document support)
# ---------------------------------------------------------------------------

reports = st.session_state.reports

if not reports:
    st.info("Upload a document (or click **Try sample document**) to get started.")
    st.stop()

st.divider()
st.subheader("Portfolio Overview")

portfolio_rows = []
for fname, r in reports.items():
    portfolio_rows.append({
        "Document": fname,
        "Type": r.parsed.file_type.upper(),
        "Risk Level": r.risk.level,
        "Risk Score": r.risk.score,
        "Findings": r.risk.total_findings,
        "Words": r.parsed.word_count,
    })
portfolio_df = pd.DataFrame(portfolio_rows)

st.dataframe(
    portfolio_df,
    use_container_width=True,
    hide_index=True,
    column_config={
        "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%.1f"),
    },
)

doc_names = list(reports.keys())
default_idx = doc_names.index(st.session_state.active_doc) if st.session_state.active_doc in doc_names else 0
active_doc = st.selectbox("Select document:", doc_names, index=default_idx)
st.session_state.active_doc = active_doc
report = reports[active_doc]

st.divider()

# ---------------------------------------------------------------------------
# Risk header for active doc
# ---------------------------------------------------------------------------

risk_color = RISK_COLORS.get(report.risk.level, "#94a3b8")
h1, h2, h3, h4 = st.columns(4)
h1.metric("Risk Level", report.risk.level)
h2.metric("Risk Score", f"{report.risk.score}/100")
h3.metric("Total Findings", report.risk.total_findings)
h4.metric("Density (per 1k words)", report.risk.density_per_1000_words)

st.markdown(
    f"""<div style="background:{risk_color}22;border-left:6px solid {risk_color};
    padding:10px 16px;border-radius:6px;margin-bottom:8px;">
    <b style="color:{risk_color};">{report.risk.level} RISK</b> — {report.risk.total_findings} sensitive
    data instances found across {report.parsed.word_count} words.</div>""",
    unsafe_allow_html=True,
)

if report.parsed.warnings:
    for w in report.parsed.warnings[:5]:  # cap at 5 to avoid UI noise
        st.warning(w)

tab_detect, tab_risk, tab_compliance, tab_chat, tab_redact, tab_audit = st.tabs(
    ["Detections", "Risk Dashboard", "Compliance Report", "Ask Questions",
     "Redacted Export", "Audit Log"]
)

# ---------------------------------------------------------------------------
# Tab: Detections
# ---------------------------------------------------------------------------
with tab_detect:
    if not report.detections:
        st.success("No sensitive data detected above the confidence threshold.")
    else:
        min_conf = st.slider("Minimum confidence", 0.0, 1.0, 0.3, 0.05)
        rows = [{
            "Category": d.label,
            "Masked Value": d.masked_value,
            "Confidence": round(d.confidence, 2),
            "Checksum Validated": "Yes" if d.validated else "—",
            "Location": d.source_location,
        } for d in report.detections if d.confidence >= min_conf]
        det_df = pd.DataFrame(rows)
        st.dataframe(det_df, use_container_width=True, hide_index=True)
        st.caption(
            "**Checksum Validated** means the value passed an independent structural/checksum "
            "algorithm (Verhoeff for Aadhaar, Luhn for cards, format rules for PAN/IFSC) — not "
            "just a regex match. This is the main lever used to cut false positives."
        )

# ---------------------------------------------------------------------------
# Tab: Risk Dashboard
# ---------------------------------------------------------------------------
with tab_risk:
    if not report.risk.breakdown:
        st.success("No contributing risk categories.")
    else:
        chart_df = pd.DataFrame(
            [{"Category": c.label, "Risk Contribution": c.contribution} for c in report.risk.breakdown]
        ).set_index("Category")
        st.bar_chart(chart_df, use_container_width=True)

        st.markdown("**Score breakdown (explainable):**")
        bd_rows = [{
            "Category": c.label,
            "Count": c.count,
            "Validated": c.validated_count,
            "Avg Confidence": c.avg_confidence,
            "Severity Weight": c.severity_weight,
            "Contribution to Score": c.contribution,
        } for c in report.risk.breakdown]
        st.dataframe(pd.DataFrame(bd_rows), use_container_width=True, hide_index=True)

        with st.expander("How is the risk score calculated?"):
            st.markdown(
                "For each category: `severity_weight × log2(1 + count) × avg_confidence × "
                "density_multiplier`, summed across categories, then squashed to 0–100 with a "
                "soft cap so a handful of severe categories can't overflow the scale. "
                f"Thresholds: 0–30 Low, 31–65 Medium, 66–100 High. "
                f"This document's match density is {report.risk.density_per_1000_words} "
                "findings per 1,000 words."
            )

# ---------------------------------------------------------------------------
# Tab: Compliance Report
# ---------------------------------------------------------------------------
with tab_compliance:
    st.markdown(report.compliance_summary)
    if report.compliance_notes:
        st.divider()
        st.markdown("**Frameworks referenced in this report:**")
        all_frameworks = sorted({fw for n in report.compliance_notes for fw in n.frameworks})
        for fw in all_frameworks:
            st.markdown(f"- {fw}")

# ---------------------------------------------------------------------------
# Tab: Ask Questions (QA)
# ---------------------------------------------------------------------------
with tab_chat:
    st.caption(
        "Try: *\"What sensitive data exists in the document?\"* · "
        "*\"How many email addresses are present?\"* · *\"Summarize this document.\"* · "
        "*\"What compliance risks are identified?\"* — these are answered instantly and "
        "locally, grounded in the detection results above (no LLM, no hallucination risk)."
    )

    history = st.session_state.chat_history.setdefault(active_doc, [])
    for role, content in history:
        with st.chat_message(role):
            st.markdown(content)

    if prompt := st.chat_input("Ask a question about this document..."):
        history.append(("user", prompt))
        audit_logger.log_event(st.session_state.session_id, active_doc, "QUERY", prompt)

        tier1_answer = rag_engine.answer_from_detections(prompt, report.detections, report.risk, report.grouped)
        if tier1_answer:
            answer = tier1_answer
            badge = "[local] answered from detection results"
        else:
            retriever = get_retriever(active_doc, report.parsed.full_text)
            if privacy_mode or not llm_api_key:
                answer = rag_engine.answer_extractive(prompt, retriever)
                badge = "[local] answered via retrieval, no LLM"
            else:
                try:
                    llm_call = make_llm_call(llm_provider, llm_api_key)
                    answer = rag_engine.answer_with_llm(prompt, retriever, llm_call)
                    badge = f"[llm] answered via {llm_provider} (retrieved snippets only, not the raw file)"
                except Exception as e:
                    answer = (f"LLM call failed ({e}). Falling back to local retrieval:\n\n"
                               + rag_engine.answer_extractive(prompt, retriever))
                    badge = "[fallback] LLM failed, fell back to local retrieval"

        full_answer = f"{answer}\n\n*{badge}*"
        history.append(("assistant", full_answer))
        st.rerun()

# ---------------------------------------------------------------------------
# Tab: Redacted Export
# ---------------------------------------------------------------------------
with tab_redact:
    st.markdown("Download a copy of this document with every detected finding masked in place "
                "(format-preserving where useful, e.g. last-4-digits for cards).")
    if report.parsed.file_type == "csv":
        st.download_button(
            "Download redacted CSV",
            data=report.redacted_csv_bytes,
            file_name=f"redacted_{active_doc}",
            mime="text/csv",
        )
        preview = report.redacted_csv_bytes.decode("utf-8", errors="replace")
    else:
        st.download_button(
            "Download redacted text",
            data=report.redacted_text.encode("utf-8"),
            file_name=f"redacted_{os.path.splitext(active_doc)[0]}.txt",
            mime="text/plain",
        )
        preview = report.redacted_text
    st.text_area("Preview", preview, height=300)

# ---------------------------------------------------------------------------
# Tab: Audit Log
# ---------------------------------------------------------------------------
with tab_audit:
    st.caption("Every upload, detection run, question, and export in this session — "
               "raw sensitive values are never written to this log, only category names and counts.")
    events = audit_logger.get_events(st.session_state.session_id)
    if events:
        ev_df = pd.DataFrame(events)[["timestamp", "filename", "event_type", "detail"]]
        st.dataframe(ev_df, use_container_width=True, hide_index=True)
    else:
        st.info("No audit events yet.")
