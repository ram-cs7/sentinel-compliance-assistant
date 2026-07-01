"""
pipeline.py
-----------
Glues parsing + detection + risk + compliance + redaction together per
document, and — importantly — handles *location attribution* differently
per format:

  - TXT: detect over the whole text; location = line number.
  - PDF: detect per page (keeps offsets meaningful per-page and lets a
    reviewer jump straight to "page 3"); redaction is rebuilt per page.
  - CSV: detect per *cell* rather than over a flattened blob. This is
    both more accurate (no risk of a regex spanning two adjacent cells)
    and gives a precise "row 214, column 'contact_email'" location,
    which is what a compliance reviewer actually needs to act on a
    finding. Redaction reconstructs a real CSV via csv.writer.

This module is what app.py calls; it returns a single `DocumentReport`
that every UI tab reads from.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import csv
import io

from core.parsers import ParsedDocument, parse_document
from core.detector import Detection, detect, group_by_category
from core.risk_engine import RiskAssessment, assess
from core import compliance_mapper
from core.redactor import redact_document


@dataclass
class DocumentReport:
    parsed: ParsedDocument
    detections: list[Detection]
    grouped: dict[str, list[Detection]]
    risk: RiskAssessment
    compliance_notes: list = field(default_factory=list)
    compliance_summary: str = ""
    redacted_text: str = ""          # for txt/pdf
    redacted_csv_bytes: bytes = b""  # for csv


def _process_txt(parsed: ParsedDocument) -> tuple[list[Detection], str]:
    dets = detect(parsed.full_text)
    for d in dets:
        line_no = parsed.full_text.count("\n", 0, d.start) + 1
        d.source_location = f"line {line_no}"
    redacted = redact_document(parsed.full_text, dets)
    return dets, redacted


def _process_pdf(parsed: ParsedDocument) -> tuple[list[Detection], str]:
    all_dets: list[Detection] = []
    redacted_pages = []
    for page_num, page_text in parsed.pages:
        page_dets = detect(page_text)
        for d in page_dets:
            d.source_location = f"page {page_num}"
        all_dets.extend(page_dets)
        redacted_pages.append(redact_document(page_text, page_dets))
    return all_dets, "\n\n".join(redacted_pages)


def _process_csv(parsed: ParsedDocument) -> tuple[list[Detection], bytes]:
    all_dets: list[Detection] = []
    # map (row_idx, col_idx) -> masked replacement, built while scanning cells
    replacements: dict[tuple[int, int], str] = {}

    for r_idx, row in enumerate(parsed.csv_rows, start=1):
        for c_idx, value in enumerate(row):
            if not value:
                continue
            cell_dets = detect(value)
            col_name = parsed.csv_header[c_idx] if c_idx < len(parsed.csv_header) else f"col_{c_idx}"
            if cell_dets:
                for d in cell_dets:
                    d.source_location = f"row {r_idx}, column '{col_name}'"
                all_dets.extend(cell_dets)
                masked_cell = redact_document(value, cell_dets)
                replacements[(r_idx, c_idx)] = masked_cell

    # Rebuild the CSV with masked cells substituted in.
    out = io.StringIO()
    writer = csv.writer(out)
    if parsed.csv_header:
        writer.writerow(parsed.csv_header)
    for r_idx, row in enumerate(parsed.csv_rows, start=1):
        new_row = [
            replacements.get((r_idx, c_idx), value)
            for c_idx, value in enumerate(row)
        ]
        writer.writerow(new_row)

    return all_dets, out.getvalue().encode("utf-8")


def build_report(file_bytes: bytes, filename: str) -> DocumentReport:
    parsed = parse_document(file_bytes, filename)

    redacted_text = ""
    redacted_csv_bytes = b""

    if parsed.file_type == "txt":
        detections, redacted_text = _process_txt(parsed)
    elif parsed.file_type == "pdf":
        detections, redacted_text = _process_pdf(parsed)
    elif parsed.file_type == "csv":
        detections, redacted_csv_bytes = _process_csv(parsed)
    else:
        detections = []

    grouped = group_by_category(detections)
    risk = assess(detections, parsed.word_count)
    notes = compliance_mapper.get_notes(list(grouped.keys()))
    summary = compliance_mapper.build_summary(risk.level, risk.breakdown, notes)

    return DocumentReport(
        parsed=parsed,
        detections=detections,
        grouped=grouped,
        risk=risk,
        compliance_notes=notes,
        compliance_summary=summary,
        redacted_text=redacted_text,
        redacted_csv_bytes=redacted_csv_bytes,
    )
