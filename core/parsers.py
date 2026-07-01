"""
parsers.py
----------
Extracts raw text from the supported upload formats (PDF, TXT, CSV).

Each parser returns a `ParsedDocument`: the flattened text used for
detection/QA, plus lightweight per-row/per-page structure so the UI can
show *where* something was found (page number for PDFs, row/column for
CSVs) -- because "we found an email" is a lot less actionable for a
compliance reviewer than "row 214, column 'contact_email'".
"""

from __future__ import annotations
from dataclasses import dataclass, field
import io
import csv


@dataclass
class ParsedDocument:
    filename: str
    file_type: str                 # "pdf" | "txt" | "csv"
    full_text: str
    page_count: int = 1
    # For CSV: list of (row_index, column_name, cell_value)
    csv_cells: list[tuple[int, str, str]] = field(default_factory=list)
    # For CSV: raw structure, kept so a redacted CSV can be reconstructed
    csv_header: list[str] = field(default_factory=list)
    csv_rows: list[list[str]] = field(default_factory=list)
    # For PDF: list of (page_number, page_text)
    pages: list[tuple[int, str]] = field(default_factory=list)
    word_count: int = 0
    # Parser-level warnings (e.g. CSV rows with more columns than the header)
    warnings: list[str] = field(default_factory=list)



def parse_txt(file_bytes: bytes, filename: str) -> ParsedDocument:
    text = file_bytes.decode("utf-8", errors="replace")
    return ParsedDocument(
        filename=filename,
        file_type="txt",
        full_text=text,
        page_count=1,
        word_count=len(text.split()),
    )


def parse_csv(file_bytes: bytes, filename: str) -> ParsedDocument:
    text = file_bytes.decode("utf-8", errors="replace")
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    cells: list[tuple[int, str, str]] = []
    flattened_lines = []
    warnings: list[str] = []

    header: list[str] = []
    data_rows: list[list[str]] = []

    if rows:
        header = rows[0]
        for r_idx, row in enumerate(rows[1:], start=1):
            if len(row) > len(header):
                warnings.append(
                    f"Row {r_idx} has {len(row)} columns but the header only "
                    f"defines {len(header)} — extra columns labelled col_N."
                )
            line_parts = []
            for c_idx, value in enumerate(row):
                col_name = header[c_idx] if c_idx < len(header) else f"col_{c_idx}"
                cells.append((r_idx, col_name, value))
                line_parts.append(value)
            flattened_lines.append(" | ".join(line_parts))
            data_rows.append(row)
    full_text = "\n".join(flattened_lines)

    return ParsedDocument(
        filename=filename,
        file_type="csv",
        full_text=full_text,
        page_count=1,
        csv_cells=cells,
        csv_header=header,
        csv_rows=data_rows,
        word_count=len(full_text.split()),
        warnings=warnings,
    )


def parse_pdf(file_bytes: bytes, filename: str) -> ParsedDocument:
    try:
        import pypdf
    except ImportError as e:
        raise RuntimeError(
            "pypdf is required to parse PDF files. Install with: pip install pypdf"
        ) from e

    reader = pypdf.PdfReader(io.BytesIO(file_bytes))
    pages: list[tuple[int, str]] = []
    for i, page in enumerate(reader.pages, start=1):
        try:
            page_text = page.extract_text() or ""
        except Exception:
            page_text = ""
        pages.append((i, page_text))

    full_text = "\n".join(p[1] for p in pages)
    return ParsedDocument(
        filename=filename,
        file_type="pdf",
        full_text=full_text,
        page_count=len(pages),
        pages=pages,
        word_count=len(full_text.split()),
    )


def parse_document(file_bytes: bytes, filename: str) -> ParsedDocument:
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext == "pdf":
        return parse_pdf(file_bytes, filename)
    if ext == "csv":
        return parse_csv(file_bytes, filename)
    if ext == "txt":
        return parse_txt(file_bytes, filename)
    raise ValueError(f"Unsupported file type: .{ext}. Supported: pdf, txt, csv")
