"""
compliance_mapper.py
---------------------
Maps detected sensitive-data categories to the regulatory frameworks
they actually implicate, plus concrete remediation steps. This is what
turns a list of regex matches into something that reads like an actual
compliance report rather than a debug log.

Coverage is intentionally India-first (Aadhaar/PAN/IFSC are India-specific
identifiers) with GDPR and PCI-DSS references layered on top since most
real documents mix personal data, payment data, and internal secrets.

Legal note: this is a portfolio/demo project, not legal advice. Framework
references are accurate as of early 2026 but organisations should confirm
current obligations with counsel -- this is stated in the app UI as well.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ComplianceNote:
    category: str
    frameworks: list[str]
    risk_note: str
    remediation: str


_COMPLIANCE_TABLE: dict[str, ComplianceNote] = {
    "AADHAAR_NUMBER": ComplianceNote(
        category="AADHAAR_NUMBER",
        frameworks=[
            "India DPDP Act, 2023 (personal/sensitive identifier)",
            "Aadhaar Act, 2016 — Section 29 restricts sharing/publishing of Aadhaar numbers",
        ],
        risk_note="Aadhaar numbers are a high-value national identifier; exposure enables "
                   "identity fraud and is subject to specific statutory restrictions on display and sharing.",
        remediation="Mask to last 4 digits in any stored or displayed copy; restrict storage to "
                     "systems with encryption at rest and access logging; avoid collecting Aadhaar "
                     "unless legally required (prefer a non-Aadhaar identifier where possible).",
    ),
    "PAN_NUMBER": ComplianceNote(
        category="PAN_NUMBER",
        frameworks=["India DPDP Act, 2023", "Income Tax Act, 1961 (PAN issuance/use provisions)"],
        risk_note="PAN is a persistent financial identifier tied to tax records; combined with "
                   "a name it materially raises identity-theft and financial-fraud risk.",
        remediation="Mask all but the first 2 and last 2 characters in logs/UI; limit access to "
                     "finance/HR roles; apply retention limits consistent with tax record-keeping rules.",
    ),
    "EMAIL": ComplianceNote(
        category="EMAIL",
        frameworks=["India DPDP Act, 2023", "GDPR Art. 4(1) (personal data)"],
        risk_note="Email addresses are personal data and, at volume, indicate a contact/customer "
                   "database that likely requires a documented lawful basis for processing.",
        remediation="Confirm a consent notice or legitimate-use basis exists for the data subject; "
                     "avoid storing plaintext email lists in shared/unencrypted documents.",
    ),
    "PHONE_NUMBER": ComplianceNote(
        category="PHONE_NUMBER",
        frameworks=["India DPDP Act, 2023", "GDPR Art. 4(1) (personal data)", "TRAI DND regulations"],
        risk_note="Phone numbers enable direct contact and, combined with other identifiers, "
                   "support re-identification of otherwise anonymised records.",
        remediation="Mask all but last 4 digits in exports; ensure marketing use complies with "
                     "consent/DND registration requirements.",
    ),
    "CREDIT_CARD": ComplianceNote(
        category="CREDIT_CARD",
        frameworks=["PCI-DSS v4.0 (Requirement 3: protect stored cardholder data)"],
        risk_note="Storing full, unencrypted card numbers outside a PCI-DSS-compliant environment "
                   "is a direct compliance violation and a severe fraud exposure.",
        remediation="Never store full PANs in plaintext documents; tokenize via a PCI-compliant "
                     "payment processor; if storage is unavoidable, encrypt and restrict to a "
                     "PCI-scoped environment with quarterly access review.",
    ),
    "BANK_ACCOUNT": ComplianceNote(
        category="BANK_ACCOUNT",
        frameworks=["India DPDP Act, 2023", "RBI data storage/security guidelines"],
        risk_note="Bank account numbers combined with IFSC/name enable direct financial fraud "
                     "(unauthorized transfers, mandate fraud).",
        remediation="Mask account numbers to last 4 digits outside finance systems; encrypt at rest; "
                     "restrict to payroll/finance roles with audit logging.",
    ),
    "IFSC_CODE": ComplianceNote(
        category="IFSC_CODE",
        frameworks=["RBI guidelines (bank branch identification)"],
        risk_note="Low sensitivity in isolation, but combined with an account number it completes "
                     "the data needed to initiate a transfer.",
        remediation="No special handling alone; treat as sensitive only in combination with an "
                     "account number in the same record.",
    ),
    "AWS_ACCESS_KEY": ComplianceNote(
        category="AWS_ACCESS_KEY",
        frameworks=["OWASP Secrets Management Cheat Sheet", "ISO/IEC 27001 Annex A.9 (access control)"],
        risk_note="A live cloud credential in a document is a direct path to account takeover, "
                     "data exfiltration, or cloud-resource abuse (cryptomining, etc).",
        remediation="Rotate the key immediately if this is a real, live credential; never commit "
                     "credentials to documents or source control; use a secrets manager (AWS "
                     "Secrets Manager, HashiCorp Vault) with short-lived credentials instead.",
    ),
    "GOOGLE_API_KEY": ComplianceNote(
        category="GOOGLE_API_KEY",
        frameworks=["OWASP Secrets Management Cheat Sheet"],
        risk_note="Exposed API keys can be used to consume paid API quota or access linked Google "
                     "Cloud services depending on key scope.",
        remediation="Rotate immediately; restrict key by IP/referrer and API scope in Google Cloud "
                     "Console; move to environment variables / secrets manager.",
    ),
    "SLACK_TOKEN": ComplianceNote(
        category="SLACK_TOKEN",
        frameworks=["OWASP Secrets Management Cheat Sheet"],
        risk_note="A live Slack token can read/post messages or exfiltrate workspace data "
                     "depending on scope.",
        remediation="Revoke/rotate via Slack app management immediately; store in a secrets manager.",
    ),
    "JWT": ComplianceNote(
        category="JWT",
        frameworks=["OWASP Secrets Management Cheat Sheet"],
        risk_note="A captured bearer token can be replayed to impersonate the issuing user/service "
                     "until it expires.",
        remediation="Treat as compromised if found outside a secure channel; shorten token TTL; "
                     "rotate signing keys if exposure is confirmed.",
    ),
    "GENERIC_SECRET": ComplianceNote(
        category="GENERIC_SECRET",
        frameworks=["OWASP Secrets Management Cheat Sheet", "ISO/IEC 27001 Annex A.9"],
        risk_note="Hard-coded passwords/secrets in documents or config bypass centralized secrets "
                     "management and access revocation.",
        remediation="Rotate the credential; move to environment variables or a secrets manager; "
                     "add pre-commit secret scanning to prevent recurrence.",
    ),
    "EMPLOYEE_ID": ComplianceNote(
        category="EMPLOYEE_ID",
        frameworks=["India DPDP Act, 2023 (internal personal data)"],
        risk_note="Low sensitivity alone; becomes higher-risk combined with salary, PAN, or "
                     "performance data in HR documents.",
        remediation="Standard access controls on HR systems are typically sufficient; review "
                     "context for co-located sensitive HR data.",
    ),
    "CONFIDENTIAL_BUSINESS_INFO": ComplianceNote(
        category="CONFIDENTIAL_BUSINESS_INFO",
        frameworks=["Contractual NDA obligations", "Trade secret protection (general)"],
        risk_note="Marked-confidential business content (financials, strategy, named parties) "
                     "carries contractual and competitive risk if it leaves controlled distribution.",
        remediation="Confirm distribution list matches the document's confidentiality marking; "
                     "apply document watermarking/DLP controls for external sharing.",
    ),
}


def get_notes(categories: list[str]) -> list[ComplianceNote]:
    notes = []
    for c in categories:
        note = _COMPLIANCE_TABLE.get(c)
        if note:
            notes.append(note)
    return notes


def build_summary(risk_level: str, breakdown, notes: list[ComplianceNote]) -> str:
    """Produces a structured compliance/security summary report grounded
    entirely in detection results. Deterministic (not an LLM call) by design
    — a compliance tool's summary should never hallucinate findings that
    aren't there. The output is structured to read like a real audit report:
    executive summary → categorised observations → remediation plan."""
    lines: list[str] = []

    # ── Executive Summary ─────────────────────────────────────────────
    total_findings = sum(c.count for c in breakdown) if breakdown else 0
    total_categories = len(breakdown) if breakdown else 0
    validated_total = sum(c.validated_count for c in breakdown) if breakdown else 0

    lines.append("## Compliance and Security Summary Report")
    lines.append("")

    if not breakdown:
        lines.append("### Executive Summary")
        lines.append("")
        lines.append("No sensitive data categories were detected above the confidence "
                      "threshold. This document appears to carry **low compliance risk** "
                      "based on automated scanning. Manual review is still recommended "
                      "for context-dependent sensitivity (e.g. business strategy, "
                      "trade secrets conveyed in natural language).")
        return "\n".join(lines)

    level_descriptions = {
        "Low": ("The document contains a small number of potentially sensitive items, "
                "most of which are low-severity or unvalidated. Standard data-handling "
                "controls are likely sufficient, but the items below should still be "
                "reviewed for appropriate access restrictions."),
        "Medium": ("The document contains a moderate volume of sensitive data spanning "
                   "multiple categories. Several findings have been structurally "
                   "validated (checksums/format rules), indicating they are likely real "
                   "identifiers rather than false positives. Targeted remediation is "
                   "recommended before this document is shared, stored, or processed "
                   "further."),
        "High": ("The document contains a significant volume of high-severity sensitive "
                 "data, including structurally validated identifiers. This level of "
                 "exposure poses material compliance and security risk. **Immediate "
                 "remediation is strongly recommended** — restrict access, apply "
                 "redaction, and review data-handling processes for this document class."),
    }

    lines.append("### Executive Summary")
    lines.append("")
    lines.append(f"**Overall Risk Level: {risk_level}** — "
                 f"{total_findings} sensitive data instance{'s' if total_findings != 1 else ''} "
                 f"detected across {total_categories} "
                 f"categor{'ies' if total_categories != 1 else 'y'}, "
                 f"of which {validated_total} "
                 f"{'were' if validated_total != 1 else 'was'} independently validated "
                 f"via checksum or structural rules.")
    lines.append("")
    lines.append(level_descriptions.get(risk_level, ""))
    lines.append("")

    # ── Compliance Observations ───────────────────────────────────────
    lines.append("---")
    lines.append("### Compliance Observations")
    lines.append("")

    # Group notes by severity bucket for readability
    high_sev = [n for n in notes if n.category in
                {"AADHAAR_NUMBER", "CREDIT_CARD", "AWS_ACCESS_KEY", "GOOGLE_API_KEY",
                 "SLACK_TOKEN", "JWT", "GENERIC_SECRET"}]
    med_sev = [n for n in notes if n.category in
               {"PAN_NUMBER", "BANK_ACCOUNT", "IFSC_CODE", "CONFIDENTIAL_BUSINESS_INFO"}]
    low_sev = [n for n in notes if n.category in {"EMAIL", "PHONE_NUMBER", "EMPLOYEE_ID"}]

    if high_sev:
        lines.append("**[HIGH] High-Severity Findings:**")
        for note in high_sev:
            cat_count = next((c.count for c in breakdown if c.category == note.category), 0)
            lines.append(f"- **{note.category.replace('_', ' ').title()}** "
                         f"({cat_count} instance{'s' if cat_count != 1 else ''}): "
                         f"{note.risk_note}")
            lines.append(f"  - _Applicable frameworks: {', '.join(note.frameworks)}_")
        lines.append("")

    if med_sev:
        lines.append("**[MEDIUM] Medium-Severity Findings:**")
        for note in med_sev:
            cat_count = next((c.count for c in breakdown if c.category == note.category), 0)
            lines.append(f"- **{note.category.replace('_', ' ').title()}** "
                         f"({cat_count} instance{'s' if cat_count != 1 else ''}): "
                         f"{note.risk_note}")
            lines.append(f"  - _Applicable frameworks: {', '.join(note.frameworks)}_")
        lines.append("")

    if low_sev:
        lines.append("**[LOW] Low-Severity Findings:**")
        for note in low_sev:
            cat_count = next((c.count for c in breakdown if c.category == note.category), 0)
            lines.append(f"- **{note.category.replace('_', ' ').title()}** "
                         f"({cat_count} instance{'s' if cat_count != 1 else ''}): "
                         f"{note.risk_note}")
            lines.append(f"  - _Applicable frameworks: {', '.join(note.frameworks)}_")
        lines.append("")

    # ── Security Risk Analysis ────────────────────────────────────────
    lines.append("---")
    lines.append("### Security Risk Analysis")
    lines.append("")
    if any(n.category in {"AWS_ACCESS_KEY", "GOOGLE_API_KEY", "SLACK_TOKEN", "JWT", "GENERIC_SECRET"}
           for n in notes):
        lines.append("**Credential Exposure Detected:** This document contains "
                     "embedded secrets or API credentials. If these are live/production "
                     "values, treat this as an active security incident — rotate "
                     "immediately and audit access logs for the credential's scope.")
        lines.append("")
    if any(n.category in {"AADHAAR_NUMBER", "CREDIT_CARD", "PAN_NUMBER", "BANK_ACCOUNT"}
           for n in notes):
        lines.append("**PII / Financial Data Exposure:** The document contains "
                     "personally identifiable information or financial instrument numbers "
                     "that could enable identity theft or financial fraud if disclosed "
                     "to unauthorized parties.")
        lines.append("")

    # ── Suggested Remediation Steps ───────────────────────────────────
    lines.append("---")
    lines.append("### Suggested Remediation Steps")
    lines.append("")
    lines.append("Prioritized by severity — address high-severity items first:")
    lines.append("")
    priority = 1
    for note in (high_sev + med_sev + low_sev):
        lines.append(f"{priority}. **{note.category.replace('_', ' ').title()}:** "
                     f"{note.remediation}")
        priority += 1

    # ── Data Handling Recommendations ─────────────────────────────────
    lines.append("")
    lines.append("---")
    lines.append("### Data Handling Recommendations")
    lines.append("")
    lines.append("- **Access Control:** Restrict this document to need-to-know "
                 "personnel only. Apply role-based access if stored in a shared system.")
    lines.append("- **Encryption:** Ensure encryption at rest and in transit for "
                 "any system storing or transmitting this document.")
    lines.append("- **Redaction:** Use the **Redacted Export** tab to generate a "
                 "masked copy suitable for wider distribution or archival.")
    lines.append("- **Retention:** Review whether indefinite storage of this data "
                 "is necessary — apply retention limits per applicable regulations.")
    lines.append("- **Audit Trail:** All detection and query activity on this "
                 "document is logged in the **Audit Log** tab for accountability.")

    return "\n".join(lines)
