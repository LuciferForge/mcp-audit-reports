"""
PDF Renderer — converts CompiledReport into a professional PDF.

Uses reportlab (pure Python, zero system deps).
Produces a multi-page compliance-grade PDF report.

Usage:
    from core.pdf_renderer import render_pdf
    render_pdf(compiled_report, output_path="/tmp/report.pdf")
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import SimpleDocTemplate

# ---- Brand Colors ----
BLACK = colors.HexColor("#0D0D0D")
DARK_GRAY = colors.HexColor("#1A1A2E")
ACCENT = colors.HexColor("#E94560")     # Red-accent for critical
ORANGE = colors.HexColor("#F5A623")     # Warning orange
GREEN = colors.HexColor("#27AE60")      # Pass green
BLUE = colors.HexColor("#2980B9")       # Info blue
LIGHT_GRAY = colors.HexColor("#F5F5F5")
MID_GRAY = colors.HexColor("#CCCCCC")
WHITE = colors.white

SEVERITY_COLORS = {
    "CRITICAL": ACCENT,
    "HIGH": ORANGE,
    "MEDIUM": colors.HexColor("#F39C12"),
    "LOW": BLUE,
    "INFO": colors.HexColor("#7F8C8D"),
}

GRADE_COLORS = {
    "A": GREEN,
    "B": colors.HexColor("#52BE80"),
    "C": ORANGE,
    "D": colors.HexColor("#E67E22"),
    "F": ACCENT,
    "U": colors.HexColor("#7F8C8D"),
}

RISK_COLORS = {
    "CRITICAL": ACCENT,
    "HIGH": ORANGE,
    "MEDIUM": colors.HexColor("#F39C12"),
    "LOW": GREEN,
}


def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title",
        fontName="Helvetica-Bold",
        fontSize=26,
        textColor=WHITE,
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle",
        fontName="Helvetica",
        fontSize=12,
        textColor=colors.HexColor("#AAAAAA"),
        alignment=TA_LEFT,
        spaceAfter=2,
    )
    styles["section_header"] = ParagraphStyle(
        "section_header",
        fontName="Helvetica-Bold",
        fontSize=14,
        textColor=DARK_GRAY,
        spaceBefore=16,
        spaceAfter=8,
        borderPadding=(0, 0, 4, 0),
    )
    styles["body"] = ParagraphStyle(
        "body",
        fontName="Helvetica",
        fontSize=9,
        textColor=BLACK,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
        leading=14,
    )
    styles["body_small"] = ParagraphStyle(
        "body_small",
        fontName="Helvetica",
        fontSize=8,
        textColor=colors.HexColor("#555555"),
        spaceAfter=4,
        leading=12,
    )
    styles["label"] = ParagraphStyle(
        "label",
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=BLACK,
        spaceAfter=2,
    )
    styles["finding_title"] = ParagraphStyle(
        "finding_title",
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=BLACK,
        spaceAfter=2,
    )
    styles["mono"] = ParagraphStyle(
        "mono",
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#333333"),
        spaceAfter=4,
        leading=12,
    )
    styles["footer"] = ParagraphStyle(
        "footer",
        fontName="Helvetica",
        fontSize=7,
        textColor=colors.HexColor("#888888"),
        alignment=TA_CENTER,
    )
    return styles


def _cover_page(report: Any, styles: dict) -> list:
    """Build cover page elements."""
    story = []

    # Dark header block — simulated with a table
    header_data = [[
        Paragraph(f"MCP SECURITY &amp; COMPLIANCE AUDIT", styles["title"]),
    ]]
    header_table = Table(header_data, colWidths=[170*mm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), DARK_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 20),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 20),
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8*mm))

    # Server name
    story.append(Paragraph(report.server_name, ParagraphStyle(
        "server_title", fontName="Helvetica-Bold", fontSize=20, textColor=DARK_GRAY,
        spaceAfter=4,
    )))
    story.append(Paragraph(report.server_repo or report.server_command, ParagraphStyle(
        "server_url", fontName="Courier", fontSize=9, textColor=colors.HexColor("#555555"),
        spaceAfter=12,
    )))

    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=12))

    # Score badges — big table
    sec_grade_color = GRADE_COLORS.get(report.security_grade, colors.gray)
    trust_grade_color = GRADE_COLORS.get(report.trust_grade, colors.gray)
    risk_color = RISK_COLORS.get(report.overall_risk, colors.gray)

    badge_data = [
        [
            Paragraph("SECURITY HYGIENE", ParagraphStyle("bh", fontName="Helvetica-Bold", fontSize=8, textColor=WHITE, alignment=TA_CENTER)),
            Paragraph("AGENT TRUST", ParagraphStyle("bh", fontName="Helvetica-Bold", fontSize=8, textColor=WHITE, alignment=TA_CENTER)),
            Paragraph("OVERALL RISK", ParagraphStyle("bh", fontName="Helvetica-Bold", fontSize=8, textColor=WHITE, alignment=TA_CENTER)),
        ],
        [
            Paragraph(f"<b>{report.security_score}/100</b><br/>Grade {report.security_grade}", ParagraphStyle("bs", fontName="Helvetica-Bold", fontSize=18, textColor=WHITE, alignment=TA_CENTER, leading=24)),
            Paragraph(f"<b>{report.trust_score}/100</b><br/>Grade {report.trust_grade}", ParagraphStyle("bs", fontName="Helvetica-Bold", fontSize=18, textColor=WHITE, alignment=TA_CENTER, leading=24)),
            Paragraph(f"<b>{report.overall_risk}</b>", ParagraphStyle("bs", fontName="Helvetica-Bold", fontSize=18, textColor=WHITE, alignment=TA_CENTER, leading=24)),
        ],
    ]
    badge_table = Table(badge_data, colWidths=[55*mm, 55*mm, 55*mm])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), sec_grade_color),
        ("BACKGROUND", (1, 0), (1, -1), trust_grade_color),
        ("BACKGROUND", (2, 0), (2, -1), risk_color),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 1, WHITE),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 8*mm))

    # Metadata table
    meta_data = [
        ["Report ID", report.report_id],
        ["Audit Date", report.generated_at[:10]],
        ["Prepared For", report.client_name],
        ["Prepared By", report.auditor_name],
        ["Methodology", "mcp-security-audit v0.2.0 + AgentCred v0.1.0"],
        ["Standards", "EU AI Act (2024/1689) + NIST AI RMF 1.0"],
    ]
    meta_table = Table(meta_data, colWidths=[45*mm, 120*mm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8*mm))

    # Disclaimer
    disclaimer_text = (
        "CONFIDENTIAL — This report is prepared for the exclusive use of the named client. "
        "It reflects the state of the audited system at the time of audit. "
        "Findings may change as the system evolves. "
        "This report does not constitute legal advice."
    )
    story.append(Paragraph(disclaimer_text, styles["body_small"]))
    story.append(PageBreak())
    return story


def _executive_summary_section(report: Any, styles: dict) -> list:
    story = []
    story.append(Paragraph("1. Executive Summary", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))

    for para in report.executive_summary.split("\n\n"):
        if para.strip():
            story.append(Paragraph(para.strip(), styles["body"]))
            story.append(Spacer(1, 3*mm))

    return story


def _score_breakdown_section(report: Any, styles: dict) -> list:
    story = []
    story.append(Paragraph("2. Score Breakdown", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))

    # Security hygiene breakdown
    story.append(Paragraph("2.1 MCP Security Hygiene (mcp-security-audit)", styles["label"]))
    story.append(Spacer(1, 2*mm))

    breakdown = report.security_json.get("hygiene_breakdown", {})
    hygiene_rows = [
        ["Category", "Score", "Max", "Description"],
        ["Documentation", f"{breakdown.get('documentation', 0):.1f}", "25", "Tool/parameter descriptions present and substantive"],
        ["Schema Rigor", f"{breakdown.get('schema_rigor', 0):.1f}", "25", "Input validation, constraints, required fields"],
        ["Injection Safety", f"{breakdown.get('injection_safety', 0):.1f}", "25", "No injection patterns in tool/prompt/resource text"],
        ["Scope & Least Privilege", f"{breakdown.get('scope_signals', 0):.1f}", "15", "Tool count, destructive tool discipline, shell safety"],
        ["Metadata", f"{breakdown.get('metadata', 0):.1f}", "10", "Server name, version, naming consistency"],
        ["TOTAL", str(report.security_score), "100", f"Grade: {report.security_grade}"],
    ]
    col_widths = [55*mm, 20*mm, 20*mm, 75*mm]
    hyg_table = Table(hygiene_rows, colWidths=col_widths)
    hyg_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("BACKGROUND", (0, -1), (-1, -1), LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [WHITE, LIGHT_GRAY]),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ]))
    story.append(hyg_table)
    story.append(Spacer(1, 4*mm))

    # Trust breakdown
    story.append(Paragraph("2.2 Agent Trust Score (AgentCred)", styles["label"]))
    story.append(Spacer(1, 2*mm))

    trust_buckets = report.trust_report.get("buckets", [])
    trust_rows = [["Bucket", "Weight", "Score", "Weighted"]]
    for b in trust_buckets:
        weighted = b["score"] * b["weight"]
        trust_rows.append([
            b["name"],
            f"{b['weight']:.0%}",
            f"{b['score']:.1f}/100",
            f"{weighted:.1f}",
        ])
    trust_rows.append(["COMPOSITE", "100%", "", f"{report.trust_score}/100 — Grade {report.trust_grade}"])

    trust_table = Table(trust_rows, colWidths=[65*mm, 25*mm, 35*mm, 45*mm])
    trust_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("BACKGROUND", (0, -1), (-1, -1), LIGHT_GRAY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [WHITE, LIGHT_GRAY]),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ]))
    story.append(trust_table)
    story.append(Spacer(1, 4*mm))

    # KYA card note
    if not report.has_kya_card:
        kya_note = (
            "No KYA (Know Your Agent) identity card was found for this server. "
            "Under EU AI Act Article 13 (Transparency) and Article 11 (Technical Documentation), "
            "high-risk AI systems must provide sufficient documentation for users to interpret outputs "
            "and exercise appropriate oversight. A KYA card provides machine-readable identity, "
            "ownership declaration, capability scope, and compliance framework declarations. "
            "Its absence reduces the agent trust score and is a documentation gap."
        )
        note_data = [[Paragraph(kya_note, styles["body_small"])]]
        note_table = Table(note_data, colWidths=[170*mm])
        note_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF9E6")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BOX", (0, 0), (-1, -1), 1, ORANGE),
        ]))
        story.append(note_table)

    return story


def _findings_section(report: Any, styles: dict) -> list:
    story = []
    story.append(Paragraph("3. Detailed Findings", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))

    if not report.enriched_findings:
        story.append(Paragraph("No findings identified. The server passed all automated checks.", styles["body"]))
        return story

    # Findings summary table
    from collections import Counter
    sev_counts = Counter(f["severity"] for f in report.enriched_findings)
    summary_rows = [["Severity", "Count"]]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            summary_rows.append([sev, str(sev_counts[sev])])
    summary_rows.append(["TOTAL", str(len(report.enriched_findings))])

    summary_table = Table(summary_rows, colWidths=[40*mm, 20*mm])
    sev_bg = []
    for i, row in enumerate(summary_rows[1:-1], 1):
        sev = row[0]
        sev_bg.append(("BACKGROUND", (0, i), (0, i), SEVERITY_COLORS.get(sev, colors.gray)))
        sev_bg.append(("TEXTCOLOR", (0, i), (0, i), WHITE))

    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ] + sev_bg))
    story.append(summary_table)
    story.append(Spacer(1, 4*mm))

    # Individual findings
    for i, finding in enumerate(report.enriched_findings, 1):
        sev = finding.get("severity", "LOW")
        sev_color = SEVERITY_COLORS.get(sev, colors.gray)
        eu_ref = finding.get("eu_ai_act") or {}

        finding_elements = []

        # Finding header
        header_data = [[
            Paragraph(f"<b>Finding {i}: {finding.get('title', '')}</b>", ParagraphStyle(
                "fh", fontName="Helvetica-Bold", fontSize=9, textColor=WHITE,
            )),
            Paragraph(sev, ParagraphStyle(
                "fs", fontName="Helvetica-Bold", fontSize=9, textColor=WHITE, alignment=TA_RIGHT,
            )),
        ]]
        header_table = Table(header_data, colWidths=[140*mm, 30*mm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (0, -1), 8),
            ("RIGHTPADDING", (-1, 0), (-1, -1), 8),
        ]))
        finding_elements.append(header_table)

        # Finding body
        body_rows = [
            ["Category", finding.get("category", "").title()],
            ["Detail", finding.get("detail", "")],
        ]
        if finding.get("tool_name"):
            body_rows.append(["Tool", finding["tool_name"]])
        if eu_ref:
            body_rows.append(["EU AI Act", f"{eu_ref.get('article', '')} — {eu_ref.get('title', '')}"])
            body_rows.append(["Requirement", eu_ref.get("requirement", "")])
            body_rows.append(["Compliance Implication", eu_ref.get("implication", "")])
        body_rows.append(["NIST AI RMF", finding.get("nist_ref", "")])
        body_rows.append(["Remediation Effort", finding.get("remediation_effort", "")])
        body_rows.append(["Priority", finding.get("remediation_priority", "")])

        body_table = Table(
            [[Paragraph(r[0], styles["label"]), Paragraph(r[1], styles["body_small"])] for r in body_rows],
            colWidths=[45*mm, 125*mm],
        )
        body_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
            ("BOX", (0, 0), (-1, -1), 1, MID_GRAY),
        ]))
        finding_elements.append(body_table)
        finding_elements.append(Spacer(1, 3*mm))

        story.append(KeepTogether(finding_elements))

    return story


def _remediation_section(report: Any, styles: dict) -> list:
    story = []
    story.append(Paragraph("4. Remediation Roadmap", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))

    story.append(Paragraph(
        "Findings are grouped by remediation priority. Address items in order — Critical items "
        "represent the highest regulatory and security risk.",
        styles["body"],
    ))
    story.append(Spacer(1, 3*mm))

    for group in report.remediation_roadmap:
        priority = group["priority"]
        items = group["findings"]
        story.append(Paragraph(f"{priority} ({group['finding_count']} finding(s))", styles["label"]))
        rows = [["#", "Finding", "Category", "Effort"]]
        for j, f in enumerate(items, 1):
            rows.append([
                str(j),
                f.get("title", ""),
                f.get("category", "").title(),
                f.get("remediation_effort", ""),
            ])
        road_table = Table(rows, colWidths=[8*mm, 100*mm, 30*mm, 32*mm])
        road_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
        ]))
        story.append(road_table)
        story.append(Spacer(1, 4*mm))

    # AgentCred recommendations
    recs = report.trust_report.get("recommendations", [])
    if recs:
        story.append(Paragraph("Agent Trust Improvement Recommendations", styles["label"]))
        for rec in recs:
            story.append(Paragraph(f"- {rec}", styles["body_small"]))
        story.append(Spacer(1, 3*mm))

    return story


def _tool_inventory_section(report: Any, styles: dict) -> list:
    story = []
    story.append(Paragraph("5. Tool Inventory", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))

    tools = report.security_json.get("tools", [])
    if not tools:
        story.append(Paragraph("No tools enumerated.", styles["body"]))
        return story

    rows = [["Tool Name", "Risk Category", "Purpose Aligned", "Matched Patterns"]]
    for t in tools:
        aligned = "Yes" if t.get("purpose_aligned") else "No"
        patterns = ", ".join(t.get("matched_patterns", [])[:3]) or "—"
        rows.append([
            t.get("name", ""),
            t.get("category", ""),
            aligned,
            patterns,
        ])

    inv_table = Table(rows, colWidths=[50*mm, 35*mm, 25*mm, 60*mm])
    risk_styles = []
    for i, t in enumerate(tools, 1):
        if t.get("is_high_risk") and not t.get("purpose_aligned"):
            risk_styles.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFE4E4")))

    inv_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("BACKGROUND", (0, 0), (-1, 0), DARK_GRAY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
    ] + risk_styles))
    story.append(inv_table)
    return story


def _methodology_section(report: Any, styles: dict) -> list:
    story = []
    story.append(Paragraph("6. Methodology", styles["section_header"]))
    story.append(HRFlowable(width="100%", thickness=1, color=MID_GRAY, spaceAfter=8))

    story.append(Paragraph("Audit Tools", styles["label"]))
    tools_text = (
        "<b>mcp-security-audit v0.2.0</b> (github.com/LuciferForge/mcp-security-audit): "
        "Connects to the MCP server via the standard stdio protocol, enumerates all tools, resources, "
        "and prompts, classifies each tool by risk category using pattern matching against 40+ patterns, "
        "scans tool/prompt/resource text for 22 injection patterns using ai-injection-guard, "
        "and scores the server on 5 hygiene categories totaling 100 points. "
        "No live tool invocations were performed — audit is static analysis only."
    )
    story.append(Paragraph(tools_text, styles["body"]))

    story.append(Paragraph(
        "<b>AgentCred v0.1.0</b> (github.com/LuciferForge/agentcred): "
        "Scores agent trust across 4 buckets — Identity Completeness (20%), "
        "Security Posture (25%), Reliability (35%), Behavioral Reputation (20%) — "
        "using static signals from KYA cards and security audit results.",
        styles["body"],
    ))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Regulatory Framework", styles["label"]))
    story.append(Paragraph(
        "Findings are mapped to the EU Artificial Intelligence Act (Regulation 2024/1689), "
        "specifically Articles 9 (Risk Management), 11 (Technical Documentation), "
        "13 (Transparency), 15 (Accuracy and Robustness), and 17 (Quality Management System). "
        "NIST AI Risk Management Framework 1.0 function references are also provided (GOVERN, MAP, MEASURE, MANAGE).",
        styles["body"],
    ))

    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Limitations", styles["label"]))
    story.append(Paragraph(
        "This audit assesses static properties observable at audit time. It does not assess: "
        "runtime behavior, authentication/authorization mechanisms, network security, "
        "data handling practices, or third-party dependency security. "
        "Dynamic testing (live tool invocation) was not performed. "
        "A clean audit does not guarantee absence of all security issues.",
        styles["body"],
    ))

    return story


def render_pdf(report: Any, output_path: str) -> str:
    """
    Render a CompiledReport to PDF.

    Returns the output_path on success.
    """
    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
        title=f"MCP Security Audit — {report.server_name}",
        author=report.auditor_name,
        subject=f"Report {report.report_id}",
    )

    story = []
    story.extend(_cover_page(report, styles))
    story.extend(_executive_summary_section(report, styles))
    story.append(Spacer(1, 4*mm))
    story.extend(_score_breakdown_section(report, styles))
    story.append(PageBreak())
    story.extend(_findings_section(report, styles))
    story.append(PageBreak())
    story.extend(_remediation_section(report, styles))
    story.append(PageBreak())
    story.extend(_tool_inventory_section(report, styles))
    story.append(PageBreak())
    story.extend(_methodology_section(report, styles))

    doc.build(story)
    return output_path
