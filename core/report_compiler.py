"""
Audit Report Compiler — orchestrates mcp-security-audit + agentcred into
a structured data payload that the PDF renderer consumes.

Usage:
    from core.report_compiler import compile_report
    data = compile_report(
        server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
        server_name="MCP Filesystem Server",
        server_repo="https://github.com/modelcontextprotocol/servers",
        client_name="Acme Corp",
        kya_card=None,           # Optional dict — KYA card if available
        github_stars=5200,       # Optional — for reputation bucket
        auditor_name="LuciferForge Security",
        report_id="LF-2026-001",
    )
"""

from __future__ import annotations

import asyncio
import datetime
import json
from dataclasses import dataclass, field, asdict
from typing import Any

from mcp_security_audit.auditor import MCPAuditor, AuditResult
from mcp_security_audit.reporter import generate_json_report
from agentcred.scorer import generate_report as agentcred_report, TrustReport


# EU AI Act article references keyed by finding category + severity
EU_AI_ACT_REFS = {
    "injection": {
        "CRITICAL": {
            "article": "Article 9(2)(a)",
            "title": "Risk Management — Risk Identification",
            "requirement": "Providers must identify and analyse known and foreseeable risks that the AI system can pose.",
            "implication": "Prompt injection vulnerabilities in tool descriptions represent a foreseeable attack vector that must be identified and mitigated before deployment.",
        },
        "HIGH": {
            "article": "Article 9(2)(b)",
            "title": "Risk Management — Risk Estimation",
            "requirement": "Providers must estimate and evaluate risks that may emerge when the system is used.",
            "implication": "High-severity injection patterns indicate failure to estimate adversarial misuse potential.",
        },
        "MEDIUM": {
            "article": "Article 9(4)",
            "title": "Risk Management — Risk Mitigation Measures",
            "requirement": "Risk management measures must be implemented proportionate to the risk.",
            "implication": "Unmitigated injection patterns require documented mitigation measures in the risk management file.",
        },
    },
    "schema": {
        "CRITICAL": {
            "article": "Article 9(2)(c) + Article 15(1)",
            "title": "Risk Management — Input Validation + Accuracy Controls",
            "requirement": "AI systems must have input data governance and validation controls.",
            "implication": "Unconstrained input schemas on shell/exec tools violate both risk management and accuracy/robustness requirements.",
        },
        "MEDIUM": {
            "article": "Article 15(1)",
            "title": "Accuracy, Robustness and Cybersecurity",
            "requirement": "High-risk AI systems must be designed to achieve an appropriate level of accuracy, robustness and cybersecurity.",
            "implication": "Lack of input constraints reduces robustness against malformed or adversarial inputs.",
        },
        "LOW": {
            "article": "Article 17(1)(d)",
            "title": "Quality Management — Data Governance",
            "requirement": "Providers must implement data governance and management practices.",
            "implication": "Parameter constraints are a data quality control — their absence is a gap in the quality management system.",
        },
    },
    "scope": {
        "CRITICAL": {
            "article": "Article 9(2)(a) + Article 15(3)",
            "title": "Risk Management + Cybersecurity",
            "requirement": "Systems must be resilient against attempts by unauthorized third parties to alter their use.",
            "implication": "Shell tools with unconstrained string inputs are the highest-risk cybersecurity exposure in an MCP deployment.",
        },
        "HIGH": {
            "article": "Article 9(5)",
            "title": "Risk Management — Least Privilege",
            "requirement": "Risk management must consider the reasonably foreseeable misuse of the system.",
            "implication": "Unexpected high-risk capabilities beyond stated server purpose indicate scope creep that must be risk-assessed.",
        },
        "MEDIUM": {
            "article": "Article 13(1)",
            "title": "Transparency — Capability Disclosure",
            "requirement": "High-risk AI systems must be designed to ensure sufficient transparency to enable users to interpret the output.",
            "implication": "Undisclosed capabilities undermine user ability to appropriately scope trust and oversight.",
        },
    },
    "documentation": {
        "MEDIUM": {
            "article": "Article 13(3)(b)",
            "title": "Transparency — Instructions for Use",
            "requirement": "Instructions must include the purpose, accuracy, and limitations of the system.",
            "implication": "Undocumented tools prevent downstream users from assessing system capabilities and limitations.",
        },
        "LOW": {
            "article": "Article 11(1)",
            "title": "Technical Documentation",
            "requirement": "Technical documentation must be drawn up before the system is placed on the market.",
            "implication": "Tool documentation is a required component of technical documentation under the Act.",
        },
    },
    "metadata": {
        "LOW": {
            "article": "Article 11(2)(a)",
            "title": "Technical Documentation — System Description",
            "requirement": "Documentation must include a general description of the AI system.",
            "implication": "Missing server name/version makes the system non-identifiable in a compliance audit trail.",
        },
    },
}

# NIST AI RMF function mapping
NIST_REFS = {
    "injection": "GOVERN 1.2 / MAP 1.5 / MEASURE 2.5",
    "schema": "MANAGE 2.2 / MEASURE 2.6",
    "scope": "MAP 1.6 / MANAGE 1.3",
    "documentation": "GOVERN 2.2 / MAP 2.3",
    "metadata": "GOVERN 1.7",
}

REMEDIATION_EFFORT = {
    "CRITICAL": ("1-2 days", "Immediate — blocks deployment"),
    "HIGH": ("2-5 days", "Sprint 0 — before production"),
    "MEDIUM": ("1-2 weeks", "Next sprint"),
    "LOW": ("Ongoing", "Technical debt queue"),
}


@dataclass
class CompiledReport:
    """Full compiled report payload — passed to PDF renderer."""
    report_id: str
    generated_at: str
    client_name: str
    auditor_name: str
    server_name: str
    server_command: str
    server_repo: str

    # Raw outputs from packages
    security_json: dict = field(default_factory=dict)
    trust_report: dict = field(default_factory=dict)

    # Derived
    security_score: int = 0
    security_grade: str = "F"
    trust_score: float = 0.0
    trust_grade: str = "U"
    overall_risk: str = "UNKNOWN"

    # Enriched findings with regulatory refs
    enriched_findings: list[dict] = field(default_factory=list)

    # Executive summary (LLM-generated or template-based)
    executive_summary: str = ""

    # Remediation roadmap
    remediation_roadmap: list[dict] = field(default_factory=list)

    # KYA identity assessment
    has_kya_card: bool = False
    kya_summary: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _determine_overall_risk(security_score: int, trust_score: float, findings: list[dict]) -> str:
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")

    if critical_count >= 2 or security_score < 40:
        return "CRITICAL"
    elif critical_count >= 1 or high_count >= 3 or security_score < 65:
        return "HIGH"
    elif high_count >= 1 or security_score < 80:
        return "MEDIUM"
    elif security_score >= 90 and trust_score >= 70:
        return "LOW"
    return "MEDIUM"


def _enrich_findings(findings: list[dict]) -> list[dict]:
    """Add EU AI Act + NIST references to each finding."""
    enriched = []
    for f in findings:
        category = f.get("category", "")
        severity = f.get("severity", "LOW")

        eu_ref = None
        cat_refs = EU_AI_ACT_REFS.get(category, {})
        # Try exact severity, then fallback to next lower
        for sev in [severity, "HIGH", "MEDIUM", "LOW"]:
            if sev in cat_refs:
                eu_ref = cat_refs[sev]
                break

        nist_ref = NIST_REFS.get(category, "GOVERN 1.1")
        effort, priority = REMEDIATION_EFFORT.get(severity, ("Unknown", "Unknown"))

        enriched.append({
            **f,
            "eu_ai_act": eu_ref,
            "nist_ref": nist_ref,
            "remediation_effort": effort,
            "remediation_priority": priority,
        })
    return enriched


def _build_remediation_roadmap(enriched_findings: list[dict]) -> list[dict]:
    """Group findings by priority into a roadmap."""
    roadmap = []
    priority_order = [
        "Immediate — blocks deployment",
        "Sprint 0 — before production",
        "Next sprint",
        "Technical debt queue",
    ]
    for priority in priority_order:
        items = [f for f in enriched_findings if f.get("remediation_priority") == priority]
        if items:
            roadmap.append({
                "priority": priority,
                "finding_count": len(items),
                "findings": items,
            })
    return roadmap


def _generate_executive_summary_template(report: "CompiledReport") -> str:
    """Deterministic template-based executive summary (no LLM dependency)."""
    critical = sum(1 for f in report.enriched_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in report.enriched_findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in report.enriched_findings if f.get("severity") == "MEDIUM")
    total = len(report.enriched_findings)

    risk_word = {
        "CRITICAL": "an unacceptable level of",
        "HIGH": "a significant level of",
        "MEDIUM": "a moderate level of",
        "LOW": "a low level of",
    }.get(report.overall_risk, "an undetermined level of")

    deployment_rec = {
        "CRITICAL": "Deployment is not recommended until all Critical and High findings are resolved.",
        "HIGH": "Deployment should be delayed until Critical findings are resolved and High findings have documented mitigations.",
        "MEDIUM": "Conditional deployment is acceptable with a documented remediation plan for Medium and High findings.",
        "LOW": "Deployment may proceed. Low findings should be addressed in the next development cycle.",
    }.get(report.overall_risk, "Review findings before proceeding.")

    return f"""This report presents the results of an independent security and compliance audit of {report.server_name}, conducted on {report.generated_at[:10]} by {report.auditor_name}.

The audit assessed the server across two dimensions: (1) MCP Security Hygiene, using the mcp-security-audit framework — scoring documentation completeness, input schema rigor, injection safety, scope discipline, and metadata hygiene; and (2) Agent Trust Posture, using the AgentCred framework — scoring identity completeness, security posture, reliability signals, and behavioral reputation.

The server received a Security Hygiene Score of {report.security_score}/100 (Grade {report.security_grade}) and an Agent Trust Score of {report.trust_score}/100 (Grade {report.trust_grade}). The overall risk classification is {report.overall_risk}, indicating {risk_word} residual risk under the EU AI Act risk management framework.

The audit identified {total} finding(s): {critical} Critical, {high} High, {medium} Medium. {deployment_rec}

Each finding in this report is mapped to the applicable EU AI Act article and NIST AI Risk Management Framework (AI RMF) function to enable direct integration with your compliance program."""


async def _run_security_audit(server_command: str) -> dict:
    """Run mcp-security-audit and return JSON report."""
    auditor = MCPAuditor(server_command=server_command, run_live_tests=False)
    result = await auditor.run()
    return generate_json_report(result)


def compile_report(
    server_command: str,
    server_name: str,
    server_repo: str,
    client_name: str,
    report_id: str,
    auditor_name: str = "LuciferForge Security",
    kya_card: dict | None = None,
    github_stars: int | None = None,
    pre_run_security_json: dict | None = None,  # Skip live run if already have data
) -> CompiledReport:
    """
    Compile a full audit report.

    If pre_run_security_json is provided, skips the live server connection.
    This is the primary path for auditing servers that require complex setup.
    """
    report = CompiledReport(
        report_id=report_id,
        generated_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        client_name=client_name,
        auditor_name=auditor_name,
        server_name=server_name,
        server_command=server_command,
        server_repo=server_repo,
    )

    # Step 1: Security audit
    if pre_run_security_json:
        report.security_json = pre_run_security_json
    else:
        report.security_json = asyncio.run(_run_security_audit(server_command))

    report.security_score = report.security_json.get("hygiene_score", 0)
    report.security_grade = report.security_json.get("grade", "F")

    # Step 2: Trust/identity scoring (agentcred)
    card = kya_card or {}
    # Inject security audit score into card's security section for agentcred
    if not card.get("security"):
        card["security"] = {}
    if "last_audit" not in card["security"] and report.security_score:
        card["security"]["last_audit"] = {
            "date": report.generated_at[:10],
            "tool": "mcp-security-audit",
            "score": report.security_score,
        }

    trust = agentcred_report(card, audit_score=report.security_score, github_stars=github_stars)
    report.trust_report = trust.to_dict()
    report.trust_score = trust.composite_score
    report.trust_grade = trust.grade
    report.has_kya_card = bool(kya_card)
    report.kya_summary = trust.summary

    # Step 3: Enrich findings
    raw_findings = report.security_json.get("findings", [])
    report.enriched_findings = _enrich_findings(raw_findings)

    # Step 4: Overall risk
    report.overall_risk = _determine_overall_risk(
        report.security_score, report.trust_score, raw_findings
    )

    # Step 5: Remediation roadmap
    report.remediation_roadmap = _build_remediation_roadmap(report.enriched_findings)

    # Step 6: Executive summary
    report.executive_summary = _generate_executive_summary_template(report)

    return report
