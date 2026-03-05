"""
Tests for report_compiler.py — validates enrichment, risk scoring, and roadmap generation.
Run: python3 -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.report_compiler import (
    compile_report,
    _enrich_findings,
    _determine_overall_risk,
    _build_remediation_roadmap,
    _generate_executive_summary_template,
    CompiledReport,
)

SAMPLE_FINDINGS = [
    {"severity": "CRITICAL", "category": "injection", "title": "Injection in tool desc", "detail": "x", "tool_name": "foo"},
    {"severity": "HIGH", "category": "scope", "title": "Unexpected shell capability", "detail": "y", "tool_name": "exec_cmd"},
    {"severity": "MEDIUM", "category": "schema", "title": "Unconstrained object param", "detail": "z", "tool_name": ""},
    {"severity": "LOW", "category": "documentation", "title": "3 undocumented tools", "detail": "a", "tool_name": ""},
]

MINIMAL_SECURITY_JSON = {
    "server": "test",
    "server_name": "test-server",
    "server_version": "1.0.0",
    "risk_profile": "FILE",
    "server_purpose": ["File System"],
    "purpose_aligned": True,
    "hygiene_score": 45,
    "grade": "D",
    "hygiene_breakdown": {
        "documentation": 5.0,
        "schema_rigor": 10.0,
        "injection_safety": 15.0,
        "scope_signals": 10.0,
        "metadata": 5.0,
    },
    "error": None,
    "summary": {"tool_count": 5, "resource_count": 0, "prompt_count": 0, "finding_count": 4, "high_risk_tools": 3},
    "tools": [],
    "findings": SAMPLE_FINDINGS,
    "resources": [],
    "prompts": [],
    "live_tests": None,
}


class TestEnrichFindings:
    def test_adds_eu_ai_act_ref_to_injection_critical(self):
        findings = [{"severity": "CRITICAL", "category": "injection", "title": "test", "detail": "x"}]
        enriched = _enrich_findings(findings)
        assert len(enriched) == 1
        assert enriched[0]["eu_ai_act"] is not None
        assert "Article 9" in enriched[0]["eu_ai_act"]["article"]

    def test_adds_nist_ref(self):
        findings = [{"severity": "HIGH", "category": "scope", "title": "test", "detail": "x"}]
        enriched = _enrich_findings(findings)
        assert "nist_ref" in enriched[0]
        assert enriched[0]["nist_ref"]

    def test_adds_remediation_effort(self):
        findings = [{"severity": "CRITICAL", "category": "injection", "title": "test", "detail": "x"}]
        enriched = _enrich_findings(findings)
        assert enriched[0]["remediation_effort"] == "1-2 days"
        assert enriched[0]["remediation_priority"] == "Immediate — blocks deployment"

    def test_low_severity_effort(self):
        findings = [{"severity": "LOW", "category": "documentation", "title": "test", "detail": "x"}]
        enriched = _enrich_findings(findings)
        assert enriched[0]["remediation_priority"] == "Technical debt queue"

    def test_unknown_category_doesnt_crash(self):
        findings = [{"severity": "MEDIUM", "category": "unknown_future_category", "title": "test", "detail": "x"}]
        enriched = _enrich_findings(findings)
        assert len(enriched) == 1
        # eu_ai_act may be None for unknown categories — that's acceptable
        assert "nist_ref" in enriched[0]

    def test_all_sample_findings_enriched(self):
        enriched = _enrich_findings(SAMPLE_FINDINGS)
        assert len(enriched) == len(SAMPLE_FINDINGS)
        for f in enriched:
            assert "eu_ai_act" in f
            assert "nist_ref" in f
            assert "remediation_effort" in f


class TestDetermineOverallRisk:
    def test_critical_findings_give_critical_risk(self):
        findings = [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}]
        assert _determine_overall_risk(80, 70, findings) == "CRITICAL"

    def test_low_score_gives_critical(self):
        assert _determine_overall_risk(35, 70, []) == "CRITICAL"

    def test_clean_high_score_gives_low(self):
        assert _determine_overall_risk(92, 75, []) == "LOW"

    def test_one_critical_gives_high(self):
        findings = [{"severity": "CRITICAL"}]
        assert _determine_overall_risk(75, 70, findings) == "HIGH"

    def test_medium_score_gives_medium(self):
        # Score 70 + 1 HIGH finding = MEDIUM (needs 3 HIGH findings or score < 65 for HIGH)
        assert _determine_overall_risk(70, 60, [{"severity": "HIGH"}]) == "MEDIUM"

    def test_three_high_findings_gives_high(self):
        findings = [{"severity": "HIGH"}, {"severity": "HIGH"}, {"severity": "HIGH"}]
        assert _determine_overall_risk(70, 60, findings) == "HIGH"


class TestRemediationRoadmap:
    def test_groups_by_priority(self):
        enriched = _enrich_findings(SAMPLE_FINDINGS)
        roadmap = _build_remediation_roadmap(enriched)
        priorities = [g["priority"] for g in roadmap]
        assert "Immediate — blocks deployment" in priorities

    def test_no_empty_groups(self):
        enriched = _enrich_findings(SAMPLE_FINDINGS)
        roadmap = _build_remediation_roadmap(enriched)
        for group in roadmap:
            assert group["finding_count"] > 0
            assert len(group["findings"]) > 0


class TestCompileReport:
    def test_compile_with_pre_run_json(self):
        report = compile_report(
            server_command="",
            server_name="Test Server",
            server_repo="https://github.com/test/test",
            client_name="Test Corp",
            report_id="TEST-001",
            pre_run_security_json=MINIMAL_SECURITY_JSON,
        )
        assert report.security_score == 45
        assert report.security_grade == "D"
        assert report.report_id == "TEST-001"
        assert report.client_name == "Test Corp"
        assert len(report.enriched_findings) == 4
        assert report.overall_risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert report.executive_summary  # Not empty

    def test_executive_summary_contains_scores(self):
        report = compile_report(
            server_command="",
            server_name="Test Server",
            server_repo="",
            client_name="Test",
            report_id="T-001",
            pre_run_security_json=MINIMAL_SECURITY_JSON,
        )
        assert "45" in report.executive_summary
        assert "D" in report.executive_summary

    def test_no_kya_card_noted(self):
        report = compile_report(
            server_command="",
            server_name="Test Server",
            server_repo="",
            client_name="Test",
            report_id="T-001",
            pre_run_security_json=MINIMAL_SECURITY_JSON,
            kya_card=None,
        )
        assert not report.has_kya_card

    def test_with_kya_card_sets_flag(self):
        minimal_card = {
            "kya_version": "0.1",
            "agent_id": "test-001",
            "name": "Test Agent",
            "version": "1.0.0",
            "purpose": "Testing",
        }
        report = compile_report(
            server_command="",
            server_name="Test Server",
            server_repo="",
            client_name="Test",
            report_id="T-001",
            pre_run_security_json=MINIMAL_SECURITY_JSON,
            kya_card=minimal_card,
        )
        assert report.has_kya_card
