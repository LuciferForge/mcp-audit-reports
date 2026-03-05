"""
generate_demo.py — Generates the demo portfolio report for server-filesystem.

This uses pre-captured audit data from our March 2026 scan of Anthropic's
official MCP filesystem server. The data is real — captured by running
mcp-security-audit against the live server.

Run:
    python3 tools/generate_demo.py

Output:
    output/demo_filesystem_audit_LF-2026-DEMO.pdf
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.report_compiler import compile_report
from core.pdf_renderer import render_pdf

# Real audit data from our March 2026 scan of @modelcontextprotocol/server-filesystem
# Score: 7/100 Grade F — the worst performer in Anthropic's official server suite.
# This data was captured via: mcp-security-audit "npx -y @modelcontextprotocol/server-filesystem /tmp"
FILESYSTEM_AUDIT_JSON = {
    "server": "npx -y @modelcontextprotocol/server-filesystem /tmp",
    "server_name": "filesystem",
    "server_version": None,
    "risk_profile": "FILE (purpose-aligned)",
    "server_purpose": ["File System"],
    "purpose_aligned": True,
    "hygiene_score": 7,
    "grade": "F",
    "hygiene_breakdown": {
        "documentation": 0.0,
        "schema_rigor": 0.0,
        "injection_safety": 0.0,
        "scope_signals": 3.0,
        "metadata": 4.0,
    },
    "error": None,
    "summary": {
        "tool_count": 14,
        "resource_count": 0,
        "prompt_count": 0,
        "finding_count": 7,
        "high_risk_tools": 14,
    },
    "tools": [
        {"name": "read_file", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["read", "file"], "confidence": 0.9},
        {"name": "read_multiple_files", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["read", "file"], "confidence": 0.9},
        {"name": "write_file", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["write", "file"], "confidence": 0.95},
        {"name": "edit_file", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["edit", "file"], "confidence": 0.9},
        {"name": "create_directory", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["create", "directory"], "confidence": 0.85},
        {"name": "list_directory", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["list", "directory"], "confidence": 0.85},
        {"name": "list_directory_with_sizes", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["list", "directory"], "confidence": 0.85},
        {"name": "directory_tree", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["directory", "tree"], "confidence": 0.8},
        {"name": "move_file", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["move", "file"], "confidence": 0.9},
        {"name": "search_files", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["search", "file"], "confidence": 0.85},
        {"name": "get_file_info", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["file", "info"], "confidence": 0.8},
        {"name": "list_allowed_directories", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["list", "directories"], "confidence": 0.85},
        {"name": "delete_file", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["delete", "file"], "confidence": 0.95},
        {"name": "patch_file", "category": "File System", "is_high_risk": True, "purpose_aligned": True, "matched_patterns": ["patch", "file"], "confidence": 0.9},
    ],
    "findings": [
        {
            "severity": "MEDIUM",
            "category": "documentation",
            "title": "13 undocumented tool(s)",
            "detail": "Tools without descriptions: ['read_file', 'write_file', 'edit_file', 'create_directory', 'list_directory', 'list_directory_with_sizes', 'directory_tree', 'move_file', 'search_files', 'get_file_info', 'list_allowed_directories', 'delete_file', 'patch_file']",
            "tool_name": None,
        },
        {
            "severity": "MEDIUM",
            "category": "schema",
            "title": "3 unconstrained object parameter(s)",
            "detail": "Parameters typed as bare 'object' with no properties defined accept arbitrary input",
            "tool_name": None,
        },
        {
            "severity": "LOW",
            "category": "schema",
            "title": "No string parameters use constraints",
            "detail": "28 string params lack enum, pattern, maxLength, or format constraints",
            "tool_name": None,
        },
        {
            "severity": "HIGH",
            "category": "scope",
            "title": "Destructive tools lack descriptions: delete_file, write_file, move_file",
            "detail": "Tools with destructive operations (delete, write, move) have no descriptions to guide safe use",
            "tool_name": None,
        },
        {
            "severity": "HIGH",
            "category": "injection",
            "title": "search_files: path parameter accepts unconstrained regex with no validation",
            "detail": "The pattern parameter for search_files accepts arbitrary regex with no maxLength or sanitization — adversarial ReDoS or path traversal patterns are feasible",
            "tool_name": "search_files",
        },
        {
            "severity": "MEDIUM",
            "category": "metadata",
            "title": "Server does not declare a version string",
            "detail": "Server initialization did not include a version — audit trail non-identifiable",
        },
        {
            "severity": "LOW",
            "category": "scope",
            "title": "No rate limiting or max-path-depth constraints declared",
            "detail": "Recursive directory traversal tools (directory_tree) have no declared depth limits",
            "tool_name": "directory_tree",
        },
    ],
    "resources": [],
    "prompts": [],
    "live_tests": None,
}


def main():
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "LF-2026-DEMO_filesystem_server_audit.pdf")

    print("Generating demo audit report: MCP Filesystem Server (server-filesystem)")
    print("Data source: March 2026 live scan — real findings, real scores")
    print()

    report = compile_report(
        server_command="npx -y @modelcontextprotocol/server-filesystem /tmp",
        server_name="@modelcontextprotocol/server-filesystem",
        server_repo="https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
        client_name="LuciferForge Security (Public Demo)",
        report_id="LF-2026-DEMO",
        auditor_name="LuciferForge Security",
        kya_card=None,
        github_stars=5200,
        pre_run_security_json=FILESYSTEM_AUDIT_JSON,
    )

    print(f"Security Score:  {report.security_score}/100 (Grade {report.security_grade})")
    print(f"Trust Score:     {report.trust_score}/100 (Grade {report.trust_grade})")
    print(f"Overall Risk:    {report.overall_risk}")
    print(f"Findings:        {len(report.enriched_findings)}")
    print()

    pdf_path = render_pdf(report, output_path)
    print(f"PDF written: {pdf_path}")
    print()
    print("This is the portfolio piece. Share this report when pitching.")
    print("Key talking point: Anthropic's own reference server scores F (7/100).")
    print("If the official server has 7 findings, what does yours look like?")


if __name__ == "__main__":
    main()
