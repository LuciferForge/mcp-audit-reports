"""
run_audit.py — CLI entry point for generating a paid audit report.

Usage:
    python3 tools/run_audit.py \
        --server-command "npx -y @modelcontextprotocol/server-filesystem /tmp" \
        --server-name "MCP Filesystem Server" \
        --server-repo "https://github.com/modelcontextprotocol/servers" \
        --client-name "Acme Corp" \
        --report-id "LF-2026-001" \
        --output /tmp/audit_report.pdf

    # Use pre-run JSON (server doesn't need to be running):
    python3 tools/run_audit.py \
        --server-name "MCP Filesystem Server" \
        --server-repo "https://github.com/modelcontextprotocol/servers" \
        --client-name "Acme Corp" \
        --report-id "LF-2026-001" \
        --pre-run-json /path/to/audit.json \
        --output /tmp/audit_report.pdf
"""

import argparse
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.report_compiler import compile_report
from core.pdf_renderer import render_pdf


def main():
    parser = argparse.ArgumentParser(description="Generate MCP Security Compliance Audit Report")
    parser.add_argument("--server-command", help="MCP server command (e.g. 'npx -y @mcp/server-filesystem /tmp')")
    parser.add_argument("--server-name", required=True, help="Human-readable server name")
    parser.add_argument("--server-repo", default="", help="GitHub repo URL")
    parser.add_argument("--client-name", default="Internal", help="Client organization name")
    parser.add_argument("--report-id", default="LF-2026-DRAFT", help="Report reference ID")
    parser.add_argument("--auditor-name", default="LuciferForge Security", help="Auditor name")
    parser.add_argument("--pre-run-json", help="Path to existing mcp-security-audit JSON output")
    parser.add_argument("--kya-card", help="Path to KYA card JSON file")
    parser.add_argument("--github-stars", type=int, help="GitHub star count for reputation scoring")
    parser.add_argument("--output", required=True, help="Output PDF path")
    parser.add_argument("--dry-run", action="store_true", help="Compile and print summary without writing PDF")

    args = parser.parse_args()

    if not args.server_command and not args.pre_run_json:
        print("ERROR: Provide either --server-command or --pre-run-json", file=sys.stderr)
        sys.exit(1)

    # Load pre-run JSON if provided
    pre_run_json = None
    if args.pre_run_json:
        with open(args.pre_run_json) as f:
            pre_run_json = json.load(f)
        print(f"Loaded pre-run security audit from {args.pre_run_json}")

    # Load KYA card if provided
    kya_card = None
    if args.kya_card:
        with open(args.kya_card) as f:
            kya_card = json.load(f)
        print(f"Loaded KYA card from {args.kya_card}")

    print(f"Compiling report: {args.server_name}")

    report = compile_report(
        server_command=args.server_command or "",
        server_name=args.server_name,
        server_repo=args.server_repo,
        client_name=args.client_name,
        report_id=args.report_id,
        auditor_name=args.auditor_name,
        kya_card=kya_card,
        github_stars=args.github_stars,
        pre_run_security_json=pre_run_json,
    )

    print(f"Security Score: {report.security_score}/100 (Grade {report.security_grade})")
    print(f"Trust Score:    {report.trust_score}/100 (Grade {report.trust_grade})")
    print(f"Overall Risk:   {report.overall_risk}")
    print(f"Findings:       {len(report.enriched_findings)}")

    if args.dry_run:
        print("\n--- EXECUTIVE SUMMARY ---")
        print(report.executive_summary)
        print("\n--- REMEDIATION ROADMAP ---")
        for group in report.remediation_roadmap:
            print(f"\n{group['priority']} ({group['finding_count']} findings):")
            for f in group["findings"]:
                print(f"  - [{f['severity']}] {f['title']}")
        print("\nDry run complete. No PDF written.")
        return

    output_path = render_pdf(report, args.output)
    print(f"\nReport written to: {output_path}")
    print(f"Report ID: {args.report_id}")


if __name__ == "__main__":
    main()
