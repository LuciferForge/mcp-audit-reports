---
title: We Audited Anthropic's Official MCP Servers — Here's the Compliance Problem No One's Talking About
published: false
description: The official MCP filesystem server scores 7/100 on security hygiene. It has 7 EU AI Act compliance findings. And it's installed by millions.
tags: mcp, ai, security, python
cover_image:
---

The Model Context Protocol has exploded. 88M+ monthly SDK downloads. 18,000+ servers. Adoption by Claude Code, Cursor, Windsurf, and every major AI coding tool.

But here's the question nobody is asking: **are these servers compliant with the regulations that take effect in months?**

We built [mcp-security-audit](https://github.com/LuciferForge/mcp-security-audit) — an open-source tool that connects to any MCP server, enumerates its tools and resources, classifies risk levels, scans for injection patterns, and produces a scored report (0-100, grades A-F).

Then we pointed it at Anthropic's own official reference servers.

## The Scorecard

| Server | Tools | Grade | Score | Findings |
|--------|-------|-------|-------|----------|
| server-time | 2 | **A** | 100 | 0 |
| server-sequential-thinking | 1 | **A** | 100 | 0 |
| server-git | 12 | **A** | 100 | 0 |
| server-fetch | 1 | **A** | 100 | 0 |
| server-everything | 13 | **A** | 97 | 1 |
| server-memory | 9 | **A** | 97 | 1 |
| server-sqlite | 6 | **C** | 73 | 4 |
| **server-filesystem** | **14** | **F** | **7** | **7** |

Six servers passed clean. Two didn't. One failed catastrophically.

## The Worst Offender: server-filesystem

**Score: 7/100. Grade: F. 7 findings.**

This is the official Anthropic filesystem server — the one installed by millions of Claude Code, Cursor, and Windsurf users. It exposes 14 tools including `read_file`, `write_file`, `delete_file`, and `move_file`.

Here's what we found:

**1. 13 of 14 tools have zero descriptions**
Tool descriptions are how an LLM understands what a tool does and when to use it. Without descriptions, the model is guessing. This is an Article 13 (Transparency) violation — users cannot assess the system's capabilities if tools aren't documented.

**2. 28 string parameters with no input constraints**
Every file path parameter is an unconstrained string. No regex patterns, no enums, no length limits. This means the LLM can pass arbitrary paths — including `../../etc/passwd` or paths outside the intended directory. Article 15 (Accuracy, Robustness, Cybersecurity) requires input validation controls.

**3. Destructive tools are completely undocumented**
`delete_file`, `write_file`, `move_file` — tools that can destroy data — have no descriptions explaining their behavior, no warnings about irreversibility, no confirmation mechanisms. Article 9 (Risk Management) requires foreseeable risks to be identified and mitigated.

**4. No version string declared**
The server exposes no version metadata. If you're running an audit trail for compliance, you can't even identify which version was deployed. Article 11 (Technical Documentation) requires system identification.

## What the EU AI Act Actually Requires

The EU AI Act takes effect August 2026. If your AI system — including MCP servers it connects to — is deployed in the EU, these articles apply:

**Article 9(2)(a) — Risk Identification**
> Providers must identify and analyse known and foreseeable risks that the AI system can pose.

Unconstrained file system access with no input validation is a foreseeable risk.

**Article 13(3)(b) — Instructions for Use**
> Instructions must include the purpose, accuracy, and limitations of the system.

13 undocumented tools means downstream users cannot assess capabilities or limitations.

**Article 15(1) — Accuracy and Robustness**
> High-risk AI systems must achieve an appropriate level of accuracy, robustness and cybersecurity.

28 unconstrained string parameters reduce robustness against malformed or adversarial inputs.

**Article 17(1)(d) — Data Governance**
> Providers must implement data governance and management practices.

Parameter constraints are a data quality control. Their absence is a gap in the quality management system.

## What About server-sqlite?

Score: 73/100. Grade: C. 4 findings.

The SQLite server scored much better but still has issues: raw SQL execution tools with unconstrained query parameters. The `read_query` and `write_query` tools accept arbitrary SQL strings with no schema validation. In an agent context, this means the LLM can execute any SQL — including `DROP TABLE`.

## The Good News

Six servers scored A (97-100). It's absolutely possible to build MCP servers that pass. The common patterns in passing servers:

- Every tool has a clear description
- Parameters have type constraints and descriptions
- Server declares name and version
- Scope matches the stated purpose (no unexpected capabilities)

## What You Should Do

**Step 1: Audit your servers (free)**

```bash
pip install mcp-security-audit
mcp-audit "your-server-command-here"
```

The tool is open source, runs locally, and produces a scored report in seconds. No data leaves your machine.

**Step 2: Fix the easy wins**

Most findings are documentation gaps — add tool descriptions, add parameter constraints, declare a version string. These are 1-2 hour fixes that dramatically improve your score.

**Step 3: If you're in a regulated environment**

The free CLI gives you raw scores. But if your compliance team needs a formal report — one with every finding mapped to specific EU AI Act articles, a prioritized remediation roadmap, and a signed PDF suitable for your compliance package — we produce those.

[View a demo report (PDF) — the full filesystem server audit](https://luciferforge.github.io/mcp-audit-reports/LF-2026-DEMO_filesystem_server_audit.pdf)

Reports start at $200/server, delivered in 3 days. Email LuciferForge@proton.me.

## Methodology

Our scoring framework evaluates 5 dimensions:

1. **Documentation Completeness** — Are tools described? Are parameters documented?
2. **Schema Rigor** — Do parameters have type constraints, enums, regex patterns?
3. **Injection Safety** — Are tool descriptions or default values vulnerable to prompt injection?
4. **Scope Discipline** — Does the server's capability set match its stated purpose?
5. **Metadata Hygiene** — Does the server declare name, version, and capabilities?

Each dimension is scored and weighted into a composite score (0-100) with letter grades. The methodology is cross-mapped to both the EU AI Act and NIST AI Risk Management Framework (AI RMF 1.0).

We submitted a formal response to the NIST AI 100-1 public comment process. Our tools are published on [PyPI](https://pypi.org/project/mcp-security-audit/) and actively maintained on [GitHub](https://github.com/LuciferForge/mcp-security-audit).

---

*The MCP ecosystem is moving fast. Security tooling needs to keep pace. If you're building or deploying MCP servers, know what you're exposing before your compliance team asks.*
