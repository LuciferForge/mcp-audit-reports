# MCP Server Security Audit Report

**Date:** March 12, 2026
**Auditor:** [mcp-security-audit v0.2.0](https://pypi.org/project/mcp-security-audit/) by LuciferForge
**Methodology:** Automated static analysis — tool classification, injection pattern scanning, schema rigor, documentation completeness, scope analysis, metadata hygiene. Scored 0-100 across 5 categories.

---

## Executive Summary

7 MCP servers audited. **5 scored Grade A, 2 scored Grade B.** No critical vulnerabilities found. The most common weakness across all servers: **unconstrained string parameters** (no maxLength, enum, or pattern validation).

| # | Server | Version | Tools | Score | Grade | Risk Profile |
|---|--------|---------|-------|-------|-------|--------------|
| 1 | **Filesystem Server** (official) | 0.2.0 | 14 | 85/100 | **B** | FILE (purpose-aligned) |
| 2 | **GitHub Server** (official) | 0.6.2 | 26 | 94/100 | **A** | FILE |
| 3 | **Memory Server** (official) | 0.6.3 | 9 | 92/100 | **A** | DATABASE |
| 4 | **Fetch Server** (official) | 1.26.0 | 1 | 100/100 | **A** | NETWORK (purpose-aligned) |
| 5 | **Git Server** (official) | 1.26.0 | 12 | 90/100 | **A** | SAFE |
| 6 | **SQLite Server** (official) | 0.1.0 | 6 | 95/100 | **A** | DATABASE (purpose-aligned) |
| 7 | **Time Server** (official) | 1.26.0 | 2 | 95/100 | **A** | SAFE |

---

## Scoring Methodology

Each server is scored across 5 hygiene categories (100 points total):

| Category | Max Points | What It Measures |
|----------|-----------|------------------|
| Documentation | 25 | Tool/param/resource descriptions present and substantive |
| Schema Rigor | 25 | Input schemas defined, constrained types, required fields |
| Injection Safety | 25 | No injection patterns in descriptions, no encoded content |
| Scope & Least Privilege | 15 | Minimal attack surface, destructive tools documented |
| Metadata | 10 | Server name/version, consistent naming, no duplicates |

**Grades:** A (90+), B (80+), C (65+), D (50+), F (<50)

---

## Detailed Findings

### 1. Filesystem Server — 85/100 (Grade B)

**Server:** `@modelcontextprotocol/server-filesystem` (Node.js)

The filesystem server exposes 14 tools for reading/writing files. All FILE-category tools are **purpose-aligned** (expected for a filesystem server).

**Findings:**
- **[MEDIUM] Injection pattern in `read_media_file` description** — The tool description triggered the `base64_injection` pattern detector. This is a false positive (the description mentions base64 encoding for media files), but highlights that tool descriptions mentioning encoding formats can be ambiguous.

**Score breakdown:** Documentation 21.4/25, Schema Rigor 20.3/25, Injection Safety 18/25, Scope 15/15, Metadata 10/10.

**Recommendation:** Rephrase the `read_media_file` description to avoid triggering injection pattern detectors. Add string constraints (maxLength) to path parameters.

---

### 2. GitHub Server — 94/100 (Grade A)

**Server:** `@modelcontextprotocol/server-github` (Node.js, deprecated)

Large surface area with 26 tools covering repos, issues, PRs, search, and file operations. Well-documented with good schema coverage.

**Findings:**
- **[HIGH] Unexpected FILE capability: `create_or_update_file`** — This tool is classified as FILE-risk but the server's inferred purpose (NETWORK/API) doesn't include file operations. The tool writes files directly to GitHub repos, which is a valid use case but flagged because it's a broader capability than expected for a pure API server.

**Score breakdown:** Documentation 23/25, Schema Rigor 20.8/25, Injection Safety 25/25, Scope 15/15, Metadata 10/10.

**Recommendation:** This server is deprecated (npm warning). Migrate to the replacement package. The `create_or_update_file` finding is a false positive for purpose alignment — creating files in repos IS the server's purpose.

---

### 3. Memory Server — 92/100 (Grade A)

**Server:** `@modelcontextprotocol/server-memory` (Node.js)

Knowledge graph server with 9 tools for entity/relation management. Clean design, minimal attack surface.

**Findings:**
- **[LOW] No string parameters use constraints** — 1 string parameter lacks enum, pattern, maxLength, or format constraints.

**Score breakdown:** Documentation 22.5/25, Schema Rigor 20/25, Injection Safety 25/25, Scope 15/15, Metadata 10/10.

**Recommendation:** Add maxLength constraints to the `search_nodes` query parameter.

---

### 4. Fetch Server — 100/100 (Grade A)

**Server:** `mcp-server-fetch` (Python)

Single-tool server for fetching URLs. Perfect score. Minimal attack surface, well-documented, properly constrained.

**Findings:** None.

**Recommendation:** None needed. This is the gold standard for a focused, well-documented MCP server.

---

### 5. Git Server — 90/100 (Grade A)

**Server:** `mcp-server-git` (Python)

12 tools for git operations. All classified as SAFE (no shell/exec patterns detected — the tools use git libraries, not shell commands).

**Findings:**
- **[LOW] No string parameters use constraints** — 18 string parameters lack enum, pattern, maxLength, or format constraints. Paths and commit messages are all freeform.

**Score breakdown:** Documentation 19.9/25, Schema Rigor 20/25, Injection Safety 25/25, Scope 15/15, Metadata 10/10.

**Recommendation:** Add maxLength to commit message parameters and path parameters. Consider enum constraints for common parameters like `--staged`.

---

### 6. SQLite Server — 95/100 (Grade A)

**Server:** `mcp-server-sqlite` (Python)

6 tools for database operations. 4 correctly classified as DATABASE-risk, purpose-aligned. Clean, well-documented schemas.

**Findings:**
- **[LOW] No string parameters use constraints** — 5 string parameters (SQL queries and table names) lack constraints. SQL queries are inherently freeform, so this is partially expected.

**Score breakdown:** Documentation 25/25, Schema Rigor 20/25, Injection Safety 25/25, Scope 15/15, Metadata 10/10.

**Recommendation:** Add maxLength to SQL query parameters to prevent extremely large queries. Table name parameters could use a pattern constraint.

---

### 7. Time Server — 95/100 (Grade A)

**Server:** `mcp-server-time` (Python)

Minimal 2-tool server for time queries and conversions. Low risk, well-documented.

**Findings:**
- **[LOW] No string parameters use constraints** — 4 string parameters (timezone names) lack constraints. These could benefit from an enum of valid IANA timezone identifiers.

**Score breakdown:** Documentation 25/25, Schema Rigor 20/25, Injection Safety 25/25, Scope 15/15, Metadata 10/10.

**Recommendation:** Add enum or pattern constraints for timezone parameters using IANA timezone format.

---

## Cross-Server Patterns

### Universal Weakness: Unconstrained String Parameters
Every server except Fetch (which got 100/100) failed to use string constraints. This is the single biggest hygiene gap across the MCP ecosystem. Unconstrained strings:
- Accept arbitrarily long input (potential DoS vector)
- Accept any format (no input validation)
- Rely entirely on the LLM to send reasonable values

**Fix:** MCP server authors should use `maxLength`, `pattern`, `enum`, or `format` on string parameters wherever possible.

### Positive Pattern: Good Documentation
Most servers provide substantive tool descriptions. The official servers set a good standard here.

### Positive Pattern: Clean Injection Safety
No server had actual injection patterns embedded in tool descriptions. The one detection (filesystem `read_media_file` mentioning base64) is a false positive.

---

## About This Audit

This audit was performed using [mcp-security-audit](https://github.com/LuciferForge/mcp-security-audit), an open-source MCP server security auditor. It connects to any MCP server via stdio, enumerates its capabilities, and produces a scored hygiene report.

Install: `pip install mcp-security-audit`
Run: `mcp-audit scan --server "your-server-command"`

Full JSON reports for each server are available alongside this summary.
