---
title: I Audited 7 Official MCP Servers. Here's What I Found.
published: false
description: Security audit of the official Model Context Protocol servers reveals a universal weakness that every MCP developer should know about.
tags: mcp, security, ai, llm
canonical_url:
cover_image:
---

Every MCP server in the official repo has the same security gap. Not a vulnerability exactly — more like a missing seatbelt that everyone forgot to install.

I ran [mcp-security-audit](https://github.com/LuciferForge/mcp-security-audit) against 7 servers from `modelcontextprotocol/servers`. The tool connects via stdio, enumerates every tool and parameter, and scores them across documentation, schema rigor, injection safety, scope control, and metadata hygiene.

## Results

| Server | Tools | Score | Grade | Notable Finding |
|--------|-------|-------|-------|----------------|
| Fetch | 1 | 100/100 | A | Clean. Zero findings. |
| SQLite | 6 | 95/100 | A | Unconstrained SQL query strings |
| Time | 2 | 95/100 | A | Unconstrained timezone strings |
| GitHub | 26 | 94/100 | A | `create_or_update_file` flagged as unexpected FILE capability |
| Memory | 9 | 92/100 | A | Unconstrained search query |
| Git | 12 | 90/100 | A | 18 unconstrained string parameters |
| Filesystem | 14 | 85/100 | B | `read_media_file` triggers base64 injection detector |

5 Grade A, 2 Grade B. No critical vulnerabilities. The official servers are generally well-built.

But there's a pattern.

## The Universal Weakness: Unconstrained Strings

Every server except Fetch failed to constrain string parameters. No `maxLength`. No `pattern`. No `enum`. Just raw, open strings that accept anything the LLM decides to send.

The Git server has 18 of them. Paths, commit messages, branch names — all freeform. The SQLite server accepts SQL queries of unlimited length. The Time server accepts timezone strings with no validation against IANA identifiers.

Why this matters:

**1. DoS vector.** An unconstrained string parameter accepts a 10MB commit message or a 50,000-character file path. The server has to process it. MCP servers typically run locally, so this isn't a remote attack — but if your MCP server is exposed via a network transport (which the spec supports), this becomes a real issue.

**2. No input validation at the boundary.** The MCP spec puts the LLM between the user and the tools. But LLMs are susceptible to prompt injection. If an attacker injects instructions that cause the LLM to send malformed input to a tool, the tool has no schema-level defense. It's trusting the LLM to be well-behaved.

**3. It's trivially fixable.** Adding `maxLength: 1000` to a path parameter takes one line. Adding `pattern: "^[a-zA-Z/_-]+$"` to a timezone parameter takes one line. These constraints are enforced by the MCP protocol layer before the tool code ever runs.

## The Fix (For MCP Server Authors)

Instead of:

```json
{
  "name": "query",
  "type": "string",
  "description": "SQL query to execute"
}
```

Do:

```json
{
  "name": "query",
  "type": "string",
  "description": "SQL query to execute",
  "maxLength": 10000
}
```

For parameters with known formats:

```json
{
  "name": "timezone",
  "type": "string",
  "description": "IANA timezone identifier",
  "pattern": "^[A-Za-z_/]+$",
  "maxLength": 50
}
```

For parameters with known values:

```json
{
  "name": "operation",
  "type": "string",
  "enum": ["staged", "unstaged", "all"]
}
```

## Specific Findings Worth Noting

### Filesystem Server: base64 injection pattern (False Positive)

The `read_media_file` tool description mentions returning base64-encoded content. Our injection detector flagged this because base64 strings in tool descriptions can be used to smuggle instructions past content filters.

In this case it's legitimate — the tool genuinely returns base64 media. But it highlights an interesting problem: how do you distinguish between a tool that legitimately handles encoded content and one that's been backdoored to inject encoded instructions?

The answer: context-aware scoring. Our auditor knows the Filesystem server's purpose is FILE operations, so base64 in a media reader is expected. A Calendar server returning base64 would be suspicious.

### GitHub Server: Unexpected FILE Capability

The GitHub server exposes `create_or_update_file`, which writes files to repos. Our auditor classified the server's purpose as NETWORK/API (it talks to the GitHub API), so a FILE-writing tool is flagged as scope creep.

This is actually correct behavior — creating files in repos IS what the GitHub API does. But the finding illustrates an important principle: **every capability beyond a server's core purpose should be explicitly justified.** If your MCP server's primary job is fetching weather data and it also has a `write_file` tool, that's a red flag.

### Fetch Server: The Gold Standard

One tool. One parameter (URL). Properly constrained. Well-documented. Perfect score.

If you're building an MCP server, model it after Fetch. Start with the minimum surface area and add tools only when necessary.

## How to Audit Your Own MCP Servers

```bash
pip install mcp-security-audit
mcp-audit scan --server "npx @modelcontextprotocol/server-filesystem /tmp"
```

The tool outputs a scored report with specific findings and recommendations. It works with any MCP server that communicates over stdio.

Full JSON audit reports for all 7 servers: [LuciferForge/audit-reports](https://github.com/LuciferForge/audit-reports)

## What This Means for the MCP Ecosystem

MCP is 6 months old and growing fast. The official servers are setting the standard that every community server will follow. Right now, that standard includes good documentation and clean injection safety — but skips input validation.

This is the same pattern we saw with early REST APIs. Everyone shipped endpoints without input validation, then spent years adding it after the exploits started. MCP has the advantage of learning from that history.

The fix is small. One line per parameter. The official servers should lead by example.

---

*Audits performed with [mcp-security-audit](https://pypi.org/project/mcp-security-audit/) v0.2.0. The tool is open-source and free.*
