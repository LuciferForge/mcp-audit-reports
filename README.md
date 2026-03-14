# MCP Audit Reports

Security and EU AI Act compliance audit reports for official MCP servers.

## Audited Servers

| Server | Score | Grade | Report |
|--------|-------|-------|--------|
| filesystem | 7/100 | F | [JSON](filesystem-server-audit.json) |
| fetch | — | — | [JSON](fetch-server-audit.json) |
| git | — | — | [JSON](git-server-audit.json) |
| github | — | — | [JSON](github-server-audit.json) |
| sqlite | — | — | [JSON](sqlite-server-audit.json) |
| memory | — | — | [JSON](memory-server-audit.json) |
| time | — | — | [JSON](time-server-audit.json) |
| agent-safety-mcp | — | — | [JSON](agent-safety-mcp-audit.json) |

## How These Were Generated

Audits are produced by [mcp-security-audit](https://github.com/LuciferForge/mcp-security-audit) — an automated security scanner for MCP servers that checks for:

- Prompt injection vulnerabilities
- Overprivileged tool access
- Missing input validation
- EU AI Act compliance gaps

## Run Your Own Audit

```bash
pip install mcp-security-audit
mcp-audit scan path/to/server.py
```

## Related

- [mcp-security-audit](https://github.com/LuciferForge/mcp-security-audit) — The scanning tool
- [ai-injection-guard](https://github.com/LuciferForge/prompt-shield) — Prompt injection detection
- [protodex.io](https://protodex.io) — Search 1,629+ MCP servers

## License

MIT
