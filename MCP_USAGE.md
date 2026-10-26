# Adversarial REA — MCP Server Guide

An MCP server that exposes local binary-analysis tools (built on `objdump`, `nm`, `strings`, and `otool`) over stdio JSON-RPC 2.0. The server extracts deterministic ground-truth telemetry from binaries on disk; the connected MCP client performs higher-level analysis over those facts.

## Setup

Register the server in your MCP client configuration (`mcp.json`):

```json
{
  "mcpServers": {
    "adversarial-rea": {
      "command": "node",
      "args": ["/absolute/path/to/adversarial-rea/src/mcp/main.js"],
      "env": {}
    }
  }
}
```

Requirements: Node.js `>= 22.0.0` and standard binary inspection utilities on `PATH` (`objdump`, `nm`, `strings`; `otool` on macOS).

## Tools

| Tool | Purpose | Key Arguments |
|------|---------|---------------|
| `analyze_binary` | One-shot overview: metadata, symbol counts, security posture, interesting strings, dangerous imports | `target_path`, `strings_min_len` |
| `get_symbols` | Symbols: `all` / `imports` / `exports` / `functions`, with optional regex filter | `target_path`, `type`, `filter` |
| `get_strings` | Extract and classify strings (credentials, URLs, paths, crypto material, …) | `target_path`, `min_length`, `interesting_only`, `category` |
| `check_security` | Mitigations (PIE, NX, canary, RELRO, FORTIFY) + 0–100 score + hardening recommendations | `target_path` |
| `disassemble` | Disassemble entire binary or a specific function | `target_path`, `function`, `limit` |
| `get_sections` | List binary sections with sizes and executable/data attributes | `target_path` |
| `get_headers` | Architecture, entry point, and format header details | `target_path` |
| `find_dangerous_patterns` | Scan imports, strings, and security posture for vulnerability patterns tagged with CWE and severity | `target_path` |

`target_path` is required for every tool.

## Operational Loop: Extraction → Correlation → Findings

1. **Extraction** — The MCP client invokes `adversarial-rea` tools; the server executes `objdump`/`nm`/`strings`/`otool` and returns structured JSON (symbols, strings, sections, mitigations, disassembly).
2. **Correlation** — Dangerous imports are cross-referenced against call sites, missing mitigations against exploitability, and classified strings against hardcoded-secret signatures.
3. **Findings** — CWE-tagged, severity-ranked observations are produced alongside actionable next steps (such as target functions to disassemble).
