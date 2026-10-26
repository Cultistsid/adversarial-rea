# Adversarial REA — MCP Server Guide

An MCP server that exposes bounded local native inspection and carrier metadata over stdio JSON-RPC 2.0. Imports and strings are review observations, not proof of a vulnerability. Decoded direct call instructions and selected byte-verified gadgets are local observations, but input flow and exploitability remain unknown.

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
| `get_symbols` | Symbols: `all` / `imports` / `exports` / `functions`, with optional literal substring filter | `target_path`, `type`, `filter` |
| `get_strings` | Extract and classify bounded strings; credential/key categories redacted by default | `target_path`, `min_length`, `interesting_only`, `category`, `reveal_sensitive` |
| `check_security` | Known/unknown mitigations (PIE, NX, canary, RELRO, FORTIFY); score is null if checks are incomplete | `target_path` |
| `disassemble` | Disassemble entire binary or a specific function | `target_path`, `function`, `limit` |
| `get_sections` | List binary sections with sizes and executable/data attributes | `target_path` |
| `get_headers` | Architecture, entry point, and format header details | `target_path` |
| `find_dangerous_patterns` | List unverified CWE-oriented import/string observations and mitigation signals; never a vulnerability verdict | `target_path` |
| `trace_calls` | Decoded direct native call sites with target hashes; no inferred source-to-sink flow | `target_path`, `sinks` (exact names), `arch` (`host`, `all`, `x86_64`, `arm64`, `arm64e`), `limit` (1–100) |
| `find_gadget_candidates` | ELF64 x86_64 two-instruction candidates checked against executable file bytes; no runtime address or reachability claim | `target_path`, `limit` (1–100) |
| `inspect_carrier` | Bounded directory/section/header metadata for APK/IPA/JAR/ZIP, ASAR, Wasm, JS/text, PE, firmware and `.app` bundles; no unpacking or execution | `target_path`, `limit` (1–200) |

`target_path` is required for every tool. The eight older native tools, `trace_calls`, and `find_gadget_candidates` still reject nonnative content. `inspect_carrier` accepts metadata-only inputs and `.app` directories; it does **not** provide JavaScript ASTs, Wasm instructions, mobile manifests, firmware extraction, IPC mapping, or PE IAT call graphs. ZIP64/multi-disk archives are not parsed. Files are limited to 64 MiB; native commands have 15-second timeouts and 2 MiB output limits. MCP responses are capped at 64 KiB. Sensitive strings require `reveal_sensitive: true` in `get_strings`; keep that opt-in output local. Set `ADV_REA_ALLOWED_ROOTS=/absolute/path/to/targets` in the server environment to restrict readable target files; without it, any readable local regular file is in scope.

## Operational Loop: Extraction → Correlation → Findings

1. **Extraction** — Native tools return symbols, strings, mitigations, and bounded disassembly; `inspect_carrier` reads container indexes and headers without executing or unpacking entries.
2. **Review** — `trace_calls` reports decoded call instructions (and unresolved indirect calls) from a selected Mach-O slice or ELF/PE host tool. `find_gadget_candidates` verifies selected ELF64 x86_64 instruction sequences against original executable bytes. Both remain observations, not vulnerabilities.
3. **Evidence** — Before claiming a vulnerability or chain, independently establish attacker-controlled input, source-to-sink flow, mitigation state, and a reproducible trigger. No implemented tool derives those proofs; missing or truncated telemetry remains unknown.
