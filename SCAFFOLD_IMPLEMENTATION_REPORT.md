# Scaffold prototype: corrected implementation status

This is a retrospective status record, not a completion certificate. An earlier
untracked draft claimed five complete, implementation-ready templates, automatic
primitive extraction from imports, runnable exports, and a tested end-to-end
integration. Those claims were not supported by the repository. Its displayed
addresses, payloads, and metrics were examples, not observations of a target.
The old draft's 2024 date also does not match this repository's 2026 commit
history; it should not be used as evidence of authorship or delivery.

## What the tree actually contains

| Component | Supported behavior | Boundary |
| --- | --- | --- |
| `src/core/exploit-scaffolds.js` | Four stored draft templates: `CODE_EXEC_LINUX`, `CODE_EXEC_WINDOWS`, `PRIV_ESC_LINUX`, `SANDBOX_ESCAPE` | Placeholders remain; no tested runnable output. `PRIV_ESC_WINDOWS` and `AUTH_BYPASS` have no scaffold template. |
| `TelemetryMapper` | Maps findings only when IDs resolve to matching, non-truncated local evidence records | Imports, symbols, strings, and model assertions alone do not establish a primitive. |
| `ScaffoldGenerator.generate()` | Returns `blocked` for unsupported templates, absent verified findings, or unresolved placeholders; otherwise labels output `review_only` | It does not verify that generated text is executable or establishes exploitability. |
| `ExploitChainBuilder` | Defines six chain concepts; checks required findings, stage references, and an observed trace before reporting an evidence-complete review | Ordinary analyses lack native def-use and observed native trigger producers; no verified chain is demonstrated by the suite. |
| `BinaryAnalyzer` / `CallSiteExtractor` | Bounded native telemetry and direct call-site observations | A decoded call is not controlled input, reachability, or a vulnerability. |
| `FlowFixtureInspector` | Replays explicit `.flow.json` source/copy/literal/validation/sink steps twice in memory and emits fixture-scoped hashes and evidence | Never runs the target binary; fixture-only evidence is excluded from native finding/chain promotion. |
| `CarrierInspector` | Metadata for PE, ZIP-based packages, ASAR, Wasm, firmware and bundles | No archive extraction, certificate verification, firmware filesystem parsing, or native argument data-flow analysis. |

The example at `examples/scaffold-generation-example.js` inspects a native
file, passes **zero** verified findings to the generator, and reports its
blocked status. It does not write an exploit or test an attack. The code retains
historical draft template strings, but this report does not certify them.

## Evidence discipline

A native claim needs matching artifact SHA-256, producer/version, location,
explicit truncation state, and independently substantiated flow and trigger
observations. The implemented gate checks ledger IDs, metadata and record
kinds; it does not authenticate an arbitrary caller-supplied ledger or
independently prove a record's semantics. Native call-site records alone do
not satisfy that gate.
`inspect_flow_fixture` emits `fixture-def-use` and `fixture-trace` kinds, not
native `def-use` or `trace`; even the direct fixture case cannot promote a
finding for a binary. Unknown mitigations remain unknown.

Reproducing a fixture sink only shows the interpreter follows its declared
steps. It is **not** a native crash, control-flow change, offset measurement,
or vulnerability trigger. This distinction is asserted in tests.

## Verification and remaining work

Run `npm run test:all` for the complete unit, live-binary, and stdio MCP
suite. For a fixture-only example, run:

```bash
node bin/cli.js inspect test/fixtures/flow-direct.flow.json --flow-fixture
```

The output withholds the raw input.
Native source-to-sink provenance, branch/alias/sanitizer analysis, an observed
native trigger harness, PE IAT/IOCTL semantics, and deeper package/firmware
parsers remain out of scope. See [README.md](README.md),
[MCP_USAGE.md](MCP_USAGE.md), [docs/EXPLOIT_SCAFFOLDS.md](docs/EXPLOIT_SCAFFOLDS.md),
and [docs/handoff/README.md](docs/handoff/README.md) for the currently
supported surfaces and unimplemented design contracts.
