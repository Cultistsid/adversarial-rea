# Code review: pre-fix snapshot and current status

> [!NOTE]
> This review records an older snapshot, **before** commit `4ef498e`.
> Historical line numbers and statements about uncommitted files refer to
> that snapshot, not to the current tree. Do not treat the findings below as
> presently reproducible without rechecking the relevant implementation.

Scope: `src/core/`, `src/index.js`, `bin/cli.js`, MCP definitions, tests and
public claims. At review time, the scaffold and chain drafts were being
evaluated as uncommitted work. The reviewer's historical 71/71 test result
does **not** describe the current suite. Run `npm run test:all` instead.

## Verified changes since the snapshot

| Historical issue | Current behavior |
| --- | --- |
| Shell interpolation in native tool calls | Uses argument-array subprocesses with time/output/input bounds; regression tests cover literal shell characters. |
| Imports converted into verified primitives | Imports remain candidate observations; ledger-gated findings require local records, and unresolved scaffold placeholders return `blocked`. |
| Raw secret-like strings in remote prompts | Structural summaries omit raw string values by default; `get_strings` reveals sensitive categories only with an explicit local opt-in. |
| Broken chain/CLI wiring and inflated scoring | Shared analysis snapshots, supported-template checks, stage coverage and `--no-chain` / hunt pattern flags have regression tests; model assertions are not sufficient evidence. |
| MCP manifest drift and exaggerated format support | `server.json` matches 12 registered local tools. PE, package and firmware inspection returns bounded **metadata**, not deep code or signature analysis. |
| No source-to-sink fixture cases | `inspect_flow_fixture` replays bounded synthetic steps only. Fixture evidence is excluded from native finding and chain gates. |

Native argument def-use provenance, observed native triggers, PE IAT/IOCTL
analysis, firmware extraction, and portable decoding remain unimplemented.
The current tree emits native call-site observations and constrained gadget
candidates; neither proves a vulnerability. Historical findings below remain
as a record of why these boundaries matter.

## Findings (highest severity first)

### P0 - MCP inputs reach a shell

`src/core/binary-analyzer.js:89-94,108-117,135-175,231-241,275-304,334-344`
inserts `targetPath`, `minLen` and `options.function` into `execSync` shell
strings. The MCP dispatcher forwards client-supplied values
(`src/mcp/server.js:166-183,189-192,238-241,305-312`). Double-quoting a
filename does not neutralize shell substitutions; the numeric and function
interpolations are not quoted at all. A malicious tool request can run an
arbitrary local command as the MCP server user, rather than merely analyze a
file. Replace with `execFile`/`spawn` and argv arrays, remove shell pipelines,
bound time/output/inputs, reject non-files, and test literal shell characters
in filenames and option values.

### P1 - Imports are misrepresented as verified exploitation primitives

`src/core/exploit-scaffolds.js:690-759` labels each `printf` import an
`info_leak` and each `strcpy` import a `stack_overflow` regardless of whether
it is called, how its arguments are controlled, or whether any overflow
exists. `:885-896` chooses the first technique when *no* primitive matches.
The generated output calls these "concrete" methods and reports false
feasibility. An inert probe with only `printf` and `strcpy` imports and zero
vulnerabilities returned both "primitives"; an empty list still selected
`format_string`. Keep imports as observations; require call-site, def-use and
trigger evidence before creating a vulnerability or usable stage.

### P1 - Secrets are sent to the model; missing extraction is not a hard stop

`src/core/attack-surface.js:50-65,98-149` embeds up to 30 "interesting"
strings in a prompt sent to `messages.create`; this category includes
credential-like strings and crypto material. `src/core/swarm.js:112-122,168-180`
and `src/core/vuln-hunter.js:198-256` transmit more binary-derived content
without redaction. On extraction failure, `attack-surface.js:64-66` and
`vuln-hunter.js:128-134` still proceed with remote reasoning and no reliable
ground truth. Do not send secrets by default: redact or hash sensitive
values, make remote disclosure opt-in and inspectable, and fail closed (or
return explicitly marked incomplete results) when extraction fails.

### P1 - The scaffold integration cannot deliver its advertised result

`src/index.js:55-61` calls `exploitChain.build(target, vulnerabilities)` but
the new scaffold path requires `binaryAnalysis` and `attackSurface`
(`src/core/exploit-chain.js:90-111`). Even the new path calls `buildChain`
*without* `binaryAnalysis` at `:95`, so prompts never see the telemetry
summary added at `:147-178`. Of six chain templates in `:11-79`, only four
exist in `src/core/exploit-scaffolds.js:8-685`; selecting
`PRIV_ESC_WINDOWS` or `AUTH_BYPASS` will throw if generation is wired. Pass
one shared analysis snapshot through the pipeline and define explicit
unsupported-template behavior before advertising generated scaffolds.

### P1 - Two scaffold templates crash; generated code remains incomplete

`ScaffoldGenerator.replacePlaceholders` always calls `selectTechnique` with
`stageData.techniques` (`src/core/exploit-scaffolds.js:864-895`), but
`PRIV_ESC_LINUX.stage4_root_shell` and `SANDBOX_ESCAPE.stage4_escape` omit
that field. An inert `generate()` call throws `techniques is not iterable`
for both. `CODE_EXEC_LINUX` returned 29 unresolved `{PLACEHOLDERS}` with
empty evidence. Those outputs are not runnable Python/C/JS scripts; the
example prints "Run with: python3 ..." without writing any file
(`examples/scaffold-generation-example.js:797-813`). Validate required
template fields, return a blocked draft with missing facts, and never claim a
script is runnable until syntax and fixture checks pass.

### P1 - Chain selection and scoring inflate feasibility

`src/core/exploit-chain.js:113-144` treats any **one** of
`required_primitives` as sufficient (`some`), then matches substrings anywhere
in a serialized finding rather than checked IDs/evidence. `:229-241` grants
a 20% score bonus for possessing a scaffold: a completely mapped,
model-scored `1.0` chain scores `120/100`. `:92-110` trusts the model's
`feasible` flag without stage validation. Require every mandatory stage and
mitigation prerequisite, report missing stages, and cap/avoid numerical
feasibility claims until calibrated against real observations.

### P1 - Security posture can be wrong or silently incomplete

`src/core/binary-analyzer.js:286-304` obtains ELF RELRO data with
`objdump -p ... | grep -i relro`. A `BIND_NOW` flag on another line is removed
by that grep, so the subsequent `dynamic.includes('bind_now')` cannot detect
full RELRO in the normal case. `:135-189` silently swallows extraction errors
and truncates `nm`/`strings` to the first 1000/500 lines, but `:322-324`
labels fewer than 10 symbols "stripped." Missing tool output is not evidence
of missing mitigations. Parse the full relevant headers, return `unknown`
for failed/unsupported checks, and surface `truncated`/tool errors to MCP.

### P2 - CLI options and tool manifest do not match reality

`bin/cli.js:40-59` accepts `--no-chain`, but `src/index.js:55-61` ignores
`buildChains`. `bin/cli.js:140-157` declares `--patterns`/`--critical-only`
without ever using `options.patterns` or `options.criticalOnly`. The
`server.json:11-32` manifest lists five orchestration tools not present in
the eight-tool MCP registry (`src/mcp/server.js:10-113`). Wire flags through
or remove them; generate the manifest from the runtime tool registry.

### P2 - README/examples claim capabilities not established by tests

`README.md:129-143,175-180,183-267` describes deep PE, APK, ASAR, firmware,
ROP and exploit-chain analysis, but `BinaryAnalyzer` uses native `file`,
`objdump`, `nm`, `strings` and `otool` on a single input file and does not
parse APK/ASAR contents. `docs/EXPLOIT_SCAFFOLDS.md:42-70` and
`docs/assets/adversarial-hero.svg` show specific exploit offsets and chain
scores with no corresponding tested fixture. Replace demonstration data
with labeled illustrations and publish supported/experimental/unimplemented
capabilities separately. An inaccurate showcase undermines the central
"ground truth" claim.

## Test gaps to hand off

1. Add a malicious-literal-filename test and bounded-input tests around every
   MCP path/option before expanding tool exposure.
2. Fixture-test a benign binary importing `printf` and `strcpy`, plus a real
   observed input-to-sink case; the first must not be a verified vulnerability.
3. Add table-driven tests across **all six** chain templates, including
   missing technique fields and absent telemetry; no generator should throw
   for unsupported templates during an ordinary analysis run.
4. Fixture-test hardening on ELF full/partial/no RELRO and Mach-O, and
   distinguish unsupported checks from `false`.
5. Assert CLI flags change behavior, `server.json` matches MCP `ListTools`,
   and every public command/example can be run as shown without hidden steps.
6. Use synthetic embedded credentials and a missing/broken analysis tool to
   verify redaction and fail-closed/incomplete-result behavior.

The original review was review-only at the time. Subsequent work changed
production code and test coverage; do not interpret the older "uncommitted"
or "not changed" descriptions as claims about the present tree. See
[`handoff/README.md`](handoff/README.md) for design-only contracts and
[`../MCP_USAGE.md`](../MCP_USAGE.md) for the current exposed inspection tools.
