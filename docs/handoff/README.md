# Adversarial analysis handoff

These are **design-only skeletons**, not features. Nothing in `docs/handoff/`
is wired into `src/`, the CLI, or MCP. Methods fail explicitly if called.
The separate scaffold implementation is now gated on local evidence and
returns blocked drafts rather than inventing primitives or exportable code.
The P0 subprocess boundary, format rejection, response limits, redaction,
CLI flags, and manifest alignment are implemented. Distinct production modules
now emit observed direct call sites and byte-verified ELF64 x86_64 gadget
candidates; `inspect_carrier` previews archive and package metadata only.
The skeletons below remain **unimplemented interfaces** for general
source-to-sink flow, relocation permissions, portable gadget decoding, and
reproducible trigger traces. The review in [`../CODE_REVIEW.md`](../CODE_REVIEW.md)
records the pre-fix snapshot.

## Why the previous sketches needed correction

- An imported function is an attack-surface indicator, not evidence of a
  vulnerability or an attacker-controlled primitive. A `printf` import is not
  a format-string leak; a `strcpy` import is not necessarily an overflow.
- `stackFrameBytes + 8` is **not** the offset to a saved return address. That
  offset depends on the actual overwritten object, compiler layout, ABI,
  optimizations, and a measured input-to-crash mapping.
- Calls in the same function do not establish a source-to-sink flow. Track
  def-use edges for the relevant sink argument, including aliases, checks,
  sanitizers, control flow, and interprocedural calls.
- Text from `objdump -d` is format/tool/architecture dependent; `head`-limited
  disassembly is incomplete. Gadget candidates require instruction decoding
  from bytes in executable sections, not substring matches over output text.
- Non-full ELF RELRO is not proof of a writable target; runtime permissions
  and binding state matter. Mach-O lazy pointers and PE IAT are different
  structures, not ELF GOT entries.
- A generated script must never fill unknown offsets, gadgets, addresses,
  inputs or mitigations with guesses. Produce a **blocked draft** until there
  is an observed trigger and sufficient evidence.

## Files and expected interfaces

| Skeleton | Input | Output when implemented |
| --- | --- | --- |
| `contracts.js` | Target hash, provider and bounded location | Shared provenance types and an explicit not-implemented error |
| `xref-slicer.js` | Typed instruction stream + symbol resolver + exact sink names | Direct/indirect call sites, argument observations and evidence IDs |
| `gadget-finder.js` | Bounded byte reader + executable ranges + architecture-specific decoder | Re-decoded candidate gadgets as image offsets, with constraints |
| `taint-correlator.js` | Def-use graph + labeled sources, sinks, barriers | Bounded source-to-argument paths or explicit missing evidence |
| `relocation-targeter.js` | Relocations + segments + optional runtime permissions | Table slots and known/unknown writability; no "arbitrary write" claim |
| `repro-draft.js` | Verified finding + observed trigger and optional measured offset | Inert reproduction checklist or blocked draft with missing facts |

`TargetImage.sha256` and `EvidenceRef.targetSha256` must match. Preserve
provider version, exact location, evidence ID and explicit truncation state.
Missing data is `null` or `unknown`, never `false`.

## Implementation sequence for the next engineer

1. **P0 (complete): Bound the existing MCP extraction surface.** The analyzer
   uses argument-array subprocesses with time, output, path/file type, and
   numeric bounds; shell-metacharacter and resource-limit tests cover it.
2. **Input and provider layer (partial).** Native signatures are detected by
   magic and container indexes are read separately. ZIP64, scripts' ASTs,
   firmware extraction, and PE relocation/IOCTL parsing remain unimplemented.
3. **Call-site evidence (partial).** `src/core/call-sites.js` resolves decoded
   direct calls through PLT/stubs and records unresolved indirect calls. It
   does not determine argument provenance or prove reachability.
4. **Flow evidence.** Implement `TaintCorrelator` with def-use propagation
   from a controlled input to the *argument* of a sink, plus conditional
   barriers and bounded interprocedural traversal.
5. **Optional exploitation constraints (partial).** `src/core/gadget-candidates.js`
   checks short ELF64 x86_64 sequences against executable bytes. Mach-O/PE
   gadget decoding, relocation permissions, CET/BTI/PAC landing checks, and
   runtime addresses are not implemented. Never equate a candidate with an
   attacker-controlled primitive.
6. **Report truthfully.** Redact secret-like strings before any model call;
   require evidence IDs for every stage of a chain. Mark unsupported and
   missing stages `unknown`/`blocked`; allow `ReproDraft` only for observed
   local triggers. Do not score scaffold existence as exploit feasibility.
7. **Wire MCP and CLI last.** Add tools only after the contracts have fixture
   tests and are implemented. Update `server.json` to match the registered
   tool list and correct unsupported claims in the README.

## Acceptance cases

- A binary that imports `printf` but calls it with a constant format yields
  an import observation, **no** verified format-string vulnerability.
- A binary that imports `strcpy` without an observed source-to-destination
  overflow yields `candidate`/`unknown`, not an exploit chain.
- A known input-to-sink path with a sanitizer does not yield an unqualified
  direct exploit path; contradictory evidence is retained.
- An unresolved indirect call, missing symbols, or truncated disassembly
  produces an explicit `unknown`/`truncated` result instead of "safe".
- ELF full/partial/no RELRO, Mach-O lazy bindings, and PE IAT are covered by
  separate fixture tests. Unsupported formats do not masquerade as ELF.
- Gadget offsets are verified against original executable bytes and
  architecture/landing constraints. PIE offsets are not runtime addresses.
- A control offset must be measured from a reproducible local crash/trace,
  never calculated from a prologue's stack allocation.
- No scaffold, CLI option, or reported score says "feasible" merely because a
  template exists or a model returned `feasible: true`.
- Credential-like strings in a binary stay local by default, and extraction
  failures produce an explicit incomplete result rather than model guesses.

Run `for file in docs/handoff/*.js; do node --check "$file"; done` and
`npm run test:all` on the current tree. Green tests for native observations
do not certify the remaining skeletons or an exploit chain.
