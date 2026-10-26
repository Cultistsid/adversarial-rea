---
name: adversarial-re
description: Adversarial reverse engineering skill for offensive security analysis. Deploys multi-agent swarms to enumerate attack surfaces, hunt vulnerabilities, and construct exploitation chains. Use for red team assessments, vulnerability research, and exploit development.
metadata:
  version: "1"
---

# Adversarial Reverse Engineering

Use this skill for offensive security analysis of binaries, applications, and systems.
This is NOT defensive security guidance - this is red team methodology.

## When to Use

- Target analysis for exploitation potential
- Vulnerability hunting in binaries/applications
- Attack surface enumeration
- Exploit chain construction
- Mitigation bypass research

## Operational Approach

### Phase 1: Attack Surface Enumeration

Deploy parallel agents to map:

1. **Entry Points**: Network listeners, file parsers, IPC handlers, plugin loaders
2. **Trust Boundaries**: Process, privilege, kernel, sandbox, network transitions
3. **Primitives**: Info leaks, write primitives, control flow hijacks, useful gadgets

```
Surface Score = Σ(vector_exploitability × 10) + Σ(boundary_bypass × weight) + Σ(primitive_usefulness × 20)
```

### Phase 2: Vulnerability Hunting

Swarm deployment with specialized roles:

| Role | Focus Areas |
|------|-------------|
| mem-corrupt | Buffer overflow, heap corruption, UAF, double-free, type confusion |
| logic-flaw | Auth bypass, race conditions, TOCTOU, state machine abuse |
| crypto-weak | Weak algorithms, key exposure, IV reuse, timing attacks |
| input-inject | Command injection, format strings, deserialization, path traversal |
| mitigation-bypass | ASLR leaks, DEP bypass, CFG evasion, canary bypass |
| priv-esc | Kernel vulns, driver exploits, service abuse, DLL hijack |
| protocol-abuse | Protocol confusion, smuggling, state desync, parser differentials |
| supply-chain | Dependency vulns, build tampering, signature bypass |

### Phase 3: Exploit Chain Construction

Chain templates available:

- **CODE_EXEC_LINUX**: info_leak → corruption → hijack → ROP → shellcode
- **CODE_EXEC_WINDOWS**: info_leak → corruption → CFG_bypass → hijack → ROP → shellcode
- **PRIV_ESC_LINUX**: kernel_leak → exploit → cred_overwrite → root
- **PRIV_ESC_WINDOWS**: kernel_leak → exploit → token_steal → SYSTEM
- **SANDBOX_ESCAPE**: sandbox_break → IPC_abuse → broker_exploit → escape
- **AUTH_BYPASS**: enum → bypass → session_forge → access

## Hunting Patterns

Critical patterns always included:

| Pattern | CWE | Indicators |
|---------|-----|------------|
| Unchecked Bounds | CWE-120 | memcpy, strcpy, sprintf, gets, read, recv |
| Integer Overflow | CWE-190 | malloc, calloc, size_t, multiplication |
| Use After Free | CWE-416 | free, delete, release, destroy, close |
| Double Free | CWE-415 | free, delete, error path, cleanup |
| Type Confusion | CWE-843 | cast, union, variant, vtable |
| Command Injection | CWE-78 | system, exec, popen, shell, cmd |
| Format String | CWE-134 | printf, sprintf, fprintf, syslog |
| Hardcoded Secret | CWE-798 | key, secret, password, const, static |
| Auth Bypass | CWE-287 | login, auth, session, token |

## Evidence Collection

All findings require:

```json
{
  "id": "unique-finding-id",
  "class": "vulnerability-class",
  "severity": "critical|high|medium|low",
  "location": "function/offset/file",
  "trigger": {
    "input": "what triggers it",
    "conditions": ["required state"],
    "steps": ["reproduction steps"]
  },
  "exploitation": {
    "technique": "how to exploit",
    "constraints": ["limitations"],
    "mitigations_to_bypass": ["ASLR", "DEP"],
    "reliability": "high|medium|low"
  },
  "confidence": 0.0-1.0,
  "evidence": ["supporting analysis"]
}
```

## Reporting Format

```
TARGET: <path/type>
ATTACK SURFACE SCORE: <0-100>

CRITICAL FINDINGS:
• [CWE-XXX] <class> at <location>
  Trigger: <how to trigger>
  Exploitation: <technique>
  Reliability: <high|medium|low>

EXPLOIT CHAINS:
• <chain-name>
  Feasibility: <percentage>
  Stages: <stage1> → <stage2> → ...
  Effort: <estimated hours/days>

RECOMMENDATIONS:
• <next analysis steps>
• <additional research needed>
```

## Integration with REA

This skill extends REA's defensive workflows with offensive capabilities:

1. REA's evidence collection → Adversarial primitive mapping
2. REA's provider routing → Parallel agent deployment
3. REA's tool composition → Exploit chain construction

Use REA tools for static analysis, then layer adversarial analysis on top.
