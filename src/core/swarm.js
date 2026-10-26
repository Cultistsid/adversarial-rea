/**
 * Agent Swarm Orchestrator
 *
 * Deploys parallel agents for multi-vector analysis.
 * Each agent specializes in a different exploitation domain.
 */

import Anthropic from '@anthropic-ai/sdk';
import pLimit from 'p-limit';
import { BinaryAnalyzer } from './binary-analyzer.js';

const AGENT_ROLES = {
  MEMORY_CORRUPTION: {
    id: 'mem-corrupt',
    name: 'Memory Corruption Hunter',
    focus: ['buffer-overflow', 'heap-corruption', 'use-after-free', 'double-free', 'type-confusion'],
    prompt: `You are an expert memory corruption vulnerability researcher.
Focus on: stack/heap buffer overflows, use-after-free, double-free, type confusion, integer overflows leading to memory corruption.
Analyze functions for unsafe memory operations, missing bounds checks, incorrect size calculations.
Report: vulnerability class, trigger conditions, exploitability assessment, suggested exploitation technique.`
  },

  LOGIC_FLAW: {
    id: 'logic-flaw',
    name: 'Logic Flaw Analyst',
    focus: ['auth-bypass', 'race-condition', 'toctou', 'state-machine-abuse'],
    prompt: `You are an expert logic vulnerability researcher.
Focus on: authentication bypasses, authorization flaws, race conditions, TOCTOU, state machine violations.
Trace control flow for logic errors, missing checks, incorrect state transitions.
Report: vulnerability class, bypass conditions, attack scenario, proof-of-concept approach.`
  },

  CRYPTO_WEAKNESS: {
    id: 'crypto-weak',
    name: 'Cryptographic Weakness Finder',
    focus: ['weak-crypto', 'key-exposure', 'iv-reuse', 'padding-oracle', 'timing-attack'],
    prompt: `You are an expert cryptographic vulnerability researcher.
Focus on: weak algorithms, hardcoded keys, IV reuse, padding oracles, timing side-channels, PRNG weaknesses.
Identify cryptographic implementations, key storage, random number generation.
Report: weakness class, exploitation feasibility, key recovery potential, mitigation bypass.`
  },

  INPUT_INJECTION: {
    id: 'input-inject',
    name: 'Input Injection Specialist',
    focus: ['command-injection', 'sql-injection', 'format-string', 'deserialization'],
    prompt: `You are an expert input validation vulnerability researcher.
Focus on: command injection, SQL injection, format strings, deserialization, path traversal, SSRF.
Trace user input to dangerous sinks, identify missing sanitization.
Report: injection point, payload construction, impact assessment, filter bypass techniques.`
  },

  MITIGATION_BYPASS: {
    id: 'mitigation-bypass',
    name: 'Mitigation Bypass Expert',
    focus: ['aslr-leak', 'dep-bypass', 'cfg-bypass', 'sandbox-escape', 'canary-bypass'],
    prompt: `You are an expert exploit mitigation bypass researcher.
Focus on: ASLR info leaks, DEP/NX bypass (ROP/JOP), CFG/CET evasion, stack canary bypass, sandbox escapes.
Identify information leak primitives, gadget availability, mitigation configurations.
Report: bypass technique, required primitives, gadget chains, reliability assessment.`
  },

  PRIVILEGE_ESCALATION: {
    id: 'priv-esc',
    name: 'Privilege Escalation Hunter',
    focus: ['kernel-vuln', 'driver-exploit', 'service-abuse', 'dll-hijack', 'setuid-abuse'],
    prompt: `You are an expert privilege escalation researcher.
Focus on: kernel vulnerabilities, driver exploits, service misconfigurations, DLL hijacking, setuid abuse.
Identify privilege boundaries, cross-boundary data flows, capability transitions.
Report: escalation path, required access, exploitation technique, persistence opportunity.`
  },

  PROTOCOL_ABUSE: {
    id: 'protocol-abuse',
    name: 'Protocol Abuse Analyst',
    focus: ['protocol-confusion', 'state-desync', 'parsing-differential', 'smuggling'],
    prompt: `You are an expert protocol vulnerability researcher.
Focus on: protocol confusion, request smuggling, state desynchronization, parsing differentials.
Analyze protocol implementations, state machines, parser behavior.
Report: protocol weakness, attack vector, chaining potential, detection evasion.`
  },

  SUPPLY_CHAIN: {
    id: 'supply-chain',
    name: 'Supply Chain Analyzer',
    focus: ['dependency-vuln', 'build-tampering', 'signature-bypass', 'update-hijack'],
    prompt: `You are an expert supply chain security researcher.
Focus on: vulnerable dependencies, build process weaknesses, code signing bypasses, update mechanisms.
Enumerate dependencies, verify signatures, analyze update channels.
Report: vulnerable component, exploitation path, persistence mechanism, detection indicators.`
  }
};

export class AgentSwarm {
  constructor(config) {
    this.config = config;
    this.client = new Anthropic();
    this.analyzer = new BinaryAnalyzer();
    this.agents = new Map();
    this.limit = pLimit(config.maxAgents || 8);
    this.results = [];
  }

  async deploy(target, mission) {
    const roles = this.selectRolesForMission(mission, target.type);
    const deployments = [];

    console.log(`[SWARM] Deploying ${roles.length} agents for mission: ${mission.objective}`);

    // Extract binary context once, shared across all agents
    let binaryContext = '';
    try {
      const data = await this.analyzer.analyze(target.path);
      binaryContext = `BINARY ANALYSIS DATA (real extracted data):
- Type: ${data.target.type}, Size: ${data.target.size} bytes
- Security: PIE=${data.security.pie}, NX=${data.security.nx}, Canary=${data.security.canary}, RELRO=${data.security.relro}, Fortify=${data.security.fortify}
- Imports (${data.imports.length}): ${data.imports.slice(0, 60).map(s => s.name).join(', ')}
- Interesting strings: ${data.strings.filter(s => s.interesting).slice(0, 20).map(s => `"${s.value}" [${s.category}]`).join(', ')}
- Sections: ${data.sections.map(s => `${s.name}(${s.size}b)`).join(', ')}`;
    } catch (e) {
      binaryContext = `Target: ${target.path} (binary extraction failed: ${e.message})`;
    }

    for (const role of roles) {
      deployments.push(
        this.limit(() => this.deployAgent(role, target, mission, binaryContext))
      );
    }

    const results = await Promise.allSettled(deployments);

    return {
      mission,
      target,
      agentResults: results.map((r, i) => ({
        role: roles[i].id,
        status: r.status,
        findings: r.status === 'fulfilled' ? r.value : null,
        error: r.status === 'rejected' ? r.reason.message : null
      })),
      timestamp: new Date().toISOString()
    };
  }

  selectRolesForMission(mission, targetType) {
    const allRoles = Object.values(AGENT_ROLES);

    if (mission.roles) {
      return allRoles.filter(r => mission.roles.includes(r.id));
    }

    // Auto-select based on target type
    const roleMap = {
      'pe': ['mem-corrupt', 'mitigation-bypass', 'priv-esc', 'input-inject'],
      'pe-driver': ['mem-corrupt', 'priv-esc', 'mitigation-bypass'],
      'elf': ['mem-corrupt', 'mitigation-bypass', 'priv-esc', 'input-inject'],
      'android': ['logic-flaw', 'crypto-weak', 'input-inject', 'supply-chain'],
      'ios': ['logic-flaw', 'crypto-weak', 'mitigation-bypass'],
      'electron': ['input-inject', 'logic-flaw', 'supply-chain', 'protocol-abuse'],
      'webassembly': ['mem-corrupt', 'logic-flaw', 'crypto-weak'],
      'firmware': ['mem-corrupt', 'crypto-weak', 'priv-esc', 'protocol-abuse']
    };

    const selectedIds = roleMap[targetType] || allRoles.map(r => r.id);
    return allRoles.filter(r => selectedIds.includes(r.id));
  }

  async deployAgent(role, target, mission, binaryContext = '') {
    const systemPrompt = this.buildAgentPrompt(role, target, mission);

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: 8192,
      system: systemPrompt,
      messages: [{
        role: 'user',
        content: this.buildAnalysisRequest(role, target, mission, binaryContext)
      }]
    });

    return this.parseAgentResponse(role, response);
  }

  buildAgentPrompt(role, target, mission) {
    return `${role.prompt}

TARGET CONTEXT:
- Type: ${target.type}
- Path: ${target.path}
- Mission: ${mission.objective}

REPORTING FORMAT:
Return findings as structured JSON with:
{
  "findings": [
    {
      "id": "unique-finding-id",
      "class": "vulnerability-class",
      "severity": "critical|high|medium|low",
      "location": "function/offset/file",
      "description": "what the vulnerability is",
      "trigger": "how to trigger it",
      "exploitation": "how to exploit it",
      "mitigations": ["what protections exist"],
      "bypass": "how to bypass mitigations if applicable",
      "confidence": 0.0-1.0,
      "evidence": ["supporting analysis"]
    }
  ],
  "attack_surface": ["identified attack vectors"],
  "recommendations": ["next analysis steps"]
}`;
  }

  buildAnalysisRequest(role, target, mission, binaryContext = '') {
    return `I am writing a penetration testing report. Review this binary for ${role.focus.join(', ')} security issues.

Target: ${target.path}
${binaryContext}

Review objective: ${mission.objective}
Context: ${JSON.stringify(mission.context || {}, null, 2)}

${mission.additionalInstructions || ''}

Document findings with severity, location, root cause, and remediation guidance. Prioritize by severity.`;
  }

  parseAgentResponse(role, response) {
    const content = response.content?.find(b => b.type === 'text' || typeof b.text === 'string')?.text || '';

    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return {
          role: role.id,
          parsed: JSON.parse(jsonMatch[0]),
          raw: content
        };
      }
    } catch (e) {
      // Fall through to raw return
    }

    return {
      role: role.id,
      parsed: null,
      raw: content
    };
  }
}

export { AGENT_ROLES };
