/**
 * Attack Surface Enumerator
 *
 * Aggressive multi-vector attack surface discovery.
 * Maps all potential entry points, trust boundaries, and exploitation primitives.
 */

import Anthropic from '@anthropic-ai/sdk';
import { BinaryAnalyzer } from './binary-analyzer.js';

const ATTACK_VECTORS = {
  // Network-facing
  NETWORK_LISTENER: { severity: 'high', class: 'network', exploitability: 0.8 },
  IPC_ENDPOINT: { severity: 'high', class: 'ipc', exploitability: 0.7 },
  RPC_HANDLER: { severity: 'high', class: 'rpc', exploitability: 0.8 },

  // File-based
  FILE_PARSER: { severity: 'high', class: 'parser', exploitability: 0.9 },
  CONFIG_LOADER: { severity: 'medium', class: 'config', exploitability: 0.6 },
  PLUGIN_LOADER: { severity: 'critical', class: 'plugin', exploitability: 0.9 },

  // Memory
  HEAP_ALLOCATOR: { severity: 'critical', class: 'memory', exploitability: 0.7 },
  BUFFER_HANDLER: { severity: 'critical', class: 'memory', exploitability: 0.8 },
  SERIALIZER: { severity: 'high', class: 'memory', exploitability: 0.8 },

  // Crypto
  KEY_DERIVATION: { severity: 'high', class: 'crypto', exploitability: 0.5 },
  SIGNATURE_VERIFY: { severity: 'critical', class: 'crypto', exploitability: 0.6 },
  RANDOM_GENERATOR: { severity: 'high', class: 'crypto', exploitability: 0.4 },

  // Privilege
  PRIVILEGE_CHECK: { severity: 'critical', class: 'authz', exploitability: 0.7 },
  CAPABILITY_GRANT: { severity: 'critical', class: 'authz', exploitability: 0.8 },
  SANDBOX_BOUNDARY: { severity: 'critical', class: 'sandbox', exploitability: 0.6 },

  // State
  STATE_MACHINE: { severity: 'medium', class: 'logic', exploitability: 0.6 },
  CACHE_HANDLER: { severity: 'medium', class: 'logic', exploitability: 0.5 },
  SESSION_MANAGER: { severity: 'high', class: 'session', exploitability: 0.7 }
};

export class AttackSurfaceEnumerator {
  constructor(config) {
    this.config = config;
    this.client = new Anthropic();
    this.analyzer = new BinaryAnalyzer();
  }

  async extractBinaryContext(target) {
    try {
      const data = await this.analyzer.analyze(target.path);
      const dangerousNames = ['strcpy','sprintf','gets','system','popen','execve','printf','fprintf','malloc','free','realloc'];
      const dangerous = data.imports
        .filter(s => dangerousNames.some(d => (s.name?.replace(/^_+/,'') || '').replace(/@.*$/,'') === d))
        .map(s => s.name).join(', ') || 'none detected';
      return `BINARY ANALYSIS DATA (real extracted data):
- Type: ${data.target.type}, Size: ${data.target.size} bytes
- Security: PIE=${data.security.pie}, NX=${data.security.nx}, Canary=${data.security.canary}, RELRO=${data.security.relro}, Fortify=${data.security.fortify}
- Imports (${data.imports.length} total): ${data.imports.slice(0, 50).map(s => s.name).join(', ')}
- Interesting strings (${data.strings.filter(s => s.interesting).length}): ${data.strings.filter(s => s.interesting).slice(0, 30).map(s => `"${s.value}" [${s.category}]`).join(', ')}
- Sections: ${data.sections.map(s => `${s.name}(${s.size}b)`).join(', ')}
- Dangerous imports: ${dangerous}`;
    } catch (e) {
      return `Target: ${target.path} (binary extraction failed: ${e.message})`;
    }
  }

  async enumerate(target) {
    const surface = {
      target,
      vectors: [],
      boundaries: [],
      primitives: [],
      dependencies: [],
      mitigations: [],
      score: 0,
      timestamp: new Date().toISOString()
    };

    const binaryContext = await this.extractBinaryContext(target);

    // Parallel enumeration phases
    const [vectors, boundaries, primitives] = await Promise.all([
      this.enumerateVectors(target, binaryContext),
      this.identifyBoundaries(target, binaryContext),
      this.findPrimitives(target, binaryContext)
    ]);

    surface.vectors = vectors;
    surface.boundaries = boundaries;
    surface.primitives = primitives;
    surface.score = this.calculateAttackScore(surface);

    return surface;
  }

  async enumerateVectors(target, binaryContext = '') {
    const prompt = `You are a security engineer reviewing a ${target.type} binary for a security assessment. Analyze the binary data below and identify input-handling functions and data processing paths that a security reviewer should examine.

${binaryContext}

For each input handler or data processing function found in the imports/symbols above, document it. Focus on functions that accept external data (network, files, user input, IPC).

Return ONLY a JSON array, no explanation:
[{
  "vector_type": "one of: ${Object.keys(ATTACK_VECTORS).join(', ')}",
  "entry_point": "function name from the imports listed above",
  "input_type": "string|buffer|integer|file|network|etc",
  "trust_level": "untrusted|semi-trusted|trusted",
  "processing_chain": ["what happens to the data"],
  "vuln_potential": ["memory-safety|injection|logic|crypto"],
  "notes": "specific concern for this function"
}]`;

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    });

    return this.parseVectors(response);
  }

  async identifyBoundaries(target, binaryContext = '') {
    const prompt = `You are a security engineer reviewing a ${target.type} binary. Using the binary data below, identify where this program crosses privilege or trust boundaries.

${binaryContext}

Look for boundary transitions in the imports and strings: network calls, privilege-changing syscalls, IPC mechanisms, authentication functions, file permission operations.

Return ONLY a JSON array, no explanation:
[{
  "boundary_type": "process|privilege|kernel|sandbox|network|auth",
  "from_context": "lower-privilege or untrusted side",
  "to_context": "higher-privilege or trusted side",
  "crossing_mechanism": "function or mechanism used",
  "validation": "what validation exists at this boundary",
  "risk_level": "high|medium|low",
  "notes": "specific concern"
}]`;

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    });

    return this.parseBoundaries(response);
  }

  async findPrimitives(target, binaryContext = '') {
    const prompt = `You are a security engineer reviewing a ${target.type} binary for memory safety. Using the binary data below, identify memory safety concerns based on the functions imported.

${binaryContext}

For each memory-unsafe function in the imports above (strcpy, sprintf, gets, malloc, free, realloc, etc.), document the memory safety concern it represents.

Return ONLY a JSON array, no explanation:
[{
  "primitive_type": "memory-write|memory-read|info-disclosure|control-flow|allocation|deallocation",
  "location": "function name from the imports listed above",
  "trigger": "what input or condition would trigger the issue",
  "constraints": ["size constraint", "precondition"],
  "usefulness": "high|medium|low",
  "related_concerns": "other functions this interacts with",
  "notes": "specific memory safety concern"
}]`;

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    });

    return this.parsePrimitives(response);
  }

  getTextContent(response) {
    return response.content.find(b => b.type === 'text')?.text || '';
  }

  parseVectors(response) {
    try {
      const content = this.getTextContent(response) || '[]';
      const match = content.match(/\[[\s\S]*\]/);
      return match ? JSON.parse(match[0]) : [];
    } catch {
      return [];
    }
  }

  parseBoundaries(response) {
    try {
      const content = this.getTextContent(response) || '[]';
      const match = content.match(/\[[\s\S]*\]/);
      return match ? JSON.parse(match[0]) : [];
    } catch {
      return [];
    }
  }

  parsePrimitives(response) {
    try {
      const content = this.getTextContent(response) || '[]';
      const match = content.match(/\[[\s\S]*\]/);
      return match ? JSON.parse(match[0]) : [];
    } catch {
      return [];
    }
  }

  calculateAttackScore(surface) {
    let score = 0;

    // Weight vectors by severity
    for (const vector of surface.vectors) {
      const meta = ATTACK_VECTORS[vector.vector_type];
      if (meta) {
        score += meta.exploitability * 10;
      }
    }

    // Weight boundaries by risk level
    for (const boundary of surface.boundaries) {
      const level = boundary.risk_level || boundary.bypass_potential;
      const weight = { high: 15, medium: 8, low: 3 }[level] || 0;
      score += weight;
    }

    // Weight primitives
    for (const primitive of surface.primitives) {
      const weight = { high: 20, medium: 10, low: 5 }[primitive.usefulness] || 0;
      score += weight;
    }

    return Math.min(100, score);
  }
}

export { ATTACK_VECTORS };
