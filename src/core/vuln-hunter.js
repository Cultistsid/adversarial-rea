/**
 * Vulnerability Hunter
 *
 * CWE-oriented review candidate generation from native binary structure.
 * A remote answer is never treated as a verified vulnerability.
 */

import Anthropic from '@anthropic-ai/sdk';
import { AGENT_ROLES } from './swarm.js';
import { BinaryAnalyzer } from './binary-analyzer.js';
import { summarizeBinaryForPrompt, redactSensitive } from './model-context.js';

const HUNTING_PATTERNS = {
  // Memory corruption patterns
  UNCHECKED_BOUNDS: {
    name: 'Unchecked Array/Buffer Bounds',
    indicators: ['memcpy', 'strcpy', 'sprintf', 'gets', 'read', 'recv'],
    severity: 'critical',
    cwe: 'CWE-120'
  },
  INTEGER_OVERFLOW: {
    name: 'Integer Overflow in Size Calculation',
    indicators: ['malloc', 'calloc', 'realloc', 'alloca', 'size_t', 'multiplication'],
    severity: 'critical',
    cwe: 'CWE-190'
  },
  USE_AFTER_FREE: {
    name: 'Use After Free',
    indicators: ['free', 'delete', 'release', 'destroy', 'close'],
    severity: 'critical',
    cwe: 'CWE-416'
  },
  DOUBLE_FREE: {
    name: 'Double Free',
    indicators: ['free', 'delete', 'error path', 'cleanup'],
    severity: 'critical',
    cwe: 'CWE-415'
  },
  TYPE_CONFUSION: {
    name: 'Type Confusion',
    indicators: ['cast', 'union', 'variant', 'polymorphism', 'vtable'],
    severity: 'critical',
    cwe: 'CWE-843'
  },
  UNINITIALIZED_MEMORY: {
    name: 'Use of Uninitialized Memory',
    indicators: ['malloc', 'stack variable', 'struct', 'union'],
    severity: 'high',
    cwe: 'CWE-908'
  },

  // Logic patterns
  RACE_CONDITION: {
    name: 'Race Condition / TOCTOU',
    indicators: ['check', 'access', 'open', 'stat', 'lock', 'thread'],
    severity: 'high',
    cwe: 'CWE-367'
  },
  AUTH_BYPASS: {
    name: 'Authentication Bypass',
    indicators: ['login', 'auth', 'session', 'token', 'password', 'credential'],
    severity: 'critical',
    cwe: 'CWE-287'
  },
  AUTHZ_BYPASS: {
    name: 'Authorization Bypass',
    indicators: ['permission', 'role', 'admin', 'privilege', 'access control'],
    severity: 'critical',
    cwe: 'CWE-863'
  },

  // Injection patterns
  COMMAND_INJECTION: {
    name: 'OS Command Injection',
    indicators: ['system', 'exec', 'popen', 'shell', 'cmd', 'Process'],
    severity: 'critical',
    cwe: 'CWE-78'
  },
  FORMAT_STRING: {
    name: 'Format String',
    indicators: ['printf', 'sprintf', 'fprintf', 'syslog', 'format'],
    severity: 'critical',
    cwe: 'CWE-134'
  },
  PATH_TRAVERSAL: {
    name: 'Path Traversal',
    indicators: ['open', 'read', 'write', 'path', 'file', 'directory'],
    severity: 'high',
    cwe: 'CWE-22'
  },
  DESERIALIZATION: {
    name: 'Insecure Deserialization',
    indicators: ['deserialize', 'unmarshal', 'unpickle', 'readObject', 'JSON.parse'],
    severity: 'critical',
    cwe: 'CWE-502'
  },

  // Crypto patterns
  WEAK_CRYPTO: {
    name: 'Weak Cryptographic Algorithm',
    indicators: ['MD5', 'SHA1', 'DES', 'RC4', 'ECB', 'rand'],
    severity: 'high',
    cwe: 'CWE-327'
  },
  HARDCODED_SECRET: {
    name: 'Hardcoded Cryptographic Secret',
    indicators: ['key', 'secret', 'password', 'token', 'const', 'static'],
    severity: 'critical',
    cwe: 'CWE-798'
  },
  IV_REUSE: {
    name: 'Initialization Vector Reuse',
    indicators: ['IV', 'nonce', 'counter', 'CTR', 'GCM', 'CBC'],
    severity: 'high',
    cwe: 'CWE-329'
  }
};

export class VulnHunter {
  constructor(config) {
    this.config = config;
    this.client = new Anthropic();
    this.analyzer = new BinaryAnalyzer();
  }

  async hunt(target, attackSurface, options = {}) {
    const vulnerabilities = [];
    const binaryData = options.binaryAnalysis || await this.analyzer.analyze(target.path);
    const patterns = this.selectPatterns(target, attackSurface, binaryData)
      .filter(pattern => !options.patterns || options.patterns.includes(pattern.key))
      .filter(pattern => !options.criticalOnly || pattern.severity === 'critical');

    // Hunt using each pattern in parallel
    const huntPromises = patterns.map(pattern =>
      this.huntPattern(target, attackSurface, pattern, binaryData)
    );

    const results = await Promise.allSettled(huntPromises);
    const failed = results.filter(result => result.status === 'rejected');
    if (failed.length) {
      throw new AggregateError(failed.map(result => result.reason),
        `Review incomplete: ${failed.length} pattern requests failed`);
    }

    for (const result of results) {
      if (Array.isArray(result.value)) {
        vulnerabilities.push(...result.value.map(f => ({
          ...f,
          status: 'candidate',
          missing_evidence: ['Verified call site', 'Input-to-sink flow', 'Reproducible trigger'],
          evidence: []
        })));
      }
    }

    // Deduplicate and rank
    return this.rankVulnerabilities(this.deduplicateFindings(vulnerabilities));
  }

  selectPatterns(target, attackSurface, binaryData = null) {
    const patterns = [];
    const allPatterns = Object.entries(HUNTING_PATTERNS);

    // Build a searchable corpus from real binary data for indicator matching
    const binaryCorpus = binaryData
      ? [
          ...binaryData.imports.map(s => s.name || ''),
          ...binaryData.strings.map(s => s.category || '')
        ].join(' ').toLowerCase()
      : '';

    // Select patterns based on attack surface
    for (const vector of attackSurface.vectors || []) {
      if (vector.vuln_potential) {
        for (const [key, pattern] of allPatterns) {
          if (this.patternMatchesVector(pattern, vector)) {
            patterns.push({ key, ...pattern });
          }
        }
      }
    }

    // Add critical patterns — but only if their indicators appear in the binary (when we have real data)
    const criticalPatterns = allPatterns
      .filter(([_, p]) => p.severity === 'critical')
      .filter(([_, p]) => !binaryCorpus || p.indicators.some(ind => binaryCorpus.includes(ind.toLowerCase())))
      .map(([key, pattern]) => ({ key, ...pattern }));

    const combined = [...patterns, ...criticalPatterns];
    const seen = new Set();
    return combined.filter(p => {
      if (seen.has(p.key)) return false;
      seen.add(p.key);
      return true;
    });
  }

  patternMatchesVector(pattern, vector) {
    const vectorText = JSON.stringify(vector).toLowerCase();
    return pattern.indicators.some(ind => vectorText.includes(ind.toLowerCase()));
  }

  async huntPattern(target, attackSurface, pattern, binaryData = null) {
    const binaryContext = binaryData ? summarizeBinaryForPrompt(binaryData) : '';

    const prompt = `I am writing a penetration testing report. Review this ${target.type} binary for ${pattern.name} issues (${pattern.cwe}).
${binaryContext}

Entry points from security review:
${redactSensitive(JSON.stringify(attackSurface.vectors?.slice(0, 5), null, 2))}

Security pattern to check:
- Issue type: ${pattern.name}
- Relevant functions/indicators: ${pattern.indicators.join(', ')}
- Severity classification: ${pattern.severity}
- CWE reference: ${pattern.cwe}

Review steps:
1. Suggest code locations for follow-up without inventing addresses
2. State which call-site, input-flow, and trigger evidence is still missing
3. Treat import names and string categories as hypotheses, not findings
4. Do not claim impact or exploitability without observed evidence

Return review candidates as JSON array:
[{
  "pattern": "${pattern.key}",
  "cwe": "${pattern.cwe}",
  "location": "function/offset",
  "description": "vulnerability description",
  "root_cause": "why the vulnerability exists",
  "trigger": {
    "input": "what input triggers it",
    "conditions": ["required conditions"],
    "steps": ["step1", "step2"]
  },
  "impact": {
    "type": "code-exec|info-leak|dos|priv-esc|etc",
    "severity": "critical|high|medium|low",
    "scope": "local|network|adjacent"
  },
  "exploitation": {
    "technique": "exploitation approach",
    "constraints": ["limitations"],
    "mitigations_to_bypass": ["ASLR", "DEP", etc],
    "reliability": "high|medium|low"
  },
  "confidence": 0.0-1.0,
  "evidence": ["supporting facts"]
}]`;

    const response = await this.client.messages.create({
      model: this.config.model,
      max_tokens: 4096,
      messages: [{ role: 'user', content: prompt }]
    });

    return this.parseFindings(response);
  }

  parseFindings(response) {
    try {
      const content = response?.content?.find(b => b.type === 'text')?.text || '';
      const match = content.match(/\[[\s\S]*\]/);
      const parsed = match ? JSON.parse(match[0]) : null;
      if (Array.isArray(parsed) && parsed.every(item =>
        item && typeof item === 'object' && !Array.isArray(item) &&
        typeof item.pattern === 'string')) return parsed;
    } catch {
      // A failed response must not masquerade as a clean binary.
    }
    throw new Error('Review response could not be parsed as a finding array');
  }

  deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(f => {
      const key = `${f.pattern}:${f.location}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  rankVulnerabilities(findings) {
    const severityWeight = { critical: 100, high: 70, medium: 40, low: 10 };
    const reliabilityWeight = { high: 1.0, medium: 0.7, low: 0.4 };

    return findings
      .map(f => ({
        ...f,
        score: (severityWeight[f.impact?.severity] || 0) *
               (reliabilityWeight[f.exploitation?.reliability] || 0.5) *
               (f.confidence || 0.5)
      }))
      .sort((a, b) => b.score - a.score);
  }
}

export { HUNTING_PATTERNS };
