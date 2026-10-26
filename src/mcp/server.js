/**
 * MCP Server for Adversarial REA
 *
 * Provides local binary analysis tools via MCP.
 */

import { BinaryAnalyzer, boundedInteger } from '../core/binary-analyzer.js';
import { CallSiteExtractor } from '../core/call-sites.js';
import { CarrierInspector } from '../core/carrier-inspector.js';
import { FlowFixtureInspector } from '../core/flow-fixtures.js';
import { GadgetCandidateFinder } from '../core/gadget-candidates.js';
import { redactSensitive } from '../core/model-context.js';
import { delimiter } from 'node:path';

function safeString(entry, revealSensitive = false) {
  const sensitive = ['credential_related', 'crypto_material'].includes(entry.category);
  return {
    ...entry,
    value: sensitive && !revealSensitive
      ? '[REDACTED]'
      : (revealSensitive ? String(entry.value) : redactSensitive(entry.value)).slice(0, 160)
  };
}

const TOOLS = {
  analyze_binary: {
    name: 'analyze_binary',
    description: 'Extract binary metadata, symbols, strings, and security info from a target',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' },
        strings_min_len: { type: 'integer', minimum: 1, maximum: 64, description: 'Minimum string length', default: 6 }
      },
      required: ['target_path']
    }
  },

  get_symbols: {
    name: 'get_symbols',
    description: 'Extract symbols (functions, imports, exports) from binary',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' },
        filter: { type: 'string', description: 'Literal substring to filter symbol names' },
        type: { type: 'string', enum: ['all', 'imports', 'exports', 'functions'], default: 'all' }
      },
      required: ['target_path']
    }
  },

  get_strings: {
    name: 'get_strings',
    description: 'Extract and classify strings from binary (credentials, URLs, paths, etc.)',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' },
        min_length: { type: 'integer', minimum: 1, maximum: 64, description: 'Minimum string length', default: 6 },
        interesting_only: { type: 'boolean', description: 'Only return security-relevant strings', default: false },
        reveal_sensitive: { type: 'boolean', description: 'Explicitly reveal sensitive string categories (local use only)', default: false },
        category: { type: 'string', description: 'Filter by category (credential_related, url, path, dangerous_function, etc.)' }
      },
      required: ['target_path']
    }
  },

  check_security: {
    name: 'check_security',
    description: 'Check binary security mitigations (PIE, NX, canary, RELRO, FORTIFY)',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' }
      },
      required: ['target_path']
    }
  },

  disassemble: {
    name: 'disassemble',
    description: 'Disassemble binary or specific function',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' },
        function: { type: 'string', description: 'Specific function to disassemble' },
        limit: { type: 'integer', minimum: 1, maximum: 500, description: 'Max lines of output', default: 500 }
      },
      required: ['target_path']
    }
  },

  get_sections: {
    name: 'get_sections',
    description: 'List binary sections with sizes and attributes',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' }
      },
      required: ['target_path']
    }
  },

  get_headers: {
    name: 'get_headers',
    description: 'Extract binary headers (architecture, entry point, etc.)',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' }
      },
      required: ['target_path']
    }
  },

  find_dangerous_patterns: {
    name: 'find_dangerous_patterns',
    description: 'List unverified imports, strings, and mitigation signals for manual review',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' }
      },
      required: ['target_path']
    }
  },

  trace_calls: {
    name: 'trace_calls',
    description: 'Observed direct native call instructions; flow and exploitability remain unknown',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to native binary' },
        sinks: { type: 'array', maxItems: 32, items: { type: 'string', maxLength: 128 },
          description: 'Exact normalized sink names; empty array lists all bounded call sites' },
        arch: { type: 'string', enum: ['host', 'all', 'x86_64', 'arm64', 'arm64e'], default: 'host',
          description: 'Select a Mach-O slice; host selects the current architecture' },
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 100 }
      },
      required: ['target_path']
    }
  },

  inspect_carrier: {
    name: 'inspect_carrier',
    description: 'Bounded file/container metadata only; does not claim vulnerability analysis',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to file or .app bundle directory' },
        limit: { type: 'integer', minimum: 1, maximum: 200, default: 100 }
      },
      required: ['target_path']
    }
  },

  inspect_flow_fixture: {
    name: 'inspect_flow_fixture',
    description: 'Reproduce in-memory flow in a bounded .flow.json fixture only; not native evidence',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to a declarative .flow.json fixture' }
      },
      required: ['target_path']
    }
  },

  find_gadget_candidates: {
    name: 'find_gadget_candidates',
    description: 'Byte-verified ELF64 x86_64 gadget candidates, not runtime exploit addresses',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to ELF64 x86_64 target' },
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 50 }
      },
      required: ['target_path']
    }
  }
};

// Dangerous functions to look for
const DANGEROUS_FUNCTIONS = [
  // Memory corruption
  { name: 'strcpy', cwe: 'CWE-120', risk: 'Buffer overflow - no bounds checking' },
  { name: 'strcat', cwe: 'CWE-120', risk: 'Buffer overflow - no bounds checking' },
  { name: 'sprintf', cwe: 'CWE-120', risk: 'Buffer overflow - no bounds checking' },
  { name: 'gets', cwe: 'CWE-120', risk: 'Buffer overflow - never use' },
  { name: 'scanf', cwe: 'CWE-120', risk: 'Buffer overflow without width specifier' },
  { name: 'vsprintf', cwe: 'CWE-120', risk: 'Buffer overflow - no bounds checking' },

  // Format string
  { name: 'printf', cwe: 'CWE-134', risk: 'Format string if user-controlled' },
  { name: 'fprintf', cwe: 'CWE-134', risk: 'Format string if user-controlled' },
  { name: 'syslog', cwe: 'CWE-134', risk: 'Format string if user-controlled' },

  // Command injection
  { name: 'system', cwe: 'CWE-78', risk: 'Command injection if user-controlled' },
  { name: 'popen', cwe: 'CWE-78', risk: 'Command injection if user-controlled' },
  { name: 'execve', cwe: 'CWE-78', risk: 'Command execution' },
  { name: 'execl', cwe: 'CWE-78', risk: 'Command execution' },
  { name: 'execlp', cwe: 'CWE-78', risk: 'Command execution' },

  // Memory management
  { name: 'malloc', cwe: 'CWE-122', risk: 'Heap - check for integer overflow in size' },
  { name: 'realloc', cwe: 'CWE-122', risk: 'Heap - check for UAF and integer overflow' },
  { name: 'free', cwe: 'CWE-415', risk: 'Check for double-free' },
  { name: 'alloca', cwe: 'CWE-770', risk: 'Stack allocation - size control needed' },

  // File operations
  { name: 'fopen', cwe: 'CWE-22', risk: 'Path traversal if user-controlled' },
  { name: 'open', cwe: 'CWE-22', risk: 'Path traversal if user-controlled' },
  { name: 'chmod', cwe: 'CWE-732', risk: 'Permission issues' },
  { name: 'chown', cwe: 'CWE-732', risk: 'Permission issues' },

  // Crypto weak
  { name: 'rand', cwe: 'CWE-338', risk: 'Weak PRNG - not cryptographically secure' },
  { name: 'srand', cwe: 'CWE-338', risk: 'Weak PRNG seed' },
  { name: 'MD5', cwe: 'CWE-328', risk: 'Weak hash algorithm' },
  { name: 'SHA1', cwe: 'CWE-328', risk: 'Weak hash algorithm' },
  { name: 'DES', cwe: 'CWE-327', risk: 'Weak encryption' }
];

export class AdversarialMCPServer {
  constructor() {
    const allowedRoots = process.env.ADV_REA_ALLOWED_ROOTS?.split(delimiter).filter(Boolean);
    this.analyzer = new BinaryAnalyzer(allowedRoots ? { allowedRoots } : {});
    this.callSites = new CallSiteExtractor(this.analyzer);
    this.carriers = new CarrierInspector(this.analyzer);
    this.fixtures = new FlowFixtureInspector(this.analyzer);
    this.gadgets = new GadgetCandidateFinder(this.analyzer);
  }

  getToolList() {
    return Object.values(TOOLS);
  }

  analysisState(analysis) {
    const warnings = analysis.warnings || [];
    const truncated = analysis.truncated || {};
    return {
      warnings,
      extraction_truncated: truncated,
      incomplete: warnings.length > 0 || Object.values(truncated).some(Boolean)
    };
  }

  async handleToolCall(name, args = {}) {
    let result;
    switch (name) {
      case 'analyze_binary':
        result = await this.analyzeBinary(args); break;
      case 'get_symbols':
        result = await this.getSymbols(args); break;
      case 'get_strings':
        result = await this.getStrings(args); break;
      case 'check_security':
        result = await this.checkSecurity(args); break;
      case 'disassemble':
        result = await this.disassemble(args); break;
      case 'get_sections':
        result = await this.getSections(args); break;
      case 'get_headers':
        result = await this.getHeaders(args); break;
      case 'find_dangerous_patterns':
        result = await this.findDangerousPatterns(args); break;
      case 'trace_calls':
        result = await this.traceCalls(args); break;
      case 'inspect_carrier':
        result = await this.inspectCarrier(args); break;
      case 'inspect_flow_fixture':
        result = await this.inspectFlowFixture(args); break;
      case 'find_gadget_candidates':
        result = await this.findGadgetCandidates(args); break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
    if (Buffer.byteLength(JSON.stringify(result)) > 64 * 1024) {
      throw new Error('Result exceeds MCP response budget');
    }
    return result;
  }

  async traceCalls(args) {
    const analysis = await this.analyzer.analyze(args.target_path);
    return {
      ...(await this.callSites.trace(analysis, {
        sinks: args.sinks, arch: args.arch, limit: boundedInteger(args.limit, 100, 100)
      })),
      ...this.analysisState(analysis)
    };
  }

  async inspectCarrier(args) {
    return this.carriers.inspect(args.target_path, {
      limit: boundedInteger(args.limit, 100, 200)
    });
  }

  async inspectFlowFixture(args) {
    return this.fixtures.inspect(args.target_path);
  }

  async findGadgetCandidates(args) {
    const analysis = await this.analyzer.analyze(args.target_path);
    return this.gadgets.find(analysis, {
      limit: boundedInteger(args.limit, 50, 100)
    });
  }

  async analyzeBinary(args) {
    const analysis = await this.analyzer.analyze(args.target_path, {
      stringsMinLen: boundedInteger(args.strings_min_len, 6, 64)
    });

    return {
      success: true,
      target: analysis.target,
      security: analysis.security,
      ...this.analysisState(analysis),
      summary: {
        symbol_count: analysis.symbols.length,
        import_count: analysis.imports.length,
        export_count: analysis.exports.length,
        function_count: analysis.functions.length,
        interesting_strings: analysis.strings.filter(s => s.interesting).length,
        sections: analysis.sections.length
      },
      headers: analysis.headers?.parsed,
      interesting_strings: analysis.strings.filter(s => s.interesting).slice(0, 20)
        .map(s => safeString(s)),
      dangerous_imports: analysis.imports
        .map(s => {
          const base = (s.name?.replace(/^_+/, '') || '').replace(/@.*$/, '');
          const match = DANGEROUS_FUNCTIONS.find(d => d.name === base);
          return match ? {
            ...s,
            status: 'candidate',
            cwe_candidate: match.cwe,
            note: 'Import presence does not establish a vulnerable call site or input flow'
          } : null;
        })
        .filter(Boolean).slice(0, 100)
    };
  }

  async getSymbols(args) {
    if (args.filter !== undefined &&
        (typeof args.filter !== 'string' || args.filter.length > 128)) {
      throw new Error('Invalid symbol filter');
    }
    const analysis = await this.analyzer.analyze(args.target_path);
    let symbols = analysis.symbols;

    if (args.type === 'imports') symbols = analysis.imports;
    else if (args.type === 'exports') symbols = analysis.exports;
    else if (args.type === 'functions') symbols = analysis.functions;

    if (args.filter) {
      symbols = symbols.filter(s => s.name?.toLowerCase().includes(args.filter.toLowerCase()));
    }

    return {
      success: true,
      count: symbols.length,
      symbols: symbols.slice(0, 100).map(s => ({ ...s, name: s.name.slice(0, 160) })),
      truncated: symbols.length > 100,
      ...this.analysisState(analysis)
    };
  }

  async getStrings(args) {
    if (args.category !== undefined &&
        (typeof args.category !== 'string' || args.category.length > 64)) {
      throw new Error('Invalid string category');
    }
    const analysis = await this.analyzer.analyze(args.target_path, {
      stringsMinLen: boundedInteger(args.min_length, 6, 64)
    });

    let strings = analysis.strings;

    if (args.interesting_only) {
      strings = strings.filter(s => s.interesting);
    }

    if (args.category) {
      strings = strings.filter(s => s.category === args.category);
    }

    return {
      success: true,
      count: strings.length,
      strings: strings.slice(0, 100).map(s => safeString(s, args.reveal_sensitive === true)),
      truncated: strings.length > 100,
      ...this.analysisState(analysis)
    };
  }

  async checkSecurity(args) {
    const analysis = await this.analyzer.analyze(args.target_path);

    const mitigations = analysis.security;
    const score = this.calculateSecurityScore(mitigations);

    return {
      success: true,
      target: analysis.target,
      mitigations,
      security_score: score,
      recommendations: this.getSecurityRecommendations(mitigations),
      ...this.analysisState(analysis),
      incomplete: this.analysisState(analysis).incomplete || score === null
    };
  }

  calculateSecurityScore(mitigations) {
    // RELRO is ELF-only — exclude from score on platforms where it can't exist
    const hasRelro = mitigations.relro !== 'n/a';
    const maxScore = hasRelro ? 100 : 85;

    let score = 0;
    if (mitigations.pie) score += 20;
    if (mitigations.nx) score += 25;
    if (mitigations.canary) score += 25;
    if (hasRelro) {
      if (mitigations.relro === 'full') score += 15;
      else if (mitigations.relro === 'partial') score += 10;
    }
    if (mitigations.fortify) score += 15;

    // Normalize to 100 for platform-fair comparison
    return [mitigations.pie, mitigations.nx, mitigations.canary, mitigations.fortify].some(value => value == null) ||
      !['full', 'partial', 'none', 'n/a'].includes(mitigations.relro)
      ? null : Math.round((score / maxScore) * 100);
  }

  getSecurityRecommendations(mitigations) {
    const recs = [];
    if (mitigations.pie === false) recs.push('Enable PIE for ASLR support');
    if (mitigations.nx === false) recs.push('Enable NX/DEP to prevent shellcode execution');
    if (mitigations.canary === false) recs.push('Enable stack canaries to detect overflows');
    if (mitigations.relro === 'none' || mitigations.relro === 'partial') recs.push('Enable full RELRO to protect GOT');
    if (mitigations.fortify === false) recs.push('Compile with FORTIFY_SOURCE');
    if (mitigations.stripped === true) recs.push('Binary is stripped - consider symbols for debugging');
    return recs;
  }

  async disassemble(args) {
    const result = await this.analyzer.disassemble(args.target_path, {
      function: args.function,
      limit: boundedInteger(args.limit, 500, 500)
    });

    return {
      success: !result.error,
      function: args.function || 'all',
      disassembly: result.raw?.slice(0, 20000),
      truncated: result.truncated || result.raw.length > 20000,
      incomplete: Boolean(result.error || result.truncated || result.raw.length > 20000),
      error: result.error
    };
  }

  async getSections(args) {
    const analysis = await this.analyzer.analyze(args.target_path);

    return {
      success: true,
      sections: analysis.sections.slice(0, 100),
      ...this.analysisState(analysis),
      executable_sections: analysis.sections.filter(s =>
        s.name?.includes('text') || s.name?.includes('code')
      ).slice(0, 100),
      data_sections: analysis.sections.filter(s =>
        s.name?.includes('data') || s.name?.includes('bss') || s.name?.includes('rodata')
      ).slice(0, 100)
    };
  }

  async getHeaders(args) {
    const analysis = await this.analyzer.analyze(args.target_path);

    return {
      success: true,
      target: analysis.target,
      ...this.analysisState(analysis),
      headers: {
        parsed: analysis.headers?.parsed,
        raw: analysis.headers?.raw?.slice(0, 10000),
        error: analysis.headers?.error
      }
    };
  }

  async findDangerousPatterns(args) {
    const analysis = await this.analyzer.analyze(args.target_path);

    const findings = [];

    // Check imports for dangerous functions — exact match against demangled name.
    // Strip leading underscores (macOS: _strcpy) and ELF version suffixes (strcpy@@GLIBC_2.2.5, strcpy@plt).
    for (const sym of analysis.imports) {
      const symBase = (sym.name?.replace(/^_+/, '') || '').replace(/@.*$/, '');
      for (const dangerous of DANGEROUS_FUNCTIONS) {
        if (symBase === dangerous.name) {
          findings.push({
            type: 'import_observation',
            function: sym.name,
            address: sym.address,
            cwe: dangerous.cwe,
            risk: `Review call sites: ${dangerous.risk}; import alone does not prove exploitability`,
            status: 'candidate',
            severity: 'medium'
          });
        }
      }
    }

    // Check strings for security-relevant patterns
    for (const str of analysis.strings.filter(s => s.interesting)) {
      if (str.category === 'credential_related') {
        findings.push({
          type: 'string_observation',
          value: '[REDACTED]',
          cwe: 'CWE-798',
          risk: 'Credential-related string; no secret or usage confirmed',
          status: 'candidate',
          severity: 'medium'
        });
      } else if (str.category === 'crypto_material') {
        findings.push({
          type: 'string_observation',
          value: '[REDACTED]',
          cwe: 'CWE-321',
          risk: 'Key-like string; key material and usage not verified',
          status: 'candidate',
          severity: 'medium'
        });
      } else if (str.category === 'sql') {
        findings.push({
          type: 'string_observation',
          value: '[REDACTED]',
          cwe: 'CWE-89',
          risk: 'SQL-like string; no user-controlled flow confirmed',
          status: 'candidate',
          severity: 'medium'
        });
      }
    }

    // Security posture issues
    if (analysis.security.pie === false) {
      findings.push({
        type: 'mitigation_observation',
        mitigation: 'PIE',
        cwe: 'CWE-693',
        risk: 'PIE not detected; this does not establish exploitability',
        status: 'observed',
        severity: 'medium'
      });
    }
    if (analysis.security.canary === false) {
      findings.push({
        type: 'mitigation_observation',
        mitigation: 'Stack Canary',
        cwe: 'CWE-693',
        risk: 'Canary not detected; no overflow established',
        status: 'observed',
        severity: 'medium'
      });
    }

    const limited = findings.slice(0, 100);
    return {
      success: true,
      target: analysis.target,
      ...this.analysisState(analysis),
      finding_count: limited.length,
      critical: limited.filter(f => f.severity === 'critical').length,
      high: limited.filter(f => f.severity === 'high').length,
      medium: limited.filter(f => f.severity === 'medium').length,
      findings: limited,
      truncated: findings.length > 100
    };
  }

  getSeverity(cwe) {
    const critical = ['CWE-78', 'CWE-120', 'CWE-122', 'CWE-415', 'CWE-416'];
    const high = ['CWE-134', 'CWE-798', 'CWE-321', 'CWE-327', 'CWE-328'];
    if (critical.includes(cwe)) return 'critical';
    if (high.includes(cwe)) return 'high';
    return 'medium';
  }
}

export { TOOLS };
