/**
 * MCP Server for Adversarial REA
 *
 * Provides local binary analysis tools via MCP.
 */

import { BinaryAnalyzer } from '../core/binary-analyzer.js';

const TOOLS = {
  analyze_binary: {
    name: 'analyze_binary',
    description: 'Extract binary metadata, symbols, strings, and security info from a target',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' },
        strings_min_len: { type: 'number', description: 'Minimum string length', default: 6 }
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
        filter: { type: 'string', description: 'Filter symbols by pattern' },
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
        min_length: { type: 'number', description: 'Minimum string length', default: 6 },
        interesting_only: { type: 'boolean', description: 'Only return security-relevant strings', default: false },
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
        limit: { type: 'number', description: 'Max lines of output', default: 500 }
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
    description: 'Scan for dangerous function calls and vulnerability patterns',
    inputSchema: {
      type: 'object',
      properties: {
        target_path: { type: 'string', description: 'Path to target binary' }
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
    this.analyzer = new BinaryAnalyzer();
  }

  getToolList() {
    return Object.values(TOOLS);
  }

  async handleToolCall(name, args) {
    switch (name) {
      case 'analyze_binary':
        return this.analyzeBinary(args);
      case 'get_symbols':
        return this.getSymbols(args);
      case 'get_strings':
        return this.getStrings(args);
      case 'check_security':
        return this.checkSecurity(args);
      case 'disassemble':
        return this.disassemble(args);
      case 'get_sections':
        return this.getSections(args);
      case 'get_headers':
        return this.getHeaders(args);
      case 'find_dangerous_patterns':
        return this.findDangerousPatterns(args);
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  async analyzeBinary(args) {
    const analysis = await this.analyzer.analyze(args.target_path, {
      stringsMinLen: args.strings_min_len || 6
    });

    return {
      success: true,
      target: analysis.target,
      security: analysis.security,
      summary: {
        symbol_count: analysis.symbols.length,
        import_count: analysis.imports.length,
        export_count: analysis.exports.length,
        function_count: analysis.functions.length,
        interesting_strings: analysis.strings.filter(s => s.interesting).length,
        sections: analysis.sections.length
      },
      headers: analysis.headers?.parsed,
      interesting_strings: analysis.strings.filter(s => s.interesting).slice(0, 50),
      dangerous_imports: analysis.imports
        .map(s => {
          const base = (s.name?.replace(/^_+/, '') || '').replace(/@.*$/, '');
          const match = DANGEROUS_FUNCTIONS.find(d => d.name === base);
          return match ? { ...s, risk: match } : null;
        })
        .filter(Boolean)
    };
  }

  async getSymbols(args) {
    const analysis = await this.analyzer.analyze(args.target_path);
    let symbols = analysis.symbols;

    if (args.type === 'imports') symbols = analysis.imports;
    else if (args.type === 'exports') symbols = analysis.exports;
    else if (args.type === 'functions') symbols = analysis.functions;

    if (args.filter) {
      const pattern = new RegExp(args.filter, 'i');
      symbols = symbols.filter(s => pattern.test(s.name));
    }

    return {
      success: true,
      count: symbols.length,
      symbols: symbols.slice(0, 500)
    };
  }

  async getStrings(args) {
    const analysis = await this.analyzer.analyze(args.target_path, {
      stringsMinLen: args.min_length || 6
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
      strings: strings.slice(0, 500)
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
      recommendations: this.getSecurityRecommendations(mitigations)
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
    return Math.round((score / maxScore) * 100);
  }

  getSecurityRecommendations(mitigations) {
    const recs = [];
    if (!mitigations.pie) recs.push('Enable PIE for ASLR support');
    if (!mitigations.nx) recs.push('Enable NX/DEP to prevent shellcode execution');
    if (!mitigations.canary) recs.push('Enable stack canaries to detect overflows');
    if (mitigations.relro !== 'n/a' && mitigations.relro !== 'full') recs.push('Enable full RELRO to protect GOT');
    if (!mitigations.fortify) recs.push('Compile with FORTIFY_SOURCE');
    if (mitigations.stripped) recs.push('Binary is stripped - consider symbols for debugging');
    return recs;
  }

  async disassemble(args) {
    const result = await this.analyzer.disassemble(args.target_path, {
      function: args.function
    });

    return {
      success: true,
      function: args.function || 'all',
      disassembly: result.raw?.slice(0, 50000),
      error: result.error
    };
  }

  async getSections(args) {
    const analysis = await this.analyzer.analyze(args.target_path);

    return {
      success: true,
      sections: analysis.sections,
      executable_sections: analysis.sections.filter(s =>
        s.name?.includes('text') || s.name?.includes('code')
      ),
      data_sections: analysis.sections.filter(s =>
        s.name?.includes('data') || s.name?.includes('bss') || s.name?.includes('rodata')
      )
    };
  }

  async getHeaders(args) {
    const analysis = await this.analyzer.analyze(args.target_path);

    return {
      success: true,
      target: analysis.target,
      headers: analysis.headers
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
            type: 'dangerous_import',
            function: sym.name,
            address: sym.address,
            cwe: dangerous.cwe,
            risk: dangerous.risk,
            severity: this.getSeverity(dangerous.cwe)
          });
        }
      }
    }

    // Check strings for security-relevant patterns
    for (const str of analysis.strings.filter(s => s.interesting)) {
      if (str.category === 'credential_related') {
        findings.push({
          type: 'hardcoded_credential',
          value: str.value.slice(0, 100),
          cwe: 'CWE-798',
          risk: 'Potential hardcoded secret',
          severity: 'high'
        });
      } else if (str.category === 'crypto_material') {
        findings.push({
          type: 'embedded_key',
          value: str.value.slice(0, 50) + '...',
          cwe: 'CWE-321',
          risk: 'Embedded cryptographic key',
          severity: 'critical'
        });
      } else if (str.category === 'sql') {
        findings.push({
          type: 'sql_query',
          value: str.value.slice(0, 100),
          cwe: 'CWE-89',
          risk: 'Potential SQL injection if user-controlled',
          severity: 'medium'
        });
      }
    }

    // Security posture issues
    if (!analysis.security.pie) {
      findings.push({
        type: 'missing_mitigation',
        mitigation: 'PIE',
        cwe: 'CWE-119',
        risk: 'No ASLR - fixed addresses exploitable',
        severity: 'medium'
      });
    }
    if (!analysis.security.canary) {
      findings.push({
        type: 'missing_mitigation',
        mitigation: 'Stack Canary',
        cwe: 'CWE-119',
        risk: 'Stack buffer overflows easier to exploit',
        severity: 'medium'
      });
    }

    return {
      success: true,
      target: analysis.target,
      finding_count: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      findings
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
