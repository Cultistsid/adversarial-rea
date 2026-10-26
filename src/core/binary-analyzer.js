/**
 * Binary Analyzer
 *
 * Local binary analysis using system tools (objdump, nm, strings, file).
 * Extracts data for the agent to reason about.
 */

import { execSync, spawn } from 'child_process';
import { readFileSync, existsSync, statSync } from 'fs';
import { basename, extname } from 'path';

export class BinaryAnalyzer {
  constructor(config = {}) {
    this.config = config;
    this.tools = this.detectTools();
  }

  detectTools() {
    const tools = {};
    const check = (name) => {
      try {
        execSync(`which ${name}`, { stdio: 'pipe' });
        return true;
      } catch { return false; }
    };

    tools.objdump = check('objdump');
    tools.nm = check('nm');
    tools.strings = check('strings');
    tools.file = check('file');
    tools.otool = check('otool');  // macOS
    tools.rizin = check('rizin');
    tools.radare2 = check('r2');

    return tools;
  }

  async analyze(targetPath, options = {}) {
    if (!existsSync(targetPath)) {
      throw new Error(`Target not found: ${targetPath}`);
    }

    const stats = statSync(targetPath);
    const fileType = await this.getFileType(targetPath);

    const analysis = {
      target: {
        path: targetPath,
        name: basename(targetPath),
        size: stats.size,
        type: fileType
      },
      headers: null,
      sections: [],
      symbols: [],
      imports: [],
      exports: [],
      strings: [],
      functions: [],
      security: {}
    };

    // Parallel extraction
    const [headers, symbols, strings, sections] = await Promise.all([
      this.extractHeaders(targetPath, fileType),
      this.extractSymbols(targetPath),
      this.extractStrings(targetPath, options.stringsMinLen || 6),
      this.extractSections(targetPath, fileType)
    ]);

    analysis.headers = headers;
    analysis.symbols = symbols;
    analysis.strings = strings;
    analysis.sections = sections;

    // Categorize symbols
    analysis.imports = symbols.filter(s => s.type === 'U' || s.imported);
    analysis.exports = symbols.filter(s => s.type === 'T' || s.exported);
    analysis.functions = symbols.filter(s =>
      s.type === 'T' || s.type === 't' || s.name?.includes('func') || s.name?.includes('sub_')
    );

    // Security checks
    analysis.security = await this.checkSecurity(targetPath, fileType, headers);

    return analysis;
  }

  async getFileType(targetPath) {
    if (!this.tools.file) return 'unknown';

    try {
      const output = execSync(`file -b "${targetPath}"`, { encoding: 'utf8' });

      if (output.includes('ELF')) return 'elf';
      if (output.includes('Mach-O')) return 'macho';
      if (output.includes('PE32') || output.includes('PE64')) return 'pe';
      if (output.includes('Android')) return 'android';
      if (output.includes('Java archive')) return 'jar';
      if (output.includes('WebAssembly')) return 'wasm';

      return output.trim().slice(0, 100);
    } catch {
      return 'unknown';
    }
  }

  async extractHeaders(targetPath, fileType) {
    const headers = { raw: '', parsed: {} };

    try {
      if (fileType === 'macho' && this.tools.otool) {
        headers.raw = execSync(`otool -h "${targetPath}" 2>/dev/null`, { encoding: 'utf8' });
        headers.load_commands = execSync(`otool -l "${targetPath}" 2>/dev/null | head -200`, { encoding: 'utf8' });
      } else if (this.tools.objdump) {
        headers.raw = execSync(`objdump -f "${targetPath}" 2>/dev/null`, { encoding: 'utf8' });
        headers.all = execSync(`objdump -x "${targetPath}" 2>/dev/null | head -100`, { encoding: 'utf8' });
      }

      // Parse key fields
      const archMatch = headers.raw.match(/architecture:\s*(\S+)/i) ||
                        headers.raw.match(/cputype\s+(\S+)/i);
      if (archMatch) headers.parsed.arch = archMatch[1];

      const entryMatch = headers.raw.match(/start address\s+(0x[0-9a-f]+)/i);
      if (entryMatch) headers.parsed.entry = entryMatch[1];

    } catch (e) {
      headers.error = e.message;
    }

    return headers;
  }

  async extractSymbols(targetPath) {
    const symbols = [];

    try {
      let output = '';

      if (this.tools.nm) {
        output = execSync(`nm -a "${targetPath}" 2>/dev/null | head -1000`, { encoding: 'utf8' });
      }

      const seen = new Set();
      for (const line of output.split('\n')) {
        const match = line.match(/^([0-9a-f]*)\s+([a-zA-Z])\s+(.+)$/i);
        if (match) {
          const key = `${match[2]}:${match[3]}`;
          if (seen.has(key)) continue;
          seen.add(key);
          symbols.push({
            address: match[1] || null,
            type: match[2],
            name: match[3],
            imported: match[2] === 'U',
            exported: match[2] === 'T'
          });
        }
      }
    } catch (e) {
      // Binary might be stripped
    }

    return symbols;
  }

  async extractStrings(targetPath, minLen = 6) {
    const strings = [];

    try {
      if (this.tools.strings) {
        const output = execSync(
          `strings -n ${minLen} "${targetPath}" 2>/dev/null | head -500`,
          { encoding: 'utf8' }
        );

        for (const str of output.split('\n')) {
          if (!str) continue;

          const classified = this.classifyString(str);
          strings.push({
            value: str,
            ...classified
          });
        }
      }
    } catch (e) {
      // Strings extraction failed
    }

    return strings;
  }

  classifyString(str) {
    const classification = { interesting: false, category: 'unknown' };

    // Security-relevant patterns — more specific checks run before broad ones
    // crypto_material before credential_related (-----BEGIN...KEY contains "KEY")
    if (/BEGIN.*KEY|-----END|-----BEGIN/i.test(str)) {
      classification.category = 'crypto_material';
      classification.interesting = true;
    // path before credential_related (HKEY_ contains "KEY")
    } else if (/\/etc\/|\/proc\/|\/dev\/|C:\\|HKEY_/i.test(str)) {
      classification.category = 'path';
      classification.interesting = true;
    } else if (/http[s]?:\/\/|ftp:\/\/|file:\/\//i.test(str)) {
      classification.category = 'url';
      classification.interesting = true;
    } else if (/password|passwd|secret|token|auth|cred/i.test(str)) {
      classification.category = 'credential_related';
      classification.interesting = true;
    } else if (/error|fail|exception|invalid|denied|forbidden/i.test(str)) {
      classification.category = 'error_message';
      classification.interesting = true;
    } else if (/sprintf|strcpy|strcat|gets|scanf|system|exec|popen/i.test(str)) {
      classification.category = 'dangerous_function';
      classification.interesting = true;
    } else if (/SELECT|INSERT|UPDATE|DELETE|FROM|WHERE/i.test(str)) {
      classification.category = 'sql';
      classification.interesting = true;
    } else if (/\.dll|\.so|\.dylib/i.test(str)) {
      classification.category = 'library_reference';
    } else if (/version|copyright|\(c\)/i.test(str)) {
      classification.category = 'version_info';
    }

    return classification;
  }

  async extractSections(targetPath, fileType) {
    const sections = [];

    try {
      let output = '';

      // objdump -h produces the same section table format for ELF and Mach-O,
      // which the regex below parses. otool -l output has a different layout.
      if (this.tools.objdump) {
        output = execSync(`objdump -h "${targetPath}" 2>/dev/null`, { encoding: 'utf8' });
      }

      // Parse sections from objdump -h output
      const lines = output.split('\n');
      for (const line of lines) {
        const match = line.match(/^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)/i);
        if (match) {
          sections.push({
            name: match[1],
            size: parseInt(match[2], 16),
            address: match[3]
          });
        }
      }
    } catch (e) {
      // Section extraction failed
    }

    return sections;
  }

  async checkSecurity(targetPath, fileType, headers) {
    const security = {
      pie: false,
      nx: false,
      canary: false,
      relro: fileType === 'macho' ? 'n/a' : 'none',
      stripped: false,
      fortify: false
    };

    try {
      const symbols = await this.extractSymbols(targetPath);

      if (fileType === 'macho') {
        // Mach-O: PIE is MH_PIE flag in otool -hv output
        if (this.tools.otool) {
          const hdr = execSync(`otool -hv "${targetPath}" 2>/dev/null`, { encoding: 'utf8' });
          security.pie = hdr.includes('PIE');
          // NX: macOS enforces non-exec stack via kernel; check for explicit allow via flags
          // Absence of ALLOW_STACK_EXECUTION flag means NX is on
          security.nx = !hdr.includes('ALLOW_STACK_EXECUTION');
        }
      } else {
        // ELF: PIE is ET_DYN in objdump output
        if (headers?.raw?.includes('DYNAMIC') || headers?.raw?.includes('DYN')) {
          security.pie = true;
        }
        // ELF: NX via GNU_STACK program header — RWX means no NX
        if (this.tools.objdump) {
          const progHeaders = execSync(
            `objdump -p "${targetPath}" 2>/dev/null | grep -E "STACK|GNU_STACK"`,
            { encoding: 'utf8' }
          ).toLowerCase();
          security.nx = progHeaders.length > 0 && !progHeaders.includes('rwx');
        }
        // ELF: RELRO
        if (this.tools.objdump) {
          const dynamic = execSync(
            `objdump -p "${targetPath}" 2>/dev/null | grep -i relro`,
            { encoding: 'utf8' }
          ).toLowerCase();
          if (dynamic.includes('relro')) security.relro = 'partial';
          if (dynamic.includes('bind_now') || dynamic.includes('now')) security.relro = 'full';
        }
      }

      // Stack canary (symbol-based — works for both ELF and Mach-O)
      if (symbols.some(s => s.name?.includes('__stack_chk'))) {
        security.canary = true;
      }

      // FORTIFY (symbol-based). Exclude __stack_chk_* — those are the stack
      // canary, not FORTIFY_SOURCE wrappers like __memcpy_chk / __sprintf_chk.
      if (symbols.some(s =>
        s.name?.includes('__fortify') ||
        (s.name?.includes('_chk') && !s.name.includes('stack_chk'))
      )) {
        security.fortify = true;
      }

      // Stripped: low symbol count
      if (symbols.length < 10) {
        security.stripped = true;
      }

    } catch (e) {
      // Security checks failed
    }

    return security;
  }

  async disassemble(targetPath, options = {}) {
    const result = { functions: [], raw: '' };

    try {
      if (this.tools.objdump) {
        const cmd = options.function
          ? `objdump -d "${targetPath}" 2>/dev/null | grep -A50 "<${options.function}>:"`
          : `objdump -d "${targetPath}" 2>/dev/null | head -500`;

        result.raw = execSync(cmd, { encoding: 'utf8' });
      }
    } catch (e) {
      result.error = e.message;
    }

    return result;
  }
}

export default BinaryAnalyzer;
