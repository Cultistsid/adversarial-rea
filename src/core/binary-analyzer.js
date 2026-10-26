/**
 * Binary Analyzer
 *
 * Local binary analysis using system tools (objdump, nm, strings, file).
 * Extracts data for the agent to reason about.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, openSync, readFileSync, readSync, realpathSync, statSync } from 'node:fs';
import { basename, extname, resolve, sep } from 'node:path';

const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_TOOL_OUTPUT = 2 * 1024 * 1024;
const TOOL_TIMEOUT_MS = 15_000;

export function boundedInteger(value, fallback, max) {
  const number = value === undefined ? fallback : value;
  if (!Number.isInteger(number) || number < 1 || number > max) {
    throw new RangeError(`Expected an integer between 1 and ${max}`);
  }
  return number;
}

export function identifyFileType(bytes, extension = '') {
  const magic = bytes.subarray(0, 4).toString('hex');
  if (magic === '7f454c46') return 'elf';
  if (['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe'].includes(magic)) return 'macho';
  if (['cafebabe', 'bebafeca'].includes(magic) && bytes.length >= 8) {
    const count = magic === 'cafebabe' ? bytes.readUInt32BE(4) : bytes.readUInt32LE(4);
    if (count > 0 && count <= 32) return 'macho';
  }
  if (bytes.subarray(0, 2).toString() === 'MZ' && bytes.length >= 0x40) {
    const peOffset = bytes.readUInt32LE(0x3c);
    if (peOffset + 4 <= bytes.length && bytes.toString('ascii', peOffset, peOffset + 4) === 'PE\0\0') return 'pe';
  }
  if (magic === '0061736d') return 'unsupported-wasm';
  if (magic === 'cafebabe' || extension === '.class') return 'unsupported-bytecode';
  if (['.asar', '.bin', '.fw'].includes(extension)) return 'unsupported-packed';
  if (magic.startsWith('504b03') || magic.startsWith('504b05')) return 'unsupported-packed';
  if (['.js', '.mjs', '.cjs', '.ts', '.txt', '.json', '.py'].includes(extension) ||
      (bytes.length && !bytes.includes(0) && bytes.subarray(0, 256).toString('utf8').includes('\n'))) {
    return 'text';
  }
  return 'unknown';
}

export class BinaryAnalyzer {
  constructor(config = {}) {
    this.config = config;
    this.allowedRoots = config.allowedRoots?.map(root => realpathSync(resolve(root))) || null;
    this.tools = this.detectTools();
  }

  detectTools() {
    const tools = {};
    const check = (name) => {
      const result = spawnSync('which', [name], { timeout: 1000, stdio: 'ignore' });
      return result.status === 0;
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

  runTool(name, args) {
    if (!this.tools[name]) throw new Error(`Required tool unavailable: ${name}`);
    return execFileSync(name, args, {
      encoding: 'utf8',
      timeout: TOOL_TIMEOUT_MS,
      maxBuffer: MAX_TOOL_OUTPUT,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  }

  validateTarget(targetPath) {
    if (typeof targetPath !== 'string' || !targetPath || targetPath.length > 4096 ||
        targetPath.includes('\0')) {
      throw new Error('Invalid target path');
    }
    if (!existsSync(targetPath)) {
      throw new Error(`Target not found: ${targetPath}`);
    }
    const safePath = realpathSync(resolve(targetPath));
    if (this.allowedRoots && !this.allowedRoots.some(root =>
      safePath === root || safePath.startsWith(`${root}${sep}`)
    )) throw new Error('Target outside allowed roots');
    const stats = statSync(safePath);
    if (!stats.isFile()) throw new Error(`Target must be a regular file: ${targetPath}`);
    if (stats.size > MAX_FILE_BYTES) throw new Error(`Target exceeds ${MAX_FILE_BYTES} bytes`);
    return safePath;
  }

  async analyze(targetPath, options = {}) {
    const safePath = this.validateTarget(targetPath);
    const stats = statSync(safePath);
    const sha256 = () => createHash('sha256').update(readFileSync(safePath)).digest('hex');
    const targetHash = sha256();
    const fileType = await this.getFileType(safePath);
    if (!['elf', 'macho', 'pe'].includes(fileType)) {
      throw new Error(`Unsupported target format: ${fileType}`);
    }
    const minLength = boundedInteger(options.stringsMinLen, 6, 64);

    const analysis = {
      target: {
        path: safePath,
        name: basename(safePath),
        size: stats.size,
        type: fileType,
        sha256: targetHash
      },
      headers: null,
      sections: [],
      symbols: [],
      imports: [],
      exports: [],
      strings: [],
      functions: [],
      security: {},
      warnings: [],
      truncated: {}
    };

    // Parallel extraction
    const [headers, symbols, strings, sections] = await Promise.all([
      this.extractHeaders(safePath, fileType),
      this.extractSymbols(safePath),
      this.extractStrings(safePath, minLength),
      this.extractSections(safePath, fileType)
    ]);

    analysis.headers = headers;
    analysis.symbols = symbols;
    analysis.strings = strings;
    analysis.sections = sections;
    analysis.truncated = {
      symbols: Boolean(symbols.truncated),
      strings: Boolean(strings.truncated),
      headers: Boolean(headers.truncated)
    };

    // Categorize symbols
    analysis.imports = symbols.filter(s => s.type === 'U' || s.imported);
    analysis.exports = symbols.filter(s => s.type === 'T' || s.exported);
    analysis.functions = symbols.filter(s =>
      s.type === 'T' || s.type === 't' || s.name?.includes('func') || s.name?.includes('sub_')
    );

    // Security checks
    analysis.security = await this.checkSecurity(safePath, fileType, headers, symbols);
    analysis.warnings = [
      headers.error,
      symbols.error,
      strings.error,
      sections.error
    ].filter(Boolean);
    if (sha256() !== targetHash) throw new Error('Target changed during analysis');

    return analysis;
  }

  async getFileType(targetPath) {
    const safePath = this.validateTarget(targetPath);
    const header = Buffer.alloc(4096);
    const fd = openSync(safePath, 'r');
    let length;
    try {
      length = readSync(fd, header, 0, header.length, 0);
    } finally {
      closeSync(fd);
    }
    return identifyFileType(header.subarray(0, length), extname(safePath).toLowerCase());
  }

  async extractHeaders(targetPath, fileType) {
    const headers = { raw: '', parsed: {} };

    try {
      if (!this.tools.objdump && !(fileType === 'macho' && this.tools.otool)) {
        throw new Error('No compatible header tool available');
      }
      if (fileType === 'macho' && this.tools.otool) {
        headers.raw = this.runTool('otool', ['-h', targetPath]);
        const commands = this.runTool('otool', ['-l', targetPath]).split('\n');
        headers.truncated = commands.length > 200;
        headers.load_commands = commands.slice(0, 200).join('\n');
      } else if (this.tools.objdump) {
        headers.raw = this.runTool('objdump', ['-f', targetPath]);
        const all = this.runTool('objdump', ['-x', targetPath]).split('\n');
        headers.truncated = all.length > 100;
        headers.all = all.slice(0, 100).join('\n');
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
      if (!this.tools.nm) throw new Error('nm unavailable');
      let output = '';

      if (this.tools.nm) {
        output = this.runTool('nm', ['-a', targetPath]);
      }

      const seen = new Set();
      const lines = output.split('\n');
      symbols.truncated = lines.length > 1000;
      for (const line of lines.slice(0, 1000)) {
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
      symbols.error = `Symbol extraction failed: ${e.message}`;
    }

    return symbols;
  }

  async extractStrings(targetPath, minLen = 6) {
    const strings = [];

    try {
      if (!this.tools.strings) throw new Error('strings unavailable');
      if (this.tools.strings) {
        const output = this.runTool('strings', ['-n', String(boundedInteger(minLen, 6, 64)), targetPath]);

        const lines = output.split('\n');
        strings.truncated = lines.length > 500;
        for (const str of lines.slice(0, 500)) {
          if (!str) continue;

          const classified = this.classifyString(str);
          strings.push({
            value: str,
            ...classified
          });
        }
      }
    } catch (e) {
      strings.error = `String extraction failed: ${e.message}`;
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
      if (!this.tools.objdump) throw new Error('objdump unavailable');
      let output = '';

      // objdump -h produces the same section table format for ELF and Mach-O,
      // which the regex below parses. otool -l output has a different layout.
      if (this.tools.objdump) {
        output = this.runTool('objdump', ['-h', targetPath]);
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
      sections.error = `Section extraction failed: ${e.message}`;
    }

    return sections;
  }

  async checkSecurity(targetPath, fileType, headers, symbols = []) {
    const security = {
      pie: null,
      nx: null,
      canary: null,
      relro: fileType === 'elf' ? 'unknown' : 'n/a',
      stripped: null,
      fortify: null
    };

    if (!symbols.error) {
      const canary = symbols.some(s => s.name?.includes('__stack_chk'));
      const fortify = symbols.some(s =>
        s.name?.includes('__fortify') ||
        (s.name?.includes('_chk') && !s.name.includes('stack_chk'))
      );
      security.canary = canary || (symbols.truncated ? null : false);
      security.fortify = fortify || (symbols.truncated ? null : false);
    }
    let fileDescription = '';
    if (this.tools.file) {
      try {
        fileDescription = this.runTool('file', ['-b', targetPath]);
        if (/\bnot stripped\b/i.test(fileDescription)) security.stripped = false;
        else if (/\bstripped\b/i.test(fileDescription)) security.stripped = true;
      } catch {
        // Stripping status is not inferred from symbol count.
      }
    }
    if (security.stripped === true || symbols.length === 0) {
      if (security.canary === false) security.canary = null;
      if (security.fortify === false) security.fortify = null;
    }
    if (fileType === 'macho' && this.tools.otool) {
      try {
          const hdr = this.runTool('otool', ['-hv', targetPath]);
          security.pie = hdr.includes('PIE');
          security.nx = !hdr.includes('ALLOW_STACK_EXECUTION');
      } catch {
        // Unknown is safer than claiming the mitigation is absent.
      }
    } else if (fileType === 'elf' && this.tools.objdump) {
      if (headers?.raw && !headers.error) {
        if (/\bEXEC_P\b/i.test(headers.raw)) security.pie = false;
        else if (/\bDYNAMIC\b|\bDYN\b/i.test(headers.raw)) {
          if (/pie executable|position.independent executable/i.test(fileDescription)) security.pie = true;
          // ET_DYN alone may be a shared object, not a PIE executable.
        }
      }
      try {
        const program = this.runTool('objdump', ['-p', targetPath]);
        const lines = program.split('\n');
        const stackIndex = lines.findIndex(line => /\b(?:GNU_)?STACK\b/i.test(line));
        if (stackIndex >= 0) {
          const stack = `${lines[stackIndex]} ${lines[stackIndex + 1] || ''}`;
          const permissions = stack.match(/(?:^|\s)(rwx|rw-|r-x|r--|RWE|RW|RE)(?=\s|$)/i);
          if (permissions) security.nx = !/[xe]/i.test(permissions[1]);
        }
        const relro = /\bGNU_RELRO\b|\bRELRO\b/i.test(program);
        const bindNow = /\bBIND_NOW\b|\bFLAGS(?:_1)?\s+.*\bNOW\b/i.test(program);
        security.relro = relro ? (bindNow ? 'full' : 'partial') : 'none';
      } catch {
        // Leave NX and RELRO unknown on tool failure.
      }
    }

    return security;
  }

  async disassemble(targetPath, options = {}) {
    const safePath = this.validateTarget(targetPath);
    const type = await this.getFileType(safePath);
    if (!['elf', 'macho', 'pe'].includes(type)) throw new Error(`Unsupported target format: ${type}`);
    const limit = boundedInteger(options.limit, 500, 500);
    if (options.function && !/^[A-Za-z0-9_.$@+-]{1,128}$/.test(options.function)) {
      throw new Error('Invalid function name');
    }
    const result = { functions: [], raw: '', truncated: false };

    try {
      if (!this.tools.objdump) throw new Error('objdump unavailable');
      const lines = this.runTool('objdump', ['-d', safePath]).split('\n');
      const start = options.function
        ? lines.findIndex(line => line.includes(`<${options.function}>:`))
        : 0;
      if (start < 0) throw new Error(`Function not found: ${options.function}`);
      result.truncated = lines.length - start > limit;
      result.raw = lines.slice(start, start + limit).join('\n');
    } catch (e) {
      result.error = e.message;
    }

    return result;
  }
}

export default BinaryAnalyzer;
