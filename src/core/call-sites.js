import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { boundedInteger } from './binary-analyzer.js';

const DEFAULT_SINKS = [
  'strcpy', 'strcat', 'sprintf', 'printf', 'system', 'popen', 'execve',
  'read', 'recv', 'gets', 'memcpy', 'malloc', 'free'
];

function normalizedSymbol(value) {
  return value.replace(/^_+/, '').replace(/@(?:plt|PLT|.*)$/, '');
}

export function decodeInstruction(line) {
  const match = line.match(/^\s*([0-9a-f]{4,16}):\s*((?:(?:[0-9a-f]{2}\s+){1,16}|[0-9a-f]{8}\s+))([a-z][a-z0-9_.]*)\s*(.*)$/i);
  if (!match) return null;
  return {
    address: match[1].toLowerCase(),
    bytes: match[2].trim().replace(/\s+/g, '').toLowerCase(),
    mnemonic: match[3].toLowerCase(),
    operands: match[4].trim()
  };
}

function callTarget(operands) {
  const stub = operands.match(/(?:symbol stub for:\s*|<)([_A-Za-z.$][\w.$@+-]*)(?:>)?/i);
  if (stub) return normalizedSymbol(stub[1]);
  const direct = operands.match(/(?:^|\s)([_A-Za-z.$][\w.$@+-]*)$/);
  return direct ? normalizedSymbol(direct[1]) : null;
}

export class CallSiteExtractor {
  constructor(analyzer) {
    this.analyzer = analyzer;
  }

  parse(disassembly, targetSha256, providerVersion, options = {}) {
    const limit = boundedInteger(options.limit, 100, 200);
    const requestedArch = options.arch || 'all';
    if (!['all', 'x86_64', 'arm64', 'arm64e'].includes(requestedArch)) {
      throw new Error('Invalid architecture');
    }
    const sinks = options.sinks === undefined ? DEFAULT_SINKS : options.sinks;
    if (!Array.isArray(sinks) || sinks.length > 32 ||
        sinks.some(name => typeof name !== 'string' || !/^[A-Za-z_][\w.$@+-]{0,127}$/.test(name))) {
      throw new Error('Invalid sink names');
    }
    const wanted = new Set(sinks.map(normalizedSymbol));
    const lines = disassembly.split('\n');
    const maxLines = 25_000;
    const calls = [];
    let section = null;
    let arch = null;
    let caller = null;
    let decoded = 0;
    let indirect = 0;
    for (const line of lines.slice(0, maxLines)) {
      const architecture = line.match(/\(architecture ([\w-]+)\):/);
      if (architecture) {
        arch = architecture[1];
        caller = null;
        section = null;
        continue;
      }
      const sectionHeader = line.match(/^Disassembly of section ([\w.,-]+):/) ||
        line.match(/^\(([\w]+),([\w]+)\) section$/);
      if (sectionHeader) {
        section = sectionHeader[2] || sectionHeader[1];
        caller = null;
        continue;
      }
      const functionHeader = line.match(/^\s*[0-9a-f]+\s+<([^>]+)>:$/i) ||
        line.match(/^([_A-Za-z.$][\w.$@+-]*):$/);
      if (functionHeader) {
        caller = functionHeader[1].slice(0, 128);
        continue;
      }
      if (section && !/^(?:__text|\.text(?:\..*)?)$/.test(section)) continue;
      if (arch && requestedArch !== 'all' && arch !== requestedArch &&
          !(requestedArch === 'arm64' && arch === 'arm64e')) continue;
      const item = decodeInstruction(line);
      if (!item) continue;
      decoded++;
      if (!/^(?:callq?|bl|blr|jmpq?|b)$/.test(item.mnemonic)) continue;
      if (item.mnemonic === 'b' && !/symbol stub for:/.test(item.operands)) continue;
      const direct = !/^(?:blr)$/.test(item.mnemonic) &&
        !/(?:^|\s)[*%]|(?:^|\s)[xw]\d+$|\([^)]*\)/i.test(item.operands);
      const callee = direct ? callTarget(item.operands) : null;
      if (!direct || !callee) indirect++;
      if (wanted.size && !wanted.has(callee)) continue;
      if (!callee && wanted.size) continue;
      if (/^(?:jmp|b$)/.test(item.mnemonic) && !/stub for:|<[^>]+>/.test(item.operands)) continue;
      if (calls.length >= limit) continue;
      const location = `0x${item.address}`;
      const detail = `${item.mnemonic} ${item.operands}`.slice(0, 256);
      const id = `call-${createHash('sha256').update(
        `${targetSha256}:${arch || ''}:${location}:${item.bytes}:${detail}`
      ).digest('hex').slice(0, 24)}`;
      calls.push({
        address: location,
        section: section || 'unknown',
        arch,
        caller,
        callee,
        kind: callee ? (/^(?:jmp|b$)/.test(item.mnemonic) ? 'tail_call' : 'direct_call') : 'indirect_call',
        flow_status: 'unknown',
        evidence: {
          id, target_sha256: targetSha256, status: 'observed',
          location_kind: 'call-site', provider: 'objdump',
          provider_version: providerVersion, location, detail,
          instruction_bytes: item.bytes, truncated: false
        }
      });
    }
    return {
      status: decoded ? 'observed' : 'unknown',
      calls,
      decoded_instructions: decoded,
      unresolved_calls: indirect,
      truncated: lines.length > maxLines || calls.length >= limit,
      architecture: requestedArch,
      vulnerability_status: 'unverified',
      note: 'A call instruction does not establish attacker control, data flow, or a vulnerability.'
    };
  }

  async trace(binaryAnalysis, options = {}) {
    if (!binaryAnalysis?.target?.sha256 || !/^[0-9a-f]{64}$/i.test(binaryAnalysis.target.sha256)) {
      throw new Error('An analyzed target and SHA-256 identity are required');
    }
    boundedInteger(options.limit, 100, 200);
    if (options.arch && !['host', 'all', 'x86_64', 'arm64', 'arm64e'].includes(options.arch)) {
      throw new Error('Invalid architecture');
    }
    if (options.sinks !== undefined &&
        (!Array.isArray(options.sinks) || options.sinks.length > 32 ||
          options.sinks.some(name => typeof name !== 'string' ||
            !/^[A-Za-z_][\w.$@+-]{0,127}$/.test(name)))) {
      throw new Error('Invalid sink names');
    }
    const safePath = this.analyzer.validateTarget(binaryAnalysis.target.path);
    const current = await this.analyzer.getFileType(safePath);
    if (current !== binaryAnalysis.target.type) throw new Error('Target format changed during tracing');
    try {
      const raw = this.analyzer.runTool('objdump', ['-d', safePath]);
      let version = 'unknown';
      try {
        version = this.analyzer.runTool('objdump', ['--version']).split('\n')[0].slice(0, 120) || 'unknown';
      } catch {
        // Some host objdump variants do not support --version.
      }
      const hostArch = process.arch === 'x64' ? 'x86_64' : process.arch;
      const arch = binaryAnalysis.target.type === 'macho' ?
        (options.arch === 'host' || !options.arch ? hostArch : options.arch) : 'all';
      const result = this.parse(raw, binaryAnalysis.target.sha256, version, {
        ...options, arch
      });
      const currentHash = createHash('sha256').update(readFileSync(safePath)).digest('hex');
      if (currentHash !== binaryAnalysis.target.sha256) {
        throw new Error('Target changed during tracing');
      }
      return { target: binaryAnalysis.target, ...result };
    } catch (error) {
      if (/Target changed during tracing/.test(error.message)) throw error;
      return {
        target: binaryAnalysis.target, status: 'unknown', calls: [],
        truncated: /ENOBUFS|maxBuffer/.test(error.message),
        vulnerability_status: 'unverified', error: `Call-site extraction incomplete: ${error.message}`
      };
    }
  }
}
