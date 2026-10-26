import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { boundedInteger } from './binary-analyzer.js';
import { decodeInstruction } from './call-sites.js';

function safeNumber(bigint) {
  if (bigint > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('ELF offset exceeds safe integer range');
  return Number(bigint);
}

function executableSections(bytes) {
  if (bytes.length < 64 || bytes.toString('hex', 0, 4) !== '7f454c46' ||
      bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== 62) {
    throw new Error('Only little-endian ELF64 x86_64 is supported');
  }
  const shoff = safeNumber(bytes.readBigUInt64LE(0x28));
  const entrySize = bytes.readUInt16LE(0x3a);
  const count = bytes.readUInt16LE(0x3c);
  const stringsIndex = bytes.readUInt16LE(0x3e);
  if (entrySize < 64 || count < 2 || count > 512 || stringsIndex >= count ||
      shoff + entrySize * count > bytes.length) {
    throw new Error('ELF section headers are absent or malformed');
  }
  const namesHeader = shoff + stringsIndex * entrySize;
  const namesOffset = safeNumber(bytes.readBigUInt64LE(namesHeader + 24));
  const namesSize = safeNumber(bytes.readBigUInt64LE(namesHeader + 32));
  if (namesOffset + namesSize > bytes.length || namesSize > 1024 * 1024) {
    throw new Error('ELF section names are missing or oversized');
  }
  const ranges = [];
  let totalSize = 0;
  for (let index = 1; index < count; index++) {
    const header = shoff + index * entrySize;
    if (bytes.readUInt32LE(header + 4) !== 1 ||
        !(bytes.readBigUInt64LE(header + 8) & 4n)) continue;
    const vaddr = safeNumber(bytes.readBigUInt64LE(header + 16));
    const offset = safeNumber(bytes.readBigUInt64LE(header + 24));
    const size = safeNumber(bytes.readBigUInt64LE(header + 32));
    const nameOffset = bytes.readUInt32LE(header);
    if (vaddr + size > Number.MAX_SAFE_INTEGER ||
        offset + size > bytes.length || nameOffset >= namesSize) {
      throw new Error('Executable section extends outside ELF image');
    }
    const first = namesOffset + nameOffset;
    const end = bytes.indexOf(0, first);
    if (end < first || end >= namesOffset + namesSize) {
      throw new Error('Invalid ELF section name');
    }
    totalSize += size;
    if (totalSize > 4 * 1024 * 1024) {
      throw new Error('Executable sections exceed gadget inspection budget');
    }
    ranges.push({
      name: bytes.toString('utf8', first, end).slice(0, 64), vaddr, offset, size
    });
  }
  if (!ranges.length) throw new Error('No executable ELF sections');
  return ranges;
}

function gadgetKind(previous, ending) {
  if (/^retq?$/.test(ending.mnemonic) && /^popq?$/.test(previous.mnemonic) &&
      /^%?rsp$/.test(previous.operands)) return 'stack_pivot';
  if (/^retq?$/.test(ending.mnemonic) && /^popq?$/.test(previous.mnemonic) &&
      /^%?(?:r(?:ax|bx|cx|dx|di|si|bp|[8-9]|1[0-5]))$/.test(previous.operands)) {
    return 'register_setup';
  }
  if (/^retq?$/.test(ending.mnemonic) && /^leaveq?$/.test(previous.mnemonic)) {
    return 'stack_pivot';
  }
  if (/^retq?$/.test(ending.mnemonic) && previous.mnemonic === 'syscall') {
    return 'syscall';
  }
  return null;
}

export class GadgetCandidateFinder {
  constructor(analyzer) {
    this.analyzer = analyzer;
  }

  parse(bytes, disassembly, targetSha256, providerVersion, options = {}) {
    const limit = boundedInteger(options.limit, 50, 100);
    const sections = executableSections(bytes);
    const candidates = [];
    const lines = disassembly.split('\n');
    let last = null;
    let decoded = 0;
    let invalidBytes = 0;
    for (const line of lines.slice(0, 25_000)) {
      const item = decodeInstruction(line);
      if (!item) {
        if (line.includes('Disassembly of section')) last = null;
        continue;
      }
      const address = Number.parseInt(item.address, 16);
      if (!Number.isSafeInteger(address)) {
        last = null;
        continue;
      }
      const section = sections.find(range => address >= range.vaddr &&
        address < range.vaddr + range.size);
      if (!section || item.bytes.length % 2 !== 0 || !item.bytes.length) {
        last = null;
        continue;
      }
      const offset = section.offset + address - section.vaddr;
      const buffer = Buffer.from(item.bytes, 'hex');
      if (offset + buffer.length > section.offset + section.size ||
          !bytes.subarray(offset, offset + buffer.length).equals(buffer)) {
        invalidBytes++;
        last = null;
        continue;
      }
      decoded++;
      if (last && last.section === section &&
          last.offset + last.buffer.length === offset) {
        const kind = gadgetKind(last.item, item);
        if (kind && candidates.length < limit) {
          const location = `0x${last.item.address}`;
          const detail = `${last.item.mnemonic} ${last.item.operands}; ${item.mnemonic}`.slice(0, 256);
          candidates.push({
            kind,
            image_address: location,
            file_offset: last.offset,
            runtime_address: null,
            section: section.name,
            landing_constraints: 'unknown (CET/IBT and runtime permissions not checked)',
            evidence: {
              id: `gadget-${createHash('sha256').update(
                `${targetSha256}:${last.offset}:${detail}`
              ).digest('hex').slice(0, 24)}`,
              target_sha256: targetSha256, status: 'observed',
              location_kind: 'gadget', location, detail,
              provider: 'objdump + original file bytes',
              provider_version: providerVersion,
              file_offset: last.offset, bytes: `${last.item.bytes}${item.bytes}`,
              truncated: false
            }
          });
        }
      }
      last = { item, offset, buffer, section };
    }
    return {
      status: decoded ? 'observed_candidates' : 'unknown',
      candidates,
      decoded_instructions: decoded,
      rejected_byte_mismatches: invalidBytes,
      truncated: lines.length > 25_000 || candidates.length >= limit,
      note: 'Original bytes and decoded boundaries match. Reachability, PIE load base, CET, and exploitability are unknown.'
    };
  }

  async find(binaryAnalysis, options = {}) {
    const limit = boundedInteger(options.limit, 50, 100);
    if (!/^[0-9a-f]{64}$/i.test(binaryAnalysis?.target?.sha256 || '')) {
      throw new Error('An analyzed target and SHA-256 identity are required');
    }
    if (binaryAnalysis.target.type !== 'elf') {
      return {
        target: binaryAnalysis.target, status: 'unsupported', candidates: [],
        note: 'Byte-verified gadgets currently require ELF64 x86_64.'
      };
    }
    const safePath = this.analyzer.validateTarget(binaryAnalysis.target.path);
    try {
      const bytes = readFileSync(safePath);
      const imageHash = createHash('sha256').update(bytes).digest('hex');
      if (imageHash !== binaryAnalysis.target.sha256) throw new Error('Target changed during gadget search');
      let version = 'unknown';
      try {
        version = this.analyzer.runTool('objdump', ['--version']).split('\n')[0].slice(0, 120) ||
          'unknown';
      } catch {
        // Tool variants may reject the version option while still supporting disassembly.
      }
      const disassembly = this.analyzer.runTool('objdump', ['-d', safePath]);
      const result = this.parse(bytes, disassembly, imageHash, version, { limit });
      const current = createHash('sha256').update(readFileSync(safePath)).digest('hex');
      if (current !== imageHash) throw new Error('Target changed during gadget search');
      return { target: binaryAnalysis.target, ...result };
    } catch (error) {
      if (/Target changed/.test(error.message)) throw error;
      return {
        target: binaryAnalysis.target, status: 'unknown', candidates: [],
        truncated: /ENOBUFS|maxBuffer/.test(error.message),
        error: `Gadget inspection incomplete: ${error.message}`
      };
    }
  }
}
