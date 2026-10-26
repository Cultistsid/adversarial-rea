import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { GadgetCandidateFinder } from '../../src/core/gadget-candidates.js';

function elfFixture() {
  const bytes = Buffer.alloc(0x300);
  Buffer.from('7f454c46', 'hex').copy(bytes);
  bytes[4] = 2;
  bytes[5] = 1;
  bytes.writeUInt16LE(62, 18);
  bytes.writeBigUInt64LE(0x180n, 0x28);
  bytes.writeUInt16LE(64, 0x3a);
  bytes.writeUInt16LE(3, 0x3c);
  bytes.writeUInt16LE(2, 0x3e);
  Buffer.from('5fc3c9c30f05c3', 'hex').copy(bytes, 0x100);
  const names = Buffer.from('\0.text\0.shstrtab\0');
  names.copy(bytes, 0x140);
  const text = 0x180 + 64;
  bytes.writeUInt32LE(1, text);
  bytes.writeUInt32LE(1, text + 4);
  bytes.writeBigUInt64LE(4n, text + 8);
  bytes.writeBigUInt64LE(0x401000n, text + 16);
  bytes.writeBigUInt64LE(0x100n, text + 24);
  bytes.writeBigUInt64LE(7n, text + 32);
  const shstr = 0x180 + 128;
  bytes.writeUInt32LE(7, shstr);
  bytes.writeBigUInt64LE(0x140n, shstr + 24);
  bytes.writeBigUInt64LE(BigInt(names.length), shstr + 32);
  return bytes;
}

const disassembly = `Disassembly of section .text:
0000000000401000 <fixture>:
  401000: 5f popq %rdi
  401001: c3 retq
  401002: c9 leaveq
  401003: c3 retq
  401004: 0f 05 syscall
  401006: c3 retq
`;

test('ELF gadget candidates map decoded instructions to original executable bytes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-gadgets-'));
  try {
    const path = join(dir, 'fixture.elf');
    const bytes = elfFixture();
    writeFileSync(path, bytes);
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const analyzer = new BinaryAnalyzer();
    analyzer.tools.objdump = true;
    analyzer.runTool = (_, args) => args[0] === '-d' ? disassembly : 'objdump fixture v1';
    const finder = new GadgetCandidateFinder(analyzer);
    const result = await finder.find({ target: { path, type: 'elf', sha256 } });
    assert.equal(result.status, 'observed_candidates');
    assert.deepEqual(result.candidates.map(item => item.kind),
      ['register_setup', 'stack_pivot', 'syscall']);
    assert.equal(result.candidates[0].file_offset, 0x100);
    assert.equal(result.candidates[0].runtime_address, null);
    assert.equal(result.candidates[0].evidence.bytes, '5fc3');
    assert.equal(result.candidates[0].evidence.target_sha256, sha256);

    const wrongBytes = finder.parse(bytes, disassembly.replace('5f popq', '58 popq'),
      sha256, 'fixture v1');
    assert.equal(wrongBytes.rejected_byte_mismatches, 1);
    assert.ok(wrongBytes.candidates.every(item => item.kind !== 'register_setup'));
    const unsupported = await finder.find({ target: { path, type: 'macho', sha256 } });
    assert.equal(unsupported.status, 'unsupported');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
