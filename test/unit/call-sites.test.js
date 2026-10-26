import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CallSiteExtractor } from '../../src/core/call-sites.js';
import { isVerifiedFinding } from '../../src/core/evidence.js';

const sha256 = 'a'.repeat(64);
const elf = `sample: file format elf64-x86-64
Disassembly of section .text:
0000000000401000 <main>:
  401000: 48 8d 3d 20 00 00 00 leaq 0x20(%rip), %rdi
  401007: e8 34 00 00 00 callq 401040 <printf@plt>
  40100c: ff d0 callq *%rax
  40100e: c3 retq
`;
const macho = `/bin/test (architecture x86_64):
(__TEXT,__text) section
100000000: 48 89 e5 movq %rsp, %rbp
100000003: e8 11 00 00 00 callq 0x100000019 ## symbol stub for: _strcpy
(__TEXT,__stubs) section
100000019: ff 25 00 00 00 00 jmpq *0x0(%rip)
`;

test('GNU direct calls identify call sites, not vulnerability or flow', () => {
  const extractor = new CallSiteExtractor({});
  const result = extractor.parse(elf, sha256, 'GNU objdump 2.40', { sinks: ['printf'] });
  assert.equal(result.status, 'observed');
  assert.equal(result.calls.length, 1);
  assert.equal(result.calls[0].callee, 'printf');
  assert.equal(result.calls[0].caller, 'main');
  assert.equal(result.calls[0].flow_status, 'unknown');
  assert.equal(result.vulnerability_status, 'unverified');
  assert.equal(result.calls[0].evidence.target_sha256, sha256);
  assert.equal(result.calls[0].evidence.provider_version, 'GNU objdump 2.40');
  assert.match(result.calls[0].evidence.instruction_bytes, /^e8/);
  assert.equal(isVerifiedFinding({
    id: 'fake', status: 'observed', evidence_ids: [result.calls[0].evidence.id]
  }, { target: { sha256 }, evidence: [result.calls[0].evidence] }), false);
});

test('Mach-O symbol stubs resolve without treating a stub as a vulnerable call', () => {
  const extractor = new CallSiteExtractor({});
  const result = extractor.parse(macho, sha256, 'Apple objdump', { sinks: ['strcpy'] });
  assert.equal(result.calls.length, 1);
  assert.equal(result.calls[0].callee, 'strcpy');
  assert.equal(result.calls[0].section, '__text');
  assert.equal(result.calls[0].arch, 'x86_64');
});

test('host ARM64 selection includes arm64e but excludes fat-binary x86_64 calls', () => {
  const fat = `${macho}/bin/test (architecture arm64e):
(__TEXT,__text) section
100000700: e9 09 00 94 bl 0x100004684 ; symbol stub for: _strcpy
`;
  const result = new CallSiteExtractor({}).parse(fat, sha256, 'Apple objdump',
    { sinks: ['strcpy'], arch: 'arm64' });
  assert.equal(result.calls.length, 1);
  assert.equal(result.calls[0].arch, 'arm64e');
  assert.equal(result.calls[0].kind, 'direct_call');
});

test('unresolved indirect calls and incomplete disassembly remain explicit', () => {
  const extractor = new CallSiteExtractor({});
  const result = extractor.parse(elf, sha256, 'GNU objdump', { sinks: [] });
  assert.equal(result.unresolved_calls, 1);
  assert.ok(result.calls.some(call => call.kind === 'indirect_call' && call.callee === null));
  const missing = extractor.parse('disassembly unavailable', sha256, 'unknown');
  assert.equal(missing.status, 'unknown');
  assert.deepEqual(missing.calls, []);
  assert.throws(() => extractor.parse(elf, sha256, 'unknown', { sinks: ['$(bad)'] }),
    /Invalid sink/);
});
