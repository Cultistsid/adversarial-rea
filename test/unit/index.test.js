import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Sub-modules (AgentSwarm, etc.) instantiate the Anthropic SDK in their
// constructors, which requires an API key to be present. Set a dummy key so
// construction succeeds — no network calls are made by these tests.
process.env.ANTHROPIC_API_KEY ||= 'test-dummy-key';

const { AdversarialREA } = await import('../../src/index.js');

test('detectTargetType() uses native magic, not misleading extensions', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-magic-'));
  const rea = new AdversarialREA();
  try {
    const elf = join(dir, 'native.exe');
    const macho = join(dir, 'native.apk');
    const pe = join(dir, 'native.so');
    const js = join(dir, 'plain.exe');
    const zip = join(dir, 'bundle.ipa');
    const wasm = join(dir, 'bytecode.wasm');
    const firmware = join(dir, 'image.bin');
    writeFileSync(elf, Buffer.from('7f454c4600000000', 'hex'));
    writeFileSync(macho, Buffer.from('feedfacf00000000', 'hex'));
    const peBytes = Buffer.alloc(256);
    peBytes.write('MZ', 0);
    peBytes.writeUInt32LE(0x80, 0x3c);
    peBytes.write('PE\0\0', 0x80, 'binary');
    writeFileSync(pe, peBytes);
    writeFileSync(js, 'console.log("not PE");\n');
    writeFileSync(zip, Buffer.from('504b0304000000', 'hex'));
    writeFileSync(wasm, Buffer.from('0061736d01000000', 'hex'));
    writeFileSync(firmware, Buffer.from('0102030405', 'hex'));
    assert.equal(await rea.detectTargetType(elf), 'elf');
    assert.equal(await rea.detectTargetType(macho), 'macho');
    assert.equal(await rea.detectTargetType(pe), 'pe');
    assert.equal(await rea.detectTargetType(js), 'text');
    assert.equal(await rea.detectTargetType(zip), 'unsupported-packed');
    assert.equal(await rea.detectTargetType(wasm), 'unsupported-wasm');
    assert.equal(await rea.detectTargetType(firmware), 'unsupported-packed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('detectTargetType() rejects missing input rather than guessing a suffix', async () => {
  const rea = new AdversarialREA();
  await assert.rejects(() => rea.detectTargetType('/nonexistent/rea.exe'), /Target not found/);
});

test('constructor sets default config', () => {
  const rea = new AdversarialREA();
  assert.equal(rea.config.model, 'claude-opus-5-5');
  assert.equal(rea.config.maxAgents, 8);
  assert.equal(rea.config.aggressiveMode, true);
  assert.equal(rea.config.parallelAnalysis, true);
  assert.equal(rea.config.timeout, 300000);
});

test('constructor respects overrides', () => {
  const rea = new AdversarialREA({
    model: 'custom-model',
    maxAgents: 3,
    aggressiveMode: false,
    parallelAnalysis: false,
    timeout: 1000
  });
  assert.equal(rea.config.model, 'custom-model');
  assert.equal(rea.config.maxAgents, 3);
  assert.equal(rea.config.aggressiveMode, false);
  assert.equal(rea.config.parallelAnalysis, false);
  assert.equal(rea.config.timeout, 1000);
});

test('constructor merges unknown config keys through', () => {
  const rea = new AdversarialREA({ customFlag: 'xyz' });
  assert.equal(rea.config.customFlag, 'xyz');
  // defaults still present
  assert.equal(rea.config.model, 'claude-opus-5-5');
});

test('constructor treats aggressiveMode:false as an explicit override (nullish coalescing)', () => {
  const rea = new AdversarialREA({ aggressiveMode: false });
  assert.equal(rea.config.aggressiveMode, false);
});

test('constructor wires up the sub-components', () => {
  const rea = new AdversarialREA();
  assert.ok(rea.swarm, 'swarm instantiated');
  assert.ok(rea.attackSurface, 'attackSurface instantiated');
  assert.ok(rea.exploitChain, 'exploitChain instantiated');
  assert.ok(rea.vulnHunter, 'vulnHunter instantiated');
});
