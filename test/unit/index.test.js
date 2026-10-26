import { test } from 'node:test';
import assert from 'node:assert/strict';

// Sub-modules (AgentSwarm, etc.) instantiate the Anthropic SDK in their
// constructors, which requires an API key to be present. Set a dummy key so
// construction succeeds — no network calls are made by these tests.
process.env.ANTHROPIC_API_KEY ||= 'test-dummy-key';

const { AdversarialREA } = await import('../../src/index.js');

test('detectTargetType() maps PE family extensions', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('a.exe'), 'pe');
  assert.equal(await rea.detectTargetType('a.dll'), 'pe');
  assert.equal(await rea.detectTargetType('a.sys'), 'pe-driver');
});

test('detectTargetType() maps ELF / shared / macho extensions', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('a.elf'), 'elf');
  assert.equal(await rea.detectTargetType('a.so'), 'elf-shared');
  assert.equal(await rea.detectTargetType('a.dylib'), 'macho-shared');
});

test('detectTargetType() maps mobile package extensions', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('app.apk'), 'android');
  assert.equal(await rea.detectTargetType('app.ipa'), 'ios');
});

test('detectTargetType() maps wasm and firmware extensions', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('m.wasm'), 'webassembly');
  assert.equal(await rea.detectTargetType('f.bin'), 'firmware');
  assert.equal(await rea.detectTargetType('f.fw'), 'firmware');
});

test('detectTargetType() returns "unknown" for unrecognized extensions', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('notes.txt'), 'unknown');
  assert.equal(await rea.detectTargetType('noextension'), 'unknown');
});

test('detectTargetType() is case-insensitive', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('A.EXE'), 'pe');
  assert.equal(await rea.detectTargetType('path/to/B.Dll'), 'pe');
});

test('detectTargetType() uses the final extension for multi-dot names', async () => {
  const rea = new AdversarialREA();
  assert.equal(await rea.detectTargetType('lib.v1.2.so'), 'elf-shared');
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
