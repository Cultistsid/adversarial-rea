import { test } from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { AdversarialMCPServer } from '../../src/mcp/server.js';

test('a binary filename with shell substitutions cannot execute commands', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-safe-'));
  try {
    const marker = join(dir, 'executed');
    const binary = join(dir, 'ls"$(printf injected)".elf');
    copyFileSync('/bin/ls', binary);
    const analyzer = new BinaryAnalyzer();
    const result = await analyzer.analyze(binary);
    assert.ok(['elf', 'macho'].includes(result.target.type));
    assert.equal(existsSync(marker), false);
    const server = new AdversarialMCPServer();
    await assert.rejects(
      () => server.disassemble({ target_path: binary, function: `main"; touch ${marker}` }),
      /Invalid function name/
    );
    assert.equal(existsSync(marker), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('untrusted integers and packed/text inputs fail closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-formats-'));
  try {
    const analyzer = new BinaryAnalyzer();
    const server = new AdversarialMCPServer();
    const js = join(dir, 'app.exe');
    const wasm = join(dir, 'module.wasm');
    const zip = join(dir, 'app.apk');
    writeFileSync(js, 'console.log("hello");\n');
    writeFileSync(wasm, Buffer.from('0061736d01000000', 'hex'));
    writeFileSync(zip, Buffer.from('504b030400000000', 'hex'));
    assert.equal(await analyzer.getFileType(js), 'text');
    assert.equal(await analyzer.getFileType(wasm), 'unsupported-wasm');
    assert.equal(await analyzer.getFileType(zip), 'unsupported-packed');
    await assert.rejects(() => analyzer.analyze(js), /Unsupported target format: text/);
    await assert.rejects(() => analyzer.analyze(wasm), /Unsupported target format: unsupported-wasm/);
    await assert.rejects(() => analyzer.analyze(zip), /Unsupported target format: unsupported-packed/);
    await assert.rejects(() => analyzer.analyze('/bin/ls', { stringsMinLen: '6; touch /tmp/unsafe' }), /integer/);
    await assert.rejects(() => server.handleToolCall('disassemble', { target_path: '/bin/ls', limit: 1e9 }), /integer/);
    await assert.rejects(() => server.handleToolCall('analyze_binary', { target_path: dir }), /regular file/);
    await assert.rejects(() => analyzer.analyze('a'.repeat(5000)), /Invalid target path/);
    await assert.rejects(
      () => server.handleToolCall('get_symbols', { target_path: js, filter: 'x'.repeat(129) }),
      /Invalid symbol filter/
    );
    await assert.rejects(
      () => server.handleToolCall('get_strings', { target_path: js, category: 'x'.repeat(65) }),
      /Invalid string category/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('MCP refuses oversized responses rather than returning unbounded text', async () => {
  const server = new AdversarialMCPServer();
  server.analyzeBinary = async () => ({ success: true, output: 'x'.repeat(70_000) });
  await assert.rejects(
    () => server.handleToolCall('analyze_binary', { target_path: '/bin/ls' }),
    /response budget/
  );
});

test('optional filesystem roots reject both direct and symlink escapes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-roots-'));
  try {
    const local = join(dir, 'native');
    const escape = join(dir, 'outside');
    copyFileSync('/bin/ls', local);
    symlinkSync('/bin/ls', escape);
    const analyzer = new BinaryAnalyzer({ allowedRoots: [dir] });
    assert.ok((await analyzer.analyze(local)).target.sha256);
    await assert.rejects(() => analyzer.analyze('/bin/ls'), /outside allowed roots/);
    await assert.rejects(() => analyzer.analyze(escape), /outside allowed roots/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('size and subprocess output budgets reject oversized inputs', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-bounds-'));
  try {
    const large = join(dir, 'large.elf');
    writeFileSync(large, Buffer.from('7f454c46', 'hex'));
    truncateSync(large, 64 * 1024 * 1024 + 1);
    const analyzer = new BinaryAnalyzer();
    await assert.rejects(() => analyzer.analyze(large), /exceeds/);
    analyzer.tools[process.execPath] = true;
    assert.throws(
      () => analyzer.runTool(process.execPath, ['-e', "process.stdout.write('x'.repeat(3000000))"]),
      /ENOBUFS|maxBuffer/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('missing native tools do not become false hardening or stripping claims', async () => {
  const analyzer = new BinaryAnalyzer();
  analyzer.tools = Object.fromEntries(Object.keys(analyzer.tools).map(name => [name, false]));
  const result = await analyzer.analyze('/bin/ls');
  assert.equal(result.security.pie, null);
  assert.equal(result.security.nx, null);
  assert.equal(result.security.canary, null);
  assert.equal(result.security.stripped, null);
  assert.ok(result.warnings.some(warning => warning.includes('nm unavailable')));
  const disassembly = await analyzer.disassemble('/bin/ls');
  assert.match(disassembly.error, /objdump unavailable/);
  const server = new AdversarialMCPServer();
  server.analyzer = analyzer;
  const response = await server.disassemble({ target_path: '/bin/ls' });
  assert.equal(response.success, false);
  assert.equal(response.incomplete, true);
});

test('ELF full, partial, and absent RELRO use all program headers', async () => {
  const analyzer = new BinaryAnalyzer();
  analyzer.tools.objdump = true;
  analyzer.tools.file = false;
  const headers = { raw: 'flags 0x10: DYNAMIC' };
  const symbols = [];
  for (const [program, expected] of [
    ['STACK 0 rw-\nGNU_RELRO 0x1234\nFLAGS_1 NOW PIE', 'full'],
    ['STACK 0 rw-\nGNU_RELRO 0x1234', 'partial'],
    ['STACK 0 rw-', 'none']
  ]) {
    analyzer.runTool = () => program;
    const security = await analyzer.checkSecurity('/bin/ls', 'elf', headers, symbols);
    assert.equal(security.relro, expected);
    assert.equal(security.nx, true);
  }
  analyzer.runTool = () => { throw new Error('tool unavailable'); };
  const unknown = await analyzer.checkSecurity('/bin/ls', 'elf', headers, symbols);
  assert.equal(unknown.relro, 'unknown');
  assert.equal(unknown.nx, null);
});

test('a truncated symbol listing never proves a mitigation is absent', async () => {
  const analyzer = new BinaryAnalyzer();
  analyzer.tools.nm = true;
  analyzer.tools.file = false;
  analyzer.runTool = () => Array.from({ length: 1001 }, (_, i) => `0000 T plain_${i}`).join('\n');
  const symbols = await analyzer.extractSymbols('/bin/ls');
  assert.equal(symbols.truncated, true);
  const security = await analyzer.checkSecurity('/bin/ls', 'pe', {}, symbols);
  assert.equal(security.canary, null);
  assert.equal(security.fortify, null);
  assert.equal(security.stripped, null);
});

test('a stripped file with no relevant symbols keeps canary and fortify unknown', async () => {
  const analyzer = new BinaryAnalyzer();
  analyzer.tools.objdump = false;
  analyzer.tools.file = true;
  analyzer.runTool = () => 'ELF 64-bit executable, stripped';
  const security = await analyzer.checkSecurity('/bin/ls', 'elf', {}, [{ name: 'entry' }]);
  assert.equal(security.stripped, true);
  assert.equal(security.canary, null);
  assert.equal(security.fortify, null);
});
