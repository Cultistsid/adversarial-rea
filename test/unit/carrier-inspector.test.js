import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { CarrierInspector } from '../../src/core/carrier-inspector.js';

function zipWithEntry(name) {
  const filename = Buffer.from(name);
  const local = Buffer.alloc(30 + filename.length);
  local.writeUInt32LE(0x04034b50);
  local.writeUInt16LE(filename.length, 26);
  filename.copy(local, 30);
  const central = Buffer.alloc(46 + filename.length);
  central.writeUInt32LE(0x02014b50);
  central.writeUInt16LE(filename.length, 28);
  filename.copy(central, 46);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length, 16);
  return Buffer.concat([local, central, end]);
}

function peWithMitigations() {
  const bytes = Buffer.alloc(256);
  bytes.write('MZ');
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write('PE\0\0', 0x40, 'binary');
  bytes.writeUInt16LE(0x8664, 0x44);
  bytes.writeUInt16LE(1, 0x46);
  bytes.writeUInt16LE(0x70, 0x54);
  bytes.writeUInt16LE(0x20b, 0x58);
  bytes.writeUInt16LE(0x4140, 0x58 + 0x46);
  bytes.write('.text\0\0\0', 0xc8);
  bytes.writeUInt32LE(0x1000, 0xc8 + 12);
  bytes.writeUInt32LE(0x20000000, 0xc8 + 36);
  return bytes;
}

function asarWithEntry() {
  const json = Buffer.from(JSON.stringify({
    files: { 'main.js': { size: 4, offset: '0' } }
  }));
  const headerSize = 8 + Math.ceil(json.length / 4) * 4;
  const header = Buffer.alloc(8 + headerSize);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(headerSize, 4);
  header.writeUInt32LE(headerSize - 4, 8);
  header.writeUInt32LE(json.length, 12);
  json.copy(header, 16);
  return Buffer.concat([header, Buffer.from('code')]);
}

test('inspects archive, wasm, PE, JS and firmware metadata without asserting findings', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-carriers-'));
  try {
    const inspector = new CarrierInspector(new BinaryAnalyzer({ allowedRoots: [dir] }));
    const apk = join(dir, 'spoof.exe');
    const unsafe = join(dir, 'unsafe.apk');
    const wasm = join(dir, 'module.wasm');
    const badWasm = join(dir, 'broken.wasm');
    const invalidSection = join(dir, 'truncated.wasm');
    const pe = join(dir, 'sample.exe');
    const asar = join(dir, 'app.asar');
    const zipNamedAsar = join(dir, 'zip.asar');
    const script = join(dir, 'index.js');
    const firmware = join(dir, 'image.bin');
    writeFileSync(apk, zipWithEntry('AndroidManifest.xml'));
    writeFileSync(unsafe, zipWithEntry('../outside'));
    writeFileSync(wasm, Buffer.from('0061736d01000000010100', 'hex'));
    writeFileSync(badWasm, Buffer.from('0061736d02000000', 'hex'));
    writeFileSync(invalidSection, Buffer.from('0061736d01000000018001', 'hex'));
    writeFileSync(pe, peWithMitigations());
    writeFileSync(asar, asarWithEntry());
    writeFileSync(zipNamedAsar, zipWithEntry('META-INF/MANIFEST.MF'));
    writeFileSync(script, 'const password = "secret";\nconsole.log(password);\n');
    writeFileSync(firmware, Buffer.from('01027f454c4600', 'hex'));

    const apkResult = await inspector.inspect(apk);
    assert.equal(apkResult.kind, 'apk');
    assert.equal(apkResult.status, 'metadata_only');
    assert.equal(apkResult.metadata.entry_count, 1);
    assert.equal((await inspector.inspect(unsafe)).metadata.unsafe_paths, 1);
    assert.equal((await inspector.inspect(wasm)).metadata.sections[0].name, 'type');
    assert.equal((await inspector.inspect(badWasm)).status, 'incomplete');
    assert.equal((await inspector.inspect(invalidSection)).status, 'incomplete');
    const peResult = await inspector.inspect(pe);
    assert.equal(peResult.metadata.mitigation_flags.guard_cf, true);
    assert.equal(peResult.metadata.sections[0].executable, true);
    assert.equal((await inspector.inspect(asar)).metadata.entries[0].name, 'main.js');
    assert.equal((await inspector.inspect(zipNamedAsar)).kind, 'jar');
    const text = await inspector.inspect(script);
    assert.equal(text.kind, 'javascript');
    assert.equal(text.status, 'metadata_only');
    assert.doesNotMatch(JSON.stringify(text), /password|secret/);
    const image = await inspector.inspect(firmware);
    assert.equal(image.metadata.elf_magic_offset, 2);
    assert.match(apkResult.note, /not an AST/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bundle inspection lists names but never follows external symlinks', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-bundle-'));
  try {
    const app = join(dir, 'Example.app');
    const contents = join(app, 'Contents');
    mkdirSync(contents, { recursive: true });
    writeFileSync(join(contents, 'Info.plist'), '<plist/>');
    symlinkSync('/bin/ls', join(contents, 'external'));
    const inspector = new CarrierInspector(new BinaryAnalyzer({ allowedRoots: [dir] }));
    const result = await inspector.inspect(app);
    assert.equal(result.status, 'metadata_only');
    assert.ok(result.children.some(entry => entry.name === 'external' && entry.type === 'symlink'));
    const otherApp = join(dir, 'Escaped.app');
    mkdirSync(otherApp);
    symlinkSync('/bin', join(otherApp, 'Contents'));
    const rejected = await inspector.inspect(otherApp);
    assert.equal(rejected.status, 'incomplete');
    assert.deepEqual(rejected.children, []);
    await assert.rejects(
      () => inspector.inspect('/bin/ls'),
      /outside allowed roots/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
