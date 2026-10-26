import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { CarrierInspector } from '../../src/core/carrier-inspector.js';

function zipWithEntry(name, options = {}) {
  const { compressed = 0, uncompressed = 0, method = 0, localName = name,
    externalAttributes = 0, creator = 0 } = options;
  const filename = Buffer.from(name);
  const localFilename = Buffer.from(localName);
  const local = Buffer.alloc(30 + localFilename.length);
  local.writeUInt32LE(0x04034b50);
  local.writeUInt16LE(method, 8);
  local.writeUInt32LE(compressed, 18);
  local.writeUInt32LE(uncompressed, 22);
  local.writeUInt16LE(localFilename.length, 26);
  localFilename.copy(local, 30);
  const central = Buffer.alloc(46 + filename.length);
  central.writeUInt32LE(0x02014b50);
  central.writeUInt16LE(creator << 8, 4);
  central.writeUInt16LE(method, 10);
  central.writeUInt32LE(compressed, 20);
  central.writeUInt32LE(uncompressed, 24);
  central.writeUInt16LE(filename.length, 28);
  central.writeUInt32LE(externalAttributes, 38);
  filename.copy(central, 46);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length, 12);
  end.writeUInt32LE(local.length + compressed, 16);
  return Buffer.concat([local, Buffer.alloc(compressed), central, end]);
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

function peWithCertificate() {
  const bytes = Buffer.alloc(512);
  bytes.write('MZ');
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write('PE\0\0', 0x40, 'binary');
  bytes.writeUInt16LE(0x8664, 0x44);
  bytes.writeUInt16LE(1, 0x46);
  bytes.writeUInt16LE(0xa0, 0x54);
  bytes.writeUInt16LE(0x20b, 0x58);
  bytes.writeUInt32LE(0x1000, 0x58 + 0x10);
  bytes.writeBigUInt64LE(0x140000000n, 0x58 + 0x18);
  bytes.writeUInt16LE(0x4140, 0x58 + 0x46);
  bytes.writeUInt32LE(5, 0x58 + 0x6c);
  bytes.writeUInt32LE(0x140, 0x58 + 0x90);
  bytes.writeUInt32LE(0x20, 0x58 + 0x94);
  bytes.write('.text\0\0\0', 0xf8);
  bytes.writeUInt32LE(0x200, 0xf8 + 8);
  bytes.writeUInt32LE(0x1000, 0xf8 + 12);
  bytes.writeUInt32LE(0x20, 0xf8 + 16);
  bytes.writeUInt32LE(0x120, 0xf8 + 20);
  bytes.writeUInt32LE(0x20000000, 0xf8 + 36);
  return bytes;
}

function plausibleElfHeader() {
  const bytes = Buffer.alloc(64);
  Buffer.from('7f454c46', 'hex').copy(bytes);
  bytes[4] = 2;
  bytes[5] = 1;
  bytes[6] = 1;
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt16LE(64, 52);
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

test('PE preview checks section and certificate extents but does not verify signatures', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-pe-'));
  try {
    const inspector = new CarrierInspector(new BinaryAnalyzer({ allowedRoots: [dir] }));
    const path = join(dir, 'sample.exe');
    const bytes = peWithCertificate();
    writeFileSync(path, bytes);
    const result = await inspector.inspect(path);
    assert.equal(result.status, 'metadata_only');
    assert.equal(result.metadata.entry_point_rva, '0x1000');
    assert.equal(result.metadata.declared_entry_section, '.text');
    assert.equal(result.metadata.image_base, '0x140000000');
    assert.equal(result.metadata.sections[0].raw_offset, 0x120);
    assert.equal(result.metadata.certificate_table.present, true);
    assert.equal(result.metadata.certificate_table.file_offset, 0x140);
    assert.equal(result.metadata.certificate_table.signature_verification, 'not_performed');
    assert.equal(result.metadata.mitigation_flags.guard_cf, true);
    const malformed = Buffer.from(bytes);
    malformed.writeUInt32LE(0x300, 0x58 + 0x90);
    writeFileSync(path, malformed);
    assert.equal((await inspector.inspect(path)).status, 'incomplete');
    malformed.writeUInt32LE(0x140, 0x58 + 0x90);
    malformed.writeUInt32LE(0x300, 0xf8 + 20);
    writeFileSync(path, malformed);
    assert.equal((await inspector.inspect(path)).status, 'incomplete');
    const hidden = Buffer.from(bytes);
    hidden.writeUInt16LE(2, 0x46);
    hidden.writeUInt32LE(0x300, 0xf8 + 40 + 20);
    hidden.writeUInt32LE(0x20, 0xf8 + 40 + 16);
    writeFileSync(path, hidden);
    assert.equal((await inspector.inspect(path, { limit: 1 })).status, 'incomplete');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('ZIP preview checks local headers, suspicious paths and declared expansion without unpacking', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-zip-'));
  try {
    const inspector = new CarrierInspector(new BinaryAnalyzer({ allowedRoots: [dir] }));
    const path = join(dir, 'archive.zip');
    writeFileSync(path, zipWithEntry('C:/outside', {
      compressed: 100, uncompressed: 1_200_000, creator: 3,
      externalAttributes: 0xa1ff0000
    }));
    const result = await inspector.inspect(path);
    assert.equal(result.kind, 'zip');
    assert.equal(result.status, 'metadata_only');
    assert.equal(result.metadata.unsafe_paths, 1);
    assert.equal(result.metadata.declared_symlink_entries, 1);
    assert.equal(result.metadata.high_expansion_entries, 1);
    assert.equal(result.metadata.total_declared_uncompressed_size, 1_200_000);
    assert.equal(result.metadata.entries[0].declared_symlink, true);
    assert.equal(result.metadata.entries[0].compression_method, 0);
    writeFileSync(path, zipWithEntry('entry.txt', { localName: 'other.txt' }));
    assert.equal((await inspector.inspect(path)).status, 'incomplete');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('firmware previews structural ELF header candidates separately from incidental magic', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-firmware-'));
  try {
    const inspector = new CarrierInspector(new BinaryAnalyzer({ allowedRoots: [dir] }));
    const path = join(dir, 'image.fw');
    const marker = Buffer.from('7f454c46', 'hex');
    const bytes = Buffer.concat([Buffer.from('ab'), marker, Buffer.from('xyz'), plausibleElfHeader()]);
    writeFileSync(path, bytes);
    const result = await inspector.inspect(path);
    assert.equal(result.kind, 'firmware');
    assert.equal(result.status, 'metadata_only');
    assert.equal(result.metadata.elf_magic_offset, 2);
    assert.deepEqual(result.metadata.plausible_elf_headers, [{
      offset: 9, class: 'ELF64', endian: 'little', machine: '0x3e'
    }]);
    assert.equal(result.metadata.marker_count_lower_bound, 2);
    assert.equal(result.metadata.truncated, false);
    assert.match(result.note, /not an AST/);
    writeFileSync(path, Buffer.concat([Buffer.from('ab'), ...Array(17).fill(marker)]));
    const bounded = await inspector.inspect(path);
    assert.equal(bounded.metadata.truncated, true);
    assert.equal(bounded.metadata.marker_count_lower_bound, 17);
    assert.deepEqual(bounded.metadata.plausible_elf_headers, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
