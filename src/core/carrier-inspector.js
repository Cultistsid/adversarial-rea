import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, openSync, opendirSync, readSync, realpathSync, statSync } from 'node:fs';
import { basename, extname, resolve, sep } from 'node:path';
import { boundedInteger, identifyFileType } from './binary-analyzer.js';
import { redactSensitive } from './model-context.js';

const SECTION_NAMES = [
  'custom', 'type', 'import', 'function', 'table', 'memory', 'global',
  'export', 'start', 'element', 'code', 'data', 'data_count'
];

function readBoundedFile(path) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 64 * 1024 * 1024) {
      throw new Error('Target must be a regular file of at most 64 MiB');
    }
    const bytes = Buffer.alloc(stat.size);
    let cursor = 0;
    while (cursor < bytes.length) {
      const read = readSync(fd, bytes, cursor, bytes.length - cursor, cursor);
      if (!read) throw new Error('Target shortened during inspection');
      cursor += read;
    }
    if (fstatSync(fd).size !== stat.size) throw new Error('Target changed during inspection');
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function readLeb(buffer, cursor) {
  let result = 0;
  for (let index = 0; index < 5 && cursor.offset < buffer.length; index++) {
    const byte = buffer[cursor.offset++];
    result += (byte & 0x7f) * 2 ** (index * 7);
    if (!(byte & 0x80)) {
      if (!Number.isSafeInteger(result)) throw new Error('Invalid WebAssembly length');
      return result;
    }
  }
  throw new Error('Invalid WebAssembly LEB128 length');
}

function inspectWasm(buffer) {
  if (buffer.length < 8 || buffer.readUInt32LE(4) !== 1) {
    throw new Error('Unsupported WebAssembly version');
  }
  const sections = [];
  const cursor = { offset: 8 };
  while (cursor.offset < buffer.length) {
    const id = buffer[cursor.offset++];
    const length = readLeb(buffer, cursor);
    if (id > 12 || cursor.offset + length > buffer.length || sections.length >= 256) {
      throw new Error('Malformed or oversized WebAssembly sections');
    }
    sections.push({ name: SECTION_NAMES[id], size: length, offset: cursor.offset });
    cursor.offset += length;
  }
  return { version: 1, sections, parsed_sections: sections.length };
}

function inspectZip(buffer, limit) {
  const earliest = Math.max(0, buffer.length - 65_557);
  let end = -1;
  for (let pos = buffer.length - 22; pos >= earliest; pos--) {
    if (buffer.readUInt32LE(pos) === 0x06054b50 &&
        pos + 22 + buffer.readUInt16LE(pos + 20) === buffer.length) {
      end = pos;
      break;
    }
  }
  if (end === -1) throw new Error('ZIP central directory missing or truncated');
  const count = buffer.readUInt16LE(end + 10);
  const size = buffer.readUInt32LE(end + 12);
  const offset = buffer.readUInt32LE(end + 16);
  if (buffer.readUInt16LE(end + 4) || buffer.readUInt16LE(end + 6) ||
      count !== buffer.readUInt16LE(end + 8) || count > 2000 ||
      size > 2 * 1024 * 1024 || offset + size > end) {
    throw new Error('Unsupported multi-disk, ZIP64, or oversized directory');
  }
  const entries = [];
  const labels = new Set();
  let encrypted = 0;
  let unsafePaths = 0;
  let pos = offset;
  for (let index = 0; index < count; index++) {
    if (pos + 46 > offset + size || buffer.readUInt32LE(pos) !== 0x02014b50) {
      throw new Error('Malformed ZIP central directory');
    }
    const flags = buffer.readUInt16LE(pos + 8);
    const compressed = buffer.readUInt32LE(pos + 20);
    const uncompressed = buffer.readUInt32LE(pos + 24);
    const nameLength = buffer.readUInt16LE(pos + 28);
    const total = 46 + nameLength + buffer.readUInt16LE(pos + 30) +
      buffer.readUInt16LE(pos + 32);
    if (pos + total > offset + size || nameLength > 1024) {
      throw new Error('Malformed ZIP entry');
    }
    const name = buffer.toString('utf8', pos + 46, pos + 46 + nameLength);
    const unsafe = name.startsWith('/') || name.includes('\\') ||
      name.split('/').some(part => part === '..' || part === '.');
    if (flags & 1) encrypted++;
    if (unsafe) unsafePaths++;
    if (name === 'AndroidManifest.xml') labels.add('apk');
    if (name === 'META-INF/MANIFEST.MF') labels.add('jar');
    if (/^Payload\/[^/]+\.app\//.test(name)) labels.add('ipa');
    if (entries.length < limit) {
      entries.push({
        name: redactSensitive(name).slice(0, 160),
        compressed_size: compressed, uncompressed_size: uncompressed,
        encrypted: Boolean(flags & 1), unsafe_path: unsafe
      });
    }
    pos += total;
  }
  if (pos !== offset + size) throw new Error('ZIP directory size mismatch');
  const kind = labels.has('apk') ? 'apk' : labels.has('ipa') ? 'ipa' :
    labels.has('jar') ? 'jar' : 'zip';
  return {
    kind, entries, entry_count: count, encrypted_entries: encrypted,
    unsafe_paths: unsafePaths, truncated: count > limit
  };
}

function inspectPe(buffer, limit) {
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length) throw new Error('Truncated PE header');
  const sectionCount = buffer.readUInt16LE(peOffset + 6);
  const optionalSize = buffer.readUInt16LE(peOffset + 20);
  const optional = peOffset + 24;
  if (sectionCount > 96 || optional + optionalSize + sectionCount * 40 > buffer.length) {
    throw new Error('Invalid PE section table');
  }
  const magic = optionalSize >= 2 ? buffer.readUInt16LE(optional) : null;
  const characteristics = optionalSize >= 0x48 && [0x10b, 0x20b].includes(magic)
    ? buffer.readUInt16LE(optional + 0x46) : null;
  const sections = [];
  for (let index = 0; index < Math.min(sectionCount, limit); index++) {
    const pos = optional + optionalSize + index * 40;
    const name = buffer.toString('ascii', pos, pos + 8).replace(/\0.*$/, '');
    sections.push({
      name: name.slice(0, 8),
      virtual_address: `0x${buffer.readUInt32LE(pos + 12).toString(16)}`,
      raw_size: buffer.readUInt32LE(pos + 16),
      executable: Boolean(buffer.readUInt32LE(pos + 36) & 0x20000000)
    });
  }
  return {
    machine: `0x${buffer.readUInt16LE(peOffset + 4).toString(16)}`,
    sections, section_count: sectionCount, truncated: sectionCount > limit,
    mitigation_flags: characteristics === null ? null : {
      dynamic_base: Boolean(characteristics & 0x40),
      nx_compat: Boolean(characteristics & 0x100),
      guard_cf: Boolean(characteristics & 0x4000)
    }
  };
}

function inspectAsar(buffer, limit) {
  if (buffer.length < 16) throw new Error('Truncated ASAR header');
  const headerSize = buffer.readUInt32LE(4);
  if (headerSize < 8 || headerSize > 1024 * 1024 || headerSize + 8 > buffer.length) {
    throw new Error('Invalid ASAR header size');
  }
  const jsonSize = buffer.readUInt32LE(12);
  if (!jsonSize || jsonSize > headerSize - 8) throw new Error('Invalid ASAR header payload');
  let header;
  try {
    header = JSON.parse(buffer.toString('utf8', 16, 16 + jsonSize).replace(/\0+$/, ''));
  } catch {
    throw new Error('Invalid ASAR header JSON');
  }
  if (!header?.files || typeof header.files !== 'object' || Array.isArray(header.files)) {
    throw new Error('Invalid ASAR file tree');
  }
  const entries = [];
  const stack = [{ files: header.files, prefix: '', depth: 0 }];
  let count = 0;
  let unsafe = 0;
  while (stack.length) {
    const node = stack.pop();
    if (node.depth > 16) throw new Error('ASAR nesting exceeds limit');
    for (const [name, value] of Object.entries(node.files)) {
      if (++count > 2000 || !value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('Invalid or oversized ASAR file tree');
      }
      const invalid = !name || name.length > 256 || name === '.' || name === '..' ||
        name.includes('/') || name.includes('\\') || name.includes('\0');
      if (invalid) unsafe++;
      const path = `${node.prefix}${name}`;
      if (value.files) {
        if (typeof value.files !== 'object' || Array.isArray(value.files)) {
          throw new Error('Invalid ASAR directory');
        }
        stack.push({ files: value.files, prefix: `${path}/`, depth: node.depth + 1 });
      } else if (!value.link && !value.unpacked) {
        if (!Number.isSafeInteger(value.size) || value.size < 0 ||
            typeof value.offset !== 'string' || value.offset.length > 20 ||
            !/^\d+$/.test(value.offset)) {
          throw new Error('Invalid ASAR file size or offset');
        }
        const dataStart = BigInt(headerSize + 8);
        if (dataStart + BigInt(value.offset) + BigInt(value.size) > BigInt(buffer.length)) {
          throw new Error('ASAR entry exceeds file boundaries');
        }
      }
      if (entries.length < limit) {
        entries.push({
          name: redactSensitive(path.slice(0, 160)),
          type: value.files ? 'directory' : value.link ? 'link' : 'file',
          size: Number.isSafeInteger(value.size) ? value.size : null,
          unpacked: value.unpacked === true, unsafe_path: invalid
        });
      }
    }
  }
  return { entries, entry_count: count, unsafe_paths: unsafe, truncated: count > limit };
}

export class CarrierInspector {
  constructor(analyzer) {
    this.analyzer = analyzer;
  }

  inspectBundle(path, limit) {
    const safePath = realpathSync(resolve(path));
    if (this.analyzer.allowedRoots && !this.analyzer.allowedRoots.some(root =>
      safePath === root || safePath.startsWith(`${root}${sep}`)
    )) throw new Error('Target outside allowed roots');
    if (extname(safePath).toLowerCase() !== '.app' || !statSync(safePath).isDirectory()) {
      throw new Error('Only .app bundle directories may be inspected');
    }
    const contents = `${safePath}${sep}Contents`;
    const children = [];
    let truncated = false;
    try {
      if (!lstatSync(contents).isDirectory()) {
        throw new Error('Contents is not a regular directory');
      }
      const directory = opendirSync(contents);
      try {
        for (let index = 0; index <= limit; index++) {
          const entry = directory.readSync();
          if (!entry) break;
          if (index === limit) {
            truncated = true;
            break;
          }
          children.push({
            name: redactSensitive(entry.name).slice(0, 160),
            type: entry.isSymbolicLink() ? 'symlink' : entry.isDirectory() ? 'directory' : 'file'
          });
        }
      } finally {
        directory.closeSync();
      }
    } catch (error) {
      return {
        status: 'incomplete', kind: 'app-bundle', children: [],
        warning: `Cannot inspect bundle Contents: ${error.code || 'unknown error'}`
      };
    }
    return { status: 'metadata_only', kind: 'app-bundle', children, truncated };
  }

  async inspect(path, options = {}) {
    const limit = boundedInteger(options.limit, 100, 200);
    if (typeof path !== 'string' || path.length > 4096 || !path) throw new Error('Invalid target path');
    if (extname(path).toLowerCase() === '.app') {
      return {
        target: { name: basename(path), sha256: null },
        ...this.inspectBundle(path, limit),
        note: 'Directory listing only; no bundle executable or IPC analysis.'
      };
    }
    const safePath = this.analyzer.validateTarget(path);
    const buffer = readBoundedFile(safePath);
    const sha256 = createHash('sha256').update(buffer).digest('hex');
    const type = identifyFileType(buffer.subarray(0, 4096), extname(safePath).toLowerCase());
    const target = { name: basename(safePath), size: buffer.length, type, sha256 };
    let metadata;
    let kind = type;
    let supported = true;
    try {
      if (type === 'unsupported-wasm') {
        kind = 'wasm';
        metadata = inspectWasm(buffer);
      } else if (buffer.length >= 4 && buffer.subarray(0, 2).toString() === 'PK') {
        metadata = inspectZip(buffer, limit);
        kind = metadata.kind;
      } else if (type === 'unsupported-packed' &&
                 extname(safePath).toLowerCase() === '.asar') {
        kind = 'asar';
        metadata = inspectAsar(buffer, limit);
      } else if (type === 'pe') {
        metadata = inspectPe(buffer, limit);
      } else if (type === 'elf' || type === 'macho') {
        metadata = { format: type, detail: 'Use native analysis tools for code and symbols' };
      } else if (type === 'text') {
        kind = ['.js', '.mjs', '.cjs'].includes(extname(safePath).toLowerCase()) ? 'javascript' : 'text';
        metadata = {
          line_count: buffer.reduce((count, byte) => count + Number(byte === 10), 0) + 1
        };
      } else if (['.bin', '.fw'].includes(extname(safePath).toLowerCase()) &&
                 type === 'unsupported-packed') {
        kind = 'firmware';
        const embedded = buffer.indexOf(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
        metadata = { elf_magic_offset: embedded >= 0 ? embedded : null };
      } else {
        supported = false;
        metadata = { reason: 'No dedicated parser available for this carrier' };
      }
    } catch (error) {
      return {
        target, kind, status: 'incomplete',
        error: error.message.slice(0, 200),
        note: 'Malformed or unsupported carrier; no claims inferred.'
      };
    }
    return {
      target, kind,
      status: !supported ? 'unsupported' :
        ['elf', 'macho'].includes(type) ? 'native_analysis_available' : 'metadata_only',
      metadata,
      note: 'Metadata is not an AST, data-flow result, gadget, vulnerability, or exploit chain.'
    };
  }
}
