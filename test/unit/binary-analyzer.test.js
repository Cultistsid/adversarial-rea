import { test } from 'node:test';
import assert from 'node:assert/strict';

import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { AdversarialMCPServer } from '../../src/mcp/server.js';

// BinaryAnalyzer.detectTools() runs `which <tool>` via execSync in its constructor.
// We don't mock the binary here; detectTools is expected to degrade gracefully
// (missing tools => false) rather than throw, so a plain construction exercises it.
function makeAnalyzer() {
  return new BinaryAnalyzer();
}

test('detectTools() returns an object of booleans for every known tool', () => {
  const analyzer = makeAnalyzer();
  const tools = analyzer.detectTools();

  assert.equal(typeof tools, 'object');
  assert.notEqual(tools, null);

  const expectedKeys = ['objdump', 'nm', 'strings', 'file', 'otool', 'rizin', 'radare2'];
  for (const key of expectedKeys) {
    assert.ok(key in tools, `expected key "${key}" in detectTools() result`);
    assert.equal(typeof tools[key], 'boolean', `tools.${key} should be boolean`);
  }
});

test('detectTools() never throws even when a tool is absent', () => {
  const analyzer = makeAnalyzer();
  assert.doesNotThrow(() => analyzer.detectTools());
});

test('classifyString() flags credential-related strings', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['user_password=abc', 'API_SECRET', 'auth_token', 'my_cred_store']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'credential_related', `"${s}" should be credential_related`);
    assert.equal(c.interesting, true);
  }
});

test('classifyString() flags URLs', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['http://example.com', 'https://a.b/c', 'ftp://host', 'file:///etc']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'url', `"${s}" should be url`);
    assert.equal(c.interesting, true);
  }
});

test('classifyString() flags paths', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['/etc/shadow', '/proc/self', '/dev/null', 'C:\\Windows', 'HKEY_LOCAL_MACHINE']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'path', `"${s}" should be path`);
    assert.equal(c.interesting, true);
  }
});

test('classifyString() flags dangerous functions', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['sprintf', 'strcpy', 'strcat', 'gets', 'scanf', 'system', 'exec', 'popen']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'dangerous_function', `"${s}" should be dangerous_function`);
    assert.equal(c.interesting, true);
  }
});

test('classifyString() flags crypto material', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['-----BEGIN RSA PRIVATE KEY-----', 'stuff-----END CERT']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'crypto_material', `"${s}" should be crypto_material`);
    assert.equal(c.interesting, true);
  }
});

test('classifyString() flags SQL', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['SELECT * FROM users', 'INSERT INTO t', 'DELETE FROM x', 'UPDATE y SET z']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'sql', `"${s}" should be sql`);
    assert.equal(c.interesting, true);
  }
});

test('classifyString() flags library references (not interesting)', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['libc.so', 'kernel32.dll', 'Foundation.dylib']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'library_reference', `"${s}" should be library_reference`);
    assert.equal(c.interesting, false);
  }
});

test('classifyString() flags version info (not interesting)', () => {
  const analyzer = makeAnalyzer();
  for (const s of ['version 1.2.3', 'Copyright 2020', '(c) ACME']) {
    const c = analyzer.classifyString(s);
    assert.equal(c.category, 'version_info', `"${s}" should be version_info`);
    assert.equal(c.interesting, false);
  }
});

test('classifyString() returns unknown for plain strings', () => {
  const analyzer = makeAnalyzer();
  const c = analyzer.classifyString('just some plain text here');
  assert.equal(c.category, 'unknown');
  assert.equal(c.interesting, false);
});

test('classifyString() runs crypto_material before credential (BEGIN KEY contains "KEY")', () => {
  const analyzer = makeAnalyzer();
  // The "-----BEGIN ... KEY-----" form must classify as crypto, not credential.
  const c = analyzer.classifyString('-----BEGIN PRIVATE KEY-----');
  assert.equal(c.category, 'crypto_material');
});

test('classifyString() runs path before credential (HKEY_ contains "KEY")', () => {
  const analyzer = makeAnalyzer();
  const c = analyzer.classifyString('HKEY_LOCAL_MACHINE\\Software\\secret');
  assert.equal(c.category, 'path');
});

test('classifyString() runs url before credential', () => {
  const analyzer = makeAnalyzer();
  const c = analyzer.classifyString('secret http://example.com');
  assert.equal(c.category, 'url');
});

test('classifyString() no longer treats bare "key" as a credential', () => {
  const analyzer = makeAnalyzer();
  // "key" was removed from the credential regex to avoid false positives.
  const c = analyzer.classifyString('monkey business');
  assert.notEqual(c.category, 'credential_related');
});

// --- AdversarialMCPServer.getSeverity() ---

test('getSeverity() maps critical CWEs', () => {
  const server = new AdversarialMCPServer();
  for (const cwe of ['CWE-78', 'CWE-120', 'CWE-122', 'CWE-415', 'CWE-416']) {
    assert.equal(server.getSeverity(cwe), 'critical', `${cwe} should be critical`);
  }
});

test('getSeverity() maps high CWEs', () => {
  const server = new AdversarialMCPServer();
  for (const cwe of ['CWE-134', 'CWE-798', 'CWE-321', 'CWE-327', 'CWE-328']) {
    assert.equal(server.getSeverity(cwe), 'high', `${cwe} should be high`);
  }
});

test('getSeverity() defaults to medium for unknown CWEs', () => {
  const server = new AdversarialMCPServer();
  assert.equal(server.getSeverity('CWE-22'), 'medium');
  assert.equal(server.getSeverity('CWE-999'), 'medium');
  assert.equal(server.getSeverity(undefined), 'medium');
});

// --- AdversarialMCPServer.calculateSecurityScore() ---

test('calculateSecurityScore() returns 0 for no mitigations', () => {
  const server = new AdversarialMCPServer();
  const score = server.calculateSecurityScore({
    pie: false, nx: false, canary: false, relro: 'none', fortify: false
  });
  assert.equal(score, 0);
});

test('calculateSecurityScore() returns 100 for all mitigations with full RELRO', () => {
  const server = new AdversarialMCPServer();
  const score = server.calculateSecurityScore({
    pie: true, nx: true, canary: true, relro: 'full', fortify: true
  });
  assert.equal(score, 20 + 25 + 25 + 15 + 15);
});

test('calculateSecurityScore() scores partial RELRO lower than full', () => {
  const server = new AdversarialMCPServer();
  const partial = server.calculateSecurityScore({
    pie: false, nx: false, canary: false, relro: 'partial', fortify: false
  });
  const full = server.calculateSecurityScore({
    pie: false, nx: false, canary: false, relro: 'full', fortify: false
  });
  assert.equal(partial, 10);
  assert.equal(full, 15);
});

test('calculateSecurityScore() sums individual mitigations', () => {
  const server = new AdversarialMCPServer();
  assert.equal(server.calculateSecurityScore({ pie: true }), 20);
  assert.equal(server.calculateSecurityScore({ nx: true }), 25);
  assert.equal(server.calculateSecurityScore({ canary: true }), 25);
  assert.equal(server.calculateSecurityScore({ fortify: true }), 15);
});

// --- AdversarialMCPServer.getSecurityRecommendations() ---

test('getSecurityRecommendations() recommends every mitigation when all are missing', () => {
  const server = new AdversarialMCPServer();
  const recs = server.getSecurityRecommendations({
    pie: false, nx: false, canary: false, relro: 'none', fortify: false, stripped: true
  });
  assert.ok(recs.some(r => /PIE/.test(r)));
  assert.ok(recs.some(r => /NX\/DEP/.test(r)));
  assert.ok(recs.some(r => /canaries/.test(r)));
  assert.ok(recs.some(r => /RELRO/.test(r)));
  assert.ok(recs.some(r => /FORTIFY/.test(r)));
  assert.ok(recs.some(r => /stripped/.test(r)));
  assert.equal(recs.length, 6);
});

test('getSecurityRecommendations() returns empty when fully hardened', () => {
  const server = new AdversarialMCPServer();
  const recs = server.getSecurityRecommendations({
    pie: true, nx: true, canary: true, relro: 'full', fortify: true, stripped: false
  });
  assert.deepEqual(recs, []);
});

test('getSecurityRecommendations() flags partial RELRO as not full', () => {
  const server = new AdversarialMCPServer();
  const recs = server.getSecurityRecommendations({
    pie: true, nx: true, canary: true, relro: 'partial', fortify: true, stripped: false
  });
  assert.equal(recs.length, 1);
  assert.ok(/RELRO/.test(recs[0]));
});
