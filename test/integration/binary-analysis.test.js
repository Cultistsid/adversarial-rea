/**
 * Integration tests for the binary analysis pipeline.
 *
 * These run against a real binary on the host (/bin/ls on macOS) using real
 * file I/O and real argument-array subprocess calls to system tools. No mocks.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { AdversarialMCPServer } from '../../src/mcp/server.js';

const TARGET = '/bin/ls';

// Guard: if the canonical target is missing, the whole suite is meaningless.
assert.ok(existsSync(TARGET), `expected ${TARGET} to exist on this host`);

test('analyzeTarget with /bin/ls', async () => {
  const analyzer = new BinaryAnalyzer();
  const analysis = await analyzer.analyze(TARGET);

  assert.equal(analysis.target.type, 'macho', 'macOS /bin/ls should be detected as Mach-O');
  assert.ok(Array.isArray(analysis.symbols) && analysis.symbols.length > 0, 'symbols should be non-empty');

  // Every expected security key must be present (value correctness is checked elsewhere).
  for (const key of ['pie', 'nx', 'canary', 'relro', 'stripped', 'fortify']) {
    assert.ok(key in analysis.security, `security.${key} should exist`);
  }

  assert.ok(Array.isArray(analysis.strings) && analysis.strings.length > 0, 'strings should be non-empty');
});

test('getStrings on /bin/ls returns value + category and filters by interesting_only', async () => {
  const server = new AdversarialMCPServer();

  const all = await server.getStrings({ target_path: TARGET });
  assert.equal(all.success, true);
  assert.ok(all.count > 0, 'should extract strings');
  for (const s of all.strings) {
    assert.equal(typeof s.value, 'string');
    assert.equal(typeof s.category, 'string');
  }

  const interesting = await server.getStrings({ target_path: TARGET, interesting_only: true });
  assert.ok(interesting.count > 0, 'ls should contain at least some interesting strings');
  assert.ok(
    interesting.count < all.count,
    `interesting_only (${interesting.count}) should be a strict subset of all (${all.count})`
  );
  assert.ok(interesting.strings.every((s) => s.interesting === true));
});

test('findDangerousPatterns on /bin/ls returns well-formed findings', async () => {
  const server = new AdversarialMCPServer();
  const result = await server.findDangerousPatterns({ target_path: TARGET });

  assert.equal(result.success, true);
  assert.ok(Array.isArray(result.findings), 'findings should be an array');
  assert.ok(result.findings.length > 0, 'ls links dangerous libc functions, expect findings');
  assert.equal(result.finding_count, result.findings.length);

  for (const f of result.findings) {
    assert.equal(typeof f.type, 'string', 'finding.type');
    assert.equal(typeof f.cwe, 'string', 'finding.cwe');
    assert.ok(/^CWE-\d+$/.test(f.cwe), `cwe should look like CWE-NNN, got ${f.cwe}`);
    assert.equal(typeof f.severity, 'string', 'finding.severity');
    assert.ok(['critical', 'high', 'medium'].includes(f.severity), `unexpected severity ${f.severity}`);
    assert.equal(typeof f.risk, 'string', 'finding.risk');
  }
});

test('checkSecurity on /bin/ls scores and recommends', async () => {
  const server = new AdversarialMCPServer();
  const result = await server.checkSecurity({ target_path: TARGET });

  assert.equal(result.success, true);
  if (result.security_score !== null) {
    assert.equal(typeof result.security_score, 'number');
    assert.ok(result.security_score >= 0 && result.security_score <= 100, 'score in [0,100]');
  } else {
    assert.ok(Object.values(result.mitigations).some(value => value === null || value === 'unknown'),
      'an unknown mitigation should prevent a numeric score');
  }

  assert.ok(result.mitigations && typeof result.mitigations === 'object', 'mitigations object exists');
  for (const key of ['pie', 'nx', 'canary', 'relro', 'stripped', 'fortify']) {
    assert.ok(key in result.mitigations, `mitigations.${key} should exist`);
  }

  assert.ok(Array.isArray(result.recommendations), 'recommendations should be an array');
});

test('MCP server tool dispatch: known tool succeeds, unknown throws', async () => {
  const server = new AdversarialMCPServer();

  const result = await server.handleToolCall('analyze_binary', { target_path: TARGET });
  assert.equal(result.success, true);
  assert.equal(result.target.type, 'macho');

  await assert.rejects(
    () => server.handleToolCall('unknown_tool', {}),
    /Unknown tool: unknown_tool/,
    'dispatch of an unknown tool should throw'
  );
});

test('analyze throws a meaningful error for a missing file', async () => {
  const analyzer = new BinaryAnalyzer();
  await assert.rejects(
    () => analyzer.analyze('/nonexistent/path/does/not/exist'),
    /Target not found: \/nonexistent\/path\/does\/not\/exist/,
    'missing target should reject with a descriptive message'
  );
});

test('full pipeline: analyze_binary and find_dangerous_patterns agree on target', async () => {
  const server = new AdversarialMCPServer();

  const analyze = await server.handleToolCall('analyze_binary', { target_path: TARGET });
  const dangerous = await server.handleToolCall('find_dangerous_patterns', { target_path: TARGET });

  assert.equal(analyze.success, true);
  assert.equal(dangerous.success, true);

  // Both tools re-run analysis independently; the target metadata must be identical.
  assert.equal(analyze.target.path, dangerous.target.path);
  assert.equal(analyze.target.name, dangerous.target.name);
  assert.equal(analyze.target.type, dangerous.target.type);
  assert.equal(analyze.target.size, dangerous.target.size);
});
