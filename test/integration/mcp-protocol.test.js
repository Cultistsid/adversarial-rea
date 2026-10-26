/**
 * Integration tests for the MCP server over the real stdio protocol.
 *
 * Spawns `node src/mcp/main.js` as a child process and talks to it with the
 * official MCP client (StdioClientTransport handles the JSON-RPC handshake and
 * newline-delimited framing over the child's stdin/stdout).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_MAIN = resolve(__dirname, '../../src/mcp/main.js');
const CLI = resolve(__dirname, '../../bin/cli.js');

const EXPECTED_TOOLS = [
  'analyze_binary',
  'get_symbols',
  'get_strings',
  'check_security',
  'disassemble',
  'get_sections',
  'get_headers',
  'find_dangerous_patterns',
  'trace_calls',
  'inspect_carrier',
  'inspect_flow_fixture',
  'find_gadget_candidates',
];

async function withClient(fn) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_MAIN],
  });
  const client = new Client({ name: 'integration-test', version: '0.0.0' }, { capabilities: {} });

  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

test('stdio: ListTools returns the registered tool catalog', async () => {
  await withClient(async (client) => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();

    assert.equal(tools.length, EXPECTED_TOOLS.length, 'manifest and runtime must agree');
    assert.deepEqual(names, [...EXPECTED_TOOLS].sort());

    for (const t of tools) {
      assert.equal(typeof t.description, 'string');
      assert.equal(t.inputSchema.type, 'object');
    }
  });
});

test('stdio: CallTool get_strings on /bin/ls returns valid JSON', async () => {
  await withClient(async (client) => {
    const res = await client.callTool({
      name: 'get_strings',
      arguments: { target_path: '/bin/ls' },
    });

    assert.ok(Array.isArray(res.content) && res.content.length > 0, 'response should have content');
    const block = res.content[0];
    assert.equal(block.type, 'text');

    const parsed = JSON.parse(block.text);
    assert.equal(parsed.success, true);
    assert.ok(parsed.count > 0, 'ls should yield strings');
    assert.ok(Array.isArray(parsed.strings));
    assert.equal(typeof parsed.strings[0].value, 'string');
    assert.equal(typeof parsed.strings[0].category, 'string');
  });
});

test('stdio: CallTool on an unknown tool reports an error', async () => {
  await withClient(async (client) => {
    const res = await client.callTool({ name: 'does_not_exist', arguments: {} });

    // main.js catches the throw and returns isError with a JSON error payload.
    assert.equal(res.isError, true);
    const parsed = JSON.parse(res.content[0].text);
    assert.match(parsed.error, /Unknown tool: does_not_exist/);
  });
});

test('stdio: trace_calls reports local observations, not verified vulnerabilities', async () => {
  await withClient(async client => {
    const response = await client.callTool({
      name: 'trace_calls',
      arguments: { target_path: '/bin/ls', sinks: ['strcpy'], limit: 4 }
    });
    assert.equal(response.isError, undefined);
    const result = JSON.parse(response.content[0].text);
    assert.equal(result.status, 'observed');
    assert.equal(result.vulnerability_status, 'unverified');
    assert.ok(result.calls.length > 0);
    for (const call of result.calls) {
      assert.equal(call.callee, 'strcpy');
      assert.equal(call.flow_status, 'unknown');
      assert.equal(call.evidence.target_sha256, result.target.sha256);
    }
  });
});

test('stdio: inspect_carrier parses Wasm metadata without running it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-stdio-'));
  try {
    const path = join(dir, 'sample.wasm');
    writeFileSync(path, Buffer.from('0061736d01000000010100', 'hex'));
    await withClient(async client => {
      const response = await client.callTool({
        name: 'inspect_carrier',
        arguments: { target_path: path }
      });
      assert.equal(response.isError, undefined);
      const result = JSON.parse(response.content[0].text);
      assert.equal(result.kind, 'wasm');
      assert.equal(result.status, 'metadata_only');
      assert.equal(result.metadata.sections[0].name, 'type');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI: inspect works offline without a service API key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-rea-cli-'));
  try {
    const path = join(dir, 'sample.wasm');
    writeFileSync(path, Buffer.from('0061736d01000000', 'hex'));
    const result = spawnSync(process.execPath, [CLI, 'inspect', path], {
      encoding: 'utf8', timeout: 5000, maxBuffer: 128 * 1024,
      env: { ...process.env, ANTHROPIC_API_KEY: '' }
    });
    assert.equal(result.status, 0, result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.carrier.kind, 'wasm');
    assert.equal(parsed.carrier.status, 'metadata_only');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('stdio: fixture flow and trigger are replayed locally without upgrading native evidence', async () => {
  const target = fileURLToPath(new URL('../fixtures/flow-direct.flow.json', import.meta.url));
  await withClient(async client => {
    const response = await client.callTool({
      name: 'inspect_flow_fixture', arguments: { target_path: target }
    });
    assert.equal(response.isError, undefined);
    const result = JSON.parse(response.content[0].text);
    assert.equal(result.status, 'fixture_only');
    assert.equal(result.flow.status, 'observed_fixture_path');
    assert.equal(result.trigger.status, 'reproduced_fixture');
    assert.match(result.note, /not native execution/);
    assert.doesNotMatch(JSON.stringify(result), /review42/);
  });
});

test('CLI: fixture replay is opt-in and remains offline', () => {
  const target = fileURLToPath(new URL('../fixtures/flow-constant.flow.json', import.meta.url));
  const result = spawnSync(process.execPath, [CLI, 'inspect', target, '--flow-fixture'], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 128 * 1024,
    env: { ...process.env, ANTHROPIC_API_KEY: '' }
  });
  assert.equal(result.status, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.flow_fixture.flow.status, 'no_fixture_path');
  assert.equal(parsed.flow_fixture.trigger.status, 'reproduced_fixture');
  assert.equal(parsed.carrier.status, 'metadata_only');
  const mixed = spawnSync(process.execPath, [CLI, 'inspect', target, '--flow-fixture', '--calls'], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 128 * 1024,
    env: { ...process.env, ANTHROPIC_API_KEY: '' }
  });
  assert.equal(mixed.status, 1);
  assert.match(mixed.stderr, /cannot be combined/);
});
