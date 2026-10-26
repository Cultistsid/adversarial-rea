/**
 * Integration tests for the MCP server over the real stdio protocol.
 *
 * Spawns `node src/mcp/main.js` as a child process and talks to it with the
 * official MCP client (StdioClientTransport handles the JSON-RPC handshake and
 * newline-delimited framing over the child's stdin/stdout).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SERVER_MAIN = resolve(__dirname, '../../src/mcp/main.js');

const EXPECTED_TOOLS = [
  'analyze_binary',
  'get_symbols',
  'get_strings',
  'check_security',
  'disassemble',
  'get_sections',
  'get_headers',
  'find_dangerous_patterns',
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

test('stdio: ListTools returns all 8 expected tools', async () => {
  await withClient(async (client) => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();

    assert.equal(tools.length, EXPECTED_TOOLS.length, 'should expose exactly 8 tools');
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
