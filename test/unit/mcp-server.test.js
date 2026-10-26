import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AdversarialMCPServer, TOOLS } from '../../src/mcp/server.js';

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
  'find_gadget_candidates'
];

test('getToolList() returns every registered tool', () => {
  const server = new AdversarialMCPServer();
  const list = server.getToolList();
  assert.equal(list.length, 12);
  assert.deepEqual(list.map(t => t.name).sort(), [...EXPECTED_TOOLS].sort());
});

test('getToolList() entries have required fields', () => {
  const server = new AdversarialMCPServer();
  for (const tool of server.getToolList()) {
    assert.equal(typeof tool.name, 'string', 'name is string');
    assert.equal(typeof tool.description, 'string', `${tool.name}.description is string`);
    assert.ok(tool.description.length > 0, `${tool.name}.description non-empty`);
    assert.equal(typeof tool.inputSchema, 'object', `${tool.name}.inputSchema is object`);
    assert.equal(tool.inputSchema.type, 'object', `${tool.name}.inputSchema.type`);
    assert.equal(typeof tool.inputSchema.properties, 'object', `${tool.name} has properties`);
  }
});

test('every tool requires target_path', () => {
  for (const name of EXPECTED_TOOLS) {
    const tool = TOOLS[name];
    assert.ok(Array.isArray(tool.inputSchema.required), `${name}.required is array`);
    assert.ok(
      tool.inputSchema.required.includes('target_path'),
      `${name} should require target_path`
    );
    assert.ok(
      'target_path' in tool.inputSchema.properties,
      `${name} should declare target_path property`
    );
  }
});

test('get_symbols type enum is well-formed', () => {
  const schema = TOOLS.get_symbols.inputSchema;
  assert.deepEqual(schema.properties.type.enum, ['all', 'imports', 'exports', 'functions']);
  assert.equal(schema.properties.type.default, 'all');
});

test('string-length defaults are declared where expected', () => {
  assert.equal(TOOLS.analyze_binary.inputSchema.properties.strings_min_len.default, 6);
  assert.equal(TOOLS.get_strings.inputSchema.properties.min_length.default, 6);
  assert.equal(TOOLS.get_strings.inputSchema.properties.interesting_only.default, false);
});

test('handleToolCall() throws for an unknown tool name', async () => {
  const server = new AdversarialMCPServer();
  await assert.rejects(
    () => server.handleToolCall('no_such_tool', {}),
    /Unknown tool: no_such_tool/
  );
});

test('handleToolCall() dispatches known tools to analyzer (surfaces missing target)', async () => {
  const server = new AdversarialMCPServer();
  // A known tool with a nonexistent path should reach the analyzer and reject
  // with "Target not found" — proving dispatch happened (not an "Unknown tool").
  await assert.rejects(
    () => server.handleToolCall('analyze_binary', { target_path: '/nonexistent/path/xyz.bin' }),
    /Target not found/
  );
});

test('TOOLS export matches getToolList()', () => {
  const server = new AdversarialMCPServer();
  assert.deepEqual(
    server.getToolList().map(t => t.name).sort(),
    Object.keys(TOOLS).sort()
  );
});
