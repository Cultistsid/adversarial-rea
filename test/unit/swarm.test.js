import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AgentSwarm, AGENT_ROLES } from '../../src/core/swarm.js';

// AgentSwarm's constructor instantiates the Anthropic client (needs an API key)
// and a p-limit pool. The methods under test are pure and never touch `this.client`
// or `this.limit`, so we build a bare instance off the prototype to avoid that setup.
function makeSwarm() {
  return Object.create(AgentSwarm.prototype);
}

const ALL_IDS = Object.values(AGENT_ROLES).map(r => r.id);

test('selectRolesForMission() honors an explicit roles list', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({ roles: ['mem-corrupt', 'crypto-weak'] }, 'elf');
  assert.deepEqual(roles.map(r => r.id).sort(), ['crypto-weak', 'mem-corrupt'].sort());
});

test('selectRolesForMission() ignores targetType when explicit roles given', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({ roles: ['logic-flaw'] }, 'pe');
  assert.deepEqual(roles.map(r => r.id), ['logic-flaw']);
});

test('selectRolesForMission() with explicit roles that match nothing returns empty', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({ roles: ['does-not-exist'] }, 'elf');
  assert.deepEqual(roles, []);
});

test('selectRolesForMission() auto-selects for targetType "pe"', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({}, 'pe');
  assert.deepEqual(
    roles.map(r => r.id).sort(),
    ['mem-corrupt', 'mitigation-bypass', 'priv-esc', 'input-inject'].sort()
  );
});

test('selectRolesForMission() auto-selects for targetType "elf"', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({}, 'elf');
  assert.deepEqual(
    roles.map(r => r.id).sort(),
    ['mem-corrupt', 'mitigation-bypass', 'priv-esc', 'input-inject'].sort()
  );
});

test('selectRolesForMission() auto-selects for targetType "android"', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({}, 'android');
  assert.deepEqual(
    roles.map(r => r.id).sort(),
    ['logic-flaw', 'crypto-weak', 'input-inject', 'supply-chain'].sort()
  );
});

test('selectRolesForMission() falls back to ALL roles for unknown targetType (regression)', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({}, 'unknown');
  assert.equal(roles.length, ALL_IDS.length);
  assert.deepEqual(roles.map(r => r.id).sort(), [...ALL_IDS].sort());
});

test('selectRolesForMission() falls back to ALL roles for undefined targetType', () => {
  const swarm = makeSwarm();
  const roles = swarm.selectRolesForMission({}, undefined);
  assert.equal(roles.length, ALL_IDS.length);
});

test('parseAgentResponse() extracts valid JSON from response text', () => {
  const swarm = makeSwarm();
  const role = { id: 'mem-corrupt' };
  const payload = { findings: [{ id: 'f1', severity: 'high' }], attack_surface: [] };
  const response = { content: [{ text: `Here are results:\n${JSON.stringify(payload)}\nDone.` }] };

  const result = swarm.parseAgentResponse(role, response);
  assert.equal(result.role, 'mem-corrupt');
  assert.equal(result.parsed.findings[0].id, 'f1');
  assert.equal(result.parsed.findings[0].status, 'candidate');
  assert.deepEqual(result.parsed.findings[0].evidence, []);
  assert.ok(result.parsed.findings[0].missing_evidence.includes('Observed trigger'));
  assert.ok(result.raw.includes('Here are results'));
});

test('parseAgentResponse() returns parsed:null when no JSON is present', () => {
  const swarm = makeSwarm();
  const role = { id: 'logic-flaw' };
  const response = { content: [{ text: 'No structured output, just prose.' }] };

  const result = swarm.parseAgentResponse(role, response);
  assert.equal(result.role, 'logic-flaw');
  assert.equal(result.parsed, null);
  assert.equal(result.raw, 'No structured output, just prose.');
});

test('parseAgentResponse() returns parsed:null on malformed JSON', () => {
  const swarm = makeSwarm();
  const role = { id: 'crypto-weak' };
  const response = { content: [{ text: 'result: {not valid json,,,}' }] };

  const result = swarm.parseAgentResponse(role, response);
  assert.equal(result.parsed, null);
  assert.ok(result.raw.includes('not valid json'));
});

test('parseAgentResponse() handles empty/missing content gracefully', () => {
  const swarm = makeSwarm();
  const role = { id: 'input-inject' };
  const result = swarm.parseAgentResponse(role, { content: [] });
  assert.equal(result.parsed, null);
  assert.equal(result.raw, '');
});

test('buildAnalysisRequest() returns a string containing focus, path and context', () => {
  const swarm = makeSwarm();
  const role = { id: 'mem-corrupt', focus: ['buffer-overflow', 'use-after-free'] };
  const target = { path: '/tmp/target.elf', type: 'elf' };
  const mission = { context: { arch: 'x64' }, additionalInstructions: 'Be thorough.' };

  const req = swarm.buildAnalysisRequest(role, target, mission);
  assert.equal(typeof req, 'string');
  assert.ok(req.includes('buffer-overflow, use-after-free'));
  assert.ok(req.includes('/tmp/target.elf'));
  assert.ok(req.includes('"arch": "x64"'));
  assert.ok(req.includes('Be thorough.'));
});

test('buildAnalysisRequest() tolerates missing context and instructions', () => {
  const swarm = makeSwarm();
  const role = { id: 'logic-flaw', focus: ['auth-bypass'] };
  const target = { path: '/bin/x', type: 'elf' };

  const req = swarm.buildAnalysisRequest(role, target, {});
  assert.ok(req.includes('auth-bypass'));
  assert.ok(req.includes('/bin/x'));
  assert.ok(req.includes('{}')); // empty context serialized
});

test('buildAgentPrompt() embeds role prompt and target context', () => {
  const swarm = makeSwarm();
  const role = { id: 'mem-corrupt', prompt: 'ROLE_SYSTEM_PROMPT' };
  const target = { path: '/tmp/t', type: 'pe' };
  const mission = { objective: 'find RCE' };

  const prompt = swarm.buildAgentPrompt(role, target, mission);
  assert.ok(prompt.includes('ROLE_SYSTEM_PROMPT'));
  assert.ok(prompt.includes('pe'));
  assert.ok(prompt.includes('/tmp/t'));
  assert.ok(prompt.includes('find RCE'));
});

test('AGENT_ROLES entries have the required shape', () => {
  for (const [key, role] of Object.entries(AGENT_ROLES)) {
    assert.equal(typeof role.id, 'string', `${key}.id`);
    assert.equal(typeof role.name, 'string', `${key}.name`);
    assert.ok(Array.isArray(role.focus), `${key}.focus is array`);
    assert.equal(typeof role.prompt, 'string', `${key}.prompt`);
  }
});
