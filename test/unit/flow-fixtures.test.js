import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BinaryAnalyzer } from '../../src/core/binary-analyzer.js';
import { isVerifiedFinding } from '../../src/core/evidence.js';
import { FlowFixtureInspector } from '../../src/core/flow-fixtures.js';

const path = name => fileURLToPath(new URL(`../fixtures/${name}.flow.json`, import.meta.url));

test('direct fixture flow has a replayed sink observation tied to its exact bytes', async () => {
  const inspector = new FlowFixtureInspector(new BinaryAnalyzer());
  const result = await inspector.inspect(path('flow-direct'));
  assert.equal(result.status, 'fixture_only');
  assert.equal(result.flow.status, 'observed_fixture_path');
  assert.deepEqual(result.flow.path, ['entry', 'alias', 'display']);
  assert.equal(result.flow.input_changes_sink, true);
  assert.equal(result.trigger.status, 'reproduced_fixture');
  assert.equal(result.trigger.repeats, 2);
  assert.equal(result.trigger.evidence.target_sha256, result.target.sha256);
  assert.equal(result.flow.evidence[1].location_kind, 'fixture-def-use');
  assert.doesNotMatch(JSON.stringify(result), /review42/);
  assert.deepEqual(await inspector.inspect(path('flow-direct')), result);
  assert.equal(isVerifiedFinding({
    id: 'fixture-is-not-native', status: 'observed',
    evidence_ids: [result.flow.evidence[1].id, result.trigger.evidence.id]
  }, {
    target: { sha256: result.target.sha256 },
    evidence: [result.flow.evidence[1], result.trigger.evidence]
  }), false);
});

test('a literal sink is reproducible but not correlated with the source', async () => {
  const result = await new FlowFixtureInspector(new BinaryAnalyzer()).inspect(path('flow-constant'));
  assert.equal(result.trigger.status, 'reproduced_fixture');
  assert.equal(result.flow.status, 'no_fixture_path');
  assert.equal(result.flow.input_changes_sink, false);
  assert.deepEqual(result.flow.path, []);
});

test('validation barrier stays explicit even if the fixture input passes', async () => {
  const inspector = new FlowFixtureInspector(new BinaryAnalyzer());
  const accepted = await inspector.inspect(path('flow-guarded'));
  assert.equal(accepted.flow.status, 'guarded_fixture_path');
  assert.deepEqual(accepted.flow.barriers, ['checked']);
  assert.equal(accepted.trigger.status, 'reproduced_fixture');
  assert.equal(accepted.flow.input_changes_sink, true);
  const denied = await inspector.inspect(path('flow-rejected'));
  assert.equal(denied.flow.status, 'guarded_fixture_path');
  assert.equal(denied.trigger.status, 'not_reached');
  assert.equal(denied.trigger.evidence, null);
  assert.equal(denied.flow.input_changes_sink, false);
});

test('unsupported, cyclic, duplicate and oversized fixtures are incomplete without evidence', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'adv-flow-'));
  try {
    const inspector = new FlowFixtureInspector(new BinaryAnalyzer({ allowedRoots: [dir] }));
    const file = join(dir, 'input.flow.json');
    for (const steps of [
      [{ id: 'entry', op: 'source' }, { id: 'display', op: 'sink', from: 'later' }],
      [{ id: 'entry', op: 'source' }, { id: 'entry', op: 'sink', from: 'entry' }],
      [{ id: 'entry', op: 'source' }, { id: 'display', op: 'exec', from: 'entry' }],
      [{ id: 'entry', op: 'source' }, { id: 'check', op: 'validate', from: 'entry', rule: 'arbitrary' },
        { id: 'display', op: 'sink', from: 'check' }],
      Array.from({ length: 34 }, (_, index) => ({ id: `step${index}`, op: 'source' }))
    ]) {
      writeFileSync(file, JSON.stringify({
        schema: 'adv-rea-flow-fixture-v1', sample_input: 'safe', steps
      }));
      const result = await inspector.inspect(file);
      assert.equal(result.status, 'incomplete');
      assert.equal(result.flow, undefined);
      assert.equal(result.trigger, undefined);
    }
    writeFileSync(file, 'x'.repeat(16 * 1024 + 1));
    assert.equal((await inspector.inspect(file)).status, 'incomplete');
    const fixture = {
      schema: 'adv-rea-flow-fixture-v1', sample_input: 'first',
      steps: [{ id: 'entry', op: 'source' }, { id: 'display', op: 'sink', from: 'entry' }]
    };
    writeFileSync(file, JSON.stringify(fixture));
    const first = await inspector.inspect(file);
    writeFileSync(file, JSON.stringify({ ...fixture, sample_input: 'second' }));
    const second = await inspector.inspect(file);
    assert.notEqual(first.target.sha256, second.target.sha256);
    assert.notEqual(first.trigger.evidence.id, second.trigger.evidence.id);
    await assert.rejects(() => inspector.inspect(path('flow-direct')), /outside allowed roots/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
