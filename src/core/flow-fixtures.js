import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { basename } from 'node:path';
import { redactSensitive } from './model-context.js';

const MAX_BYTES = 16 * 1024;
const MAX_STEPS = 32;
const SCHEMA = 'adv-rea-flow-fixture-v1';
const digest = value => createHash('sha256').update(value).digest('hex');

function readFixture(path) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_BYTES) throw new Error('Fixture exceeds 16 KiB or is not a file');
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!count) throw new Error('Fixture changed during inspection');
      offset += count;
    }
    if (fstatSync(fd).size !== stat.size) throw new Error('Fixture changed during inspection');
    return bytes;
  } finally {
    closeSync(fd);
  }
}

function parseFixture(bytes) {
  const fixture = JSON.parse(bytes.toString('utf8'));
  if (!fixture || Array.isArray(fixture) || fixture.schema !== SCHEMA ||
      Object.keys(fixture).length !== 3 ||
      Object.keys(fixture).some(key => !['schema', 'sample_input', 'steps'].includes(key)) ||
      typeof fixture.sample_input !== 'string' ||
      !/^[\x20-\x7e]{1,128}$/.test(fixture.sample_input) ||
      !Array.isArray(fixture.steps) || fixture.steps.length < 2 ||
      fixture.steps.length > MAX_STEPS) throw new Error('Unsupported flow fixture');
  const fields = {
    source: ['id', 'op'],
    literal: ['id', 'op', 'value'],
    copy: ['id', 'op', 'from'],
    validate: ['id', 'op', 'from', 'rule'],
    sink: ['id', 'op', 'from']
  };
  const seen = new Set();
  for (const [index, step] of fixture.steps.entries()) {
    const allowed = Object.hasOwn(fields, step?.op) ? fields[step.op] : null;
    if (!allowed || typeof step.id !== 'string' ||
        !/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(step.id) ||
        seen.has(step.id) || Object.keys(step).length !== allowed.length ||
        Object.keys(step).some(key => !allowed.includes(key)) ||
        (index === 0) !== (step.op === 'source') ||
        (index === fixture.steps.length - 1) !== (step.op === 'sink') ||
        (step.from !== undefined && !seen.has(step.from)) ||
        (step.op === 'literal' &&
          (typeof step.value !== 'string' || !/^[\x20-\x7e]{0,128}$/.test(step.value))) ||
        (step.op === 'validate' && step.rule !== 'alphanumeric')) {
      throw new Error('Unsupported flow fixture');
    }
    seen.add(step.id);
  }
  return fixture;
}

function evaluate(fixture, input) {
  const states = new Map();
  for (const step of fixture.steps) {
    if (step.op === 'source') {
      states.set(step.id, { value: input, path: [step.id], barriers: [] });
      continue;
    }
    if (step.op === 'literal') {
      states.set(step.id, { value: step.value, path: [], barriers: [] });
      continue;
    }
    const previous = states.get(step.from);
    const path = previous.path.length ? [...previous.path, step.id] : [];
    if (step.op === 'sink') {
      return {
        reached: previous.value !== null,
        path: previous.value === null ? [] : path,
        barriers: previous.barriers,
        value_digest: previous.value === null ? null : digest(previous.value)
      };
    }
    states.set(step.id, {
      value: step.op === 'validate' && previous.value !== null &&
        !/^[A-Za-z0-9]{1,128}$/.test(previous.value) ? null : previous.value,
      path,
      barriers: step.op === 'validate' && path.length
        ? [...previous.barriers, step.id] : previous.barriers
    });
  }
}

function record(sha256, kind, step, detail) {
  return {
    id: `fixture-${digest(`${sha256}:${kind}:${step}`).slice(0, 24)}`,
    target_sha256: sha256, status: 'observed', location_kind: kind,
    provider: 'flow-fixture-evaluator', provider_version: '1',
    location: `step:${step}`, detail, truncated: false
  };
}

export class FlowFixtureInspector {
  constructor(analyzer) {
    this.analyzer = analyzer;
  }

  async inspect(path) {
    const safePath = this.analyzer.validateTarget(path);
    const target = { name: redactSensitive(basename(safePath)).slice(0, 160), sha256: null };
    if (!safePath.endsWith('.flow.json')) {
      return { target, status: 'incomplete', reason: 'Expected a .flow.json fixture' };
    }
    let bytes;
    try {
      bytes = readFixture(safePath);
      target.size = bytes.length;
      target.sha256 = digest(bytes);
      const fixture = parseFixture(bytes);
      const first = evaluate(fixture, fixture.sample_input);
      const second = evaluate(fixture, fixture.sample_input);
      if (JSON.stringify(first) !== JSON.stringify(second)) throw new Error('Fixture replay differs');
      const changed = evaluate(fixture, fixture.sample_input === 'a' ? 'b' : 'a');
      const sink = fixture.steps.at(-1).id;
      const barriers = first.barriers;
      return {
        target,
        status: 'fixture_only',
        flow: {
          status: barriers.length ? 'guarded_fixture_path' :
            first.path.length ? 'observed_fixture_path' : 'no_fixture_path',
          path: first.path,
          barriers,
          input_changes_sink: first.reached && changed.reached &&
            first.value_digest !== changed.value_digest,
          evidence: first.path.map(step => record(
            target.sha256, 'fixture-def-use', step, 'Explicit in-memory fixture dependency'
          ))
        },
        trigger: {
          status: first.reached ? 'reproduced_fixture' : 'not_reached',
          outcome: first.reached ? 'sink_reached' : 'validation_rejected',
          input_digest: digest(fixture.sample_input),
          replay_digest: digest(JSON.stringify({ input: digest(fixture.sample_input), result: first })),
          repeats: 2,
          evidence: first.reached ? record(
            target.sha256, 'fixture-trace', sink, 'Two identical local fixture sink observations'
          ) : null
        },
        note: 'Only a deterministic, in-memory fixture replay; not native execution, vulnerability evidence, or an exploit trigger.'
      };
    } catch {
      return { target, status: 'incomplete', reason: 'Malformed, changed, or unsupported flow fixture' };
    }
  }
}
