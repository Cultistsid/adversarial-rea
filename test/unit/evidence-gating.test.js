import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AdversarialMCPServer } from '../../src/mcp/server.js';
import { isVerifiedFinding } from '../../src/core/evidence.js';
import { summarizeBinaryForPrompt, redactSensitive } from '../../src/core/model-context.js';
import { ScaffoldGenerator, TelemetryMapper } from '../../src/core/exploit-scaffolds.js';
import { HUNTING_PATTERNS, VulnHunter } from '../../src/core/vuln-hunter.js';
import { AttackSurfaceEnumerator } from '../../src/core/attack-surface.js';

process.env.ANTHROPIC_API_KEY ||= 'test-dummy-key';
const { ExploitChainBuilder } = await import('../../src/core/exploit-chain.js');
const { AdversarialREA } = await import('../../src/index.js');

function sampleAnalysis() {
  return {
    target: { path: '/tmp/native', name: 'native', type: 'elf', size: 120, sha256: 'a'.repeat(64) },
    imports: [{ name: 'printf', type: 'U' }, { name: 'strcpy', type: 'U' }],
    strings: [
      { value: 'password=TOP_SECRET', category: 'credential_related', interesting: true },
      { value: '-----BEGIN PRIVATE KEY-----SECRET-----END PRIVATE KEY-----', category: 'crypto_material', interesting: true }
    ],
    sections: [],
    symbols: [],
    functions: [],
    exports: [],
    headers: { parsed: {} },
    warnings: [],
    security: { pie: null, canary: null, nx: null, fortify: null, relro: 'unknown' },
    evidence: []
  };
}

test('prompts include structural facts but never raw secret values', async () => {
  const analysis = sampleAnalysis();
  const text = summarizeBinaryForPrompt(analysis);
  assert.match(text, /credential_related/);
  assert.doesNotMatch(text, /TOP_SECRET|PRIVATE KEY/);
  assert.equal(redactSensitive('token=abc123 password="secret"'), 'token=[REDACTED] password=[REDACTED]');
  const hunter = new VulnHunter({ model: 'test' });
  hunter.selectPatterns = () => [{ key: 'UNCHECKED_BOUNDS', ...HUNTING_PATTERNS.UNCHECKED_BOUNDS }];
  let prompt;
  hunter.client.messages.create = async request => {
    prompt = request.messages[0].content;
    return { content: [{ type: 'text', text: JSON.stringify([{
      id: 'fabricated',
      pattern: 'UNCHECKED_BOUNDS',
      location: 'strcpy',
      status: 'observed',
      evidence: ['invented'],
      impact: { severity: 'critical' }
    }]) }] };
  };
  const findings = await hunter.hunt({ path: analysis.target.path, type: 'elf' }, { vectors: [] }, {
    binaryAnalysis: analysis, patterns: ['UNCHECKED_BOUNDS']
  });
  assert.doesNotMatch(prompt, /TOP_SECRET|PRIVATE KEY/);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].status, 'candidate');
  assert.deepEqual(findings[0].evidence, []);
  assert.equal(isVerifiedFinding(findings[0], analysis), false);
});

test('imports and model claims do not become primitives or vulnerability findings', async () => {
  const analysis = sampleAnalysis();
  const mapper = new TelemetryMapper();
  const primitives = mapper.mapTelemetryToPrimitives(analysis, []);
  assert.ok(Object.values(primitives).every(values => values.length === 0));
  const scaffold = new ScaffoldGenerator({}).generate('CODE_EXEC_LINUX', analysis, [], {});
  assert.equal(scaffold.status, 'blocked');
  assert.match(scaffold.reason, /verified/);
  assert.equal(new ScaffoldGenerator({}).generate('AUTH_BYPASS', analysis, [], {}).status, 'blocked');
  assert.equal(new ScaffoldGenerator({}).generate('PRIV_ESC_WINDOWS', analysis, [], {}).status, 'blocked');
  assert.equal(new ScaffoldGenerator({}).selectTechnique(undefined, []), null);

  const server = new AdversarialMCPServer();
  server.analyzer.analyze = async () => analysis;
  const result = await server.findDangerousPatterns({ target_path: analysis.target.path });
  assert.ok(result.findings.some(f => f.function === 'printf'));
  assert.ok(result.findings.every(f => f.status === 'candidate'));
  assert.ok(result.findings.every(f => f.severity === 'medium'));
  assert.ok(result.findings.filter(f => 'value' in f).every(f => f.value === '[REDACTED]'));
  assert.doesNotMatch(JSON.stringify(result), /TOP_SECRET|PRIVATE KEY/);
  const strings = await server.getStrings({ target_path: analysis.target.path });
  assert.ok(strings.strings.every(entry => entry.value === '[REDACTED]'));
  const explicit = await server.getStrings({ target_path: analysis.target.path, reveal_sensitive: true });
  assert.match(explicit.strings[0].value, /TOP_SECRET/);
});

test('hunt pattern and severity flags select only requested review work', async () => {
  const hunter = new VulnHunter({ model: 'test' });
  hunter.selectPatterns = () => [
    { key: 'UNCHECKED_BOUNDS', severity: 'critical' },
    { key: 'WEAK_CRYPTO', severity: 'high' }
  ];
  const invoked = [];
  hunter.huntPattern = async (_target, _surface, pattern) => {
    invoked.push(pattern.key);
    return [];
  };
  await hunter.hunt({ path: '/tmp/test' }, { vectors: [] }, {
    binaryAnalysis: sampleAnalysis(), patterns: ['UNCHECKED_BOUNDS', 'WEAK_CRYPTO'], criticalOnly: true
  });
  assert.deepEqual(invoked, ['UNCHECKED_BOUNDS']);
});

test('unparseable reasoning output fails as incomplete instead of zero findings', async () => {
  const analysis = sampleAnalysis();
  const hunter = new VulnHunter({ model: 'test' });
  hunter.selectPatterns = () => [{ key: 'UNCHECKED_BOUNDS', ...HUNTING_PATTERNS.UNCHECKED_BOUNDS }];
  hunter.client.messages.create = async () => ({ content: [{ type: 'text', text: 'not JSON' }] });
  await assert.rejects(
    () => hunter.hunt({ path: analysis.target.path, type: 'elf' }, { vectors: [] },
      { binaryAnalysis: analysis }),
    /Review incomplete/
  );
  const surface = new AttackSurfaceEnumerator({ model: 'test' });
  assert.throws(() => surface.parseVectors({ content: [] }), /could not be parsed/);
  surface.analyzer.analyze = async () => { throw new Error('Unsupported target format: text'); };
  surface.client.messages.create = async () => { throw new Error('should not be called'); };
  await assert.rejects(
    () => surface.enumerate({ path: '/tmp/readme.js', type: 'text' }),
    /Unsupported target format: text/
  );
});

test('only locally sourced evidence IDs can advance a finding or chain', async () => {
  const analysis = sampleAnalysis();
  const finding = {
    id: 'f1', pattern: 'UNCHECKED_BOUNDS', status: 'observed', evidence_ids: ['site', 'trigger']
  };
  assert.equal(isVerifiedFinding(finding, analysis), false);
  const record = (id, kind, primitive) => ({
    id, target_sha256: analysis.target.sha256, status: 'observed',
    location_kind: kind, primitive, provider: 'fixture', provider_version: '1',
    location: '0x1000', detail: 'Observed fixture data', truncated: false
  });
  analysis.evidence = [
    record('site', 'call-site', 'memory-corruption'),
    record('trigger', 'trace', 'memory-corruption'),
    record('hijackTrace', 'trace', 'control-flow')
  ];
  assert.equal(isVerifiedFinding(finding, analysis), true);
  const primitives = new TelemetryMapper().mapTelemetryToPrimitives(analysis, [finding]);
  assert.equal(primitives.memory_corruption[0].source, 'local-evidence');
  assert.equal(primitives.memory_corruption[0].primitive, 'memory-corruption');
  const blockedScaffold = new ScaffoldGenerator({}).generate('CODE_EXEC_LINUX', analysis, [finding], {});
  assert.equal(blockedScaffold.status, 'blocked');
  assert.ok(blockedScaffold.unresolved?.length > 0);
  for (const template of ['PRIV_ESC_LINUX', 'SANDBOX_ESCAPE']) {
    const blocked = new ScaffoldGenerator({}).generate(template, analysis, [finding], {});
    assert.equal(blocked.status, 'blocked');
    assert.ok(blocked.unresolved?.length > 0, `${template} needs unresolved facts`);
  }
  analysis.evidence[1].truncated = true;
  assert.equal(isVerifiedFinding(finding, analysis), false);
  analysis.evidence[1].truncated = false;
  const hijack = {
    id: 'f2', pattern: 'control-flow', status: 'observed', evidence_ids: ['hijackTrace']
  };
  const builder = new ExploitChainBuilder({ model: 'test' });
  const template = {
    key: 'CODE_EXEC_LINUX', name: 'Test',
    stages: [{ name: 'corruption', primitive: 'memory-corruption' }, { name: 'hijack', primitive: 'control-flow' }]
  };
  const draft = {
    feasible: true, feasibility_score: 1, scaffold: {},
    stages: [
      { stage: 'corruption', vulnerability_used: 'f1', evidence_ids: ['trigger'] },
      { stage: 'hijack', vulnerability_used: 'f2', evidence_ids: [] }
    ]
  };
  const blocked = builder.validateChain(draft, template, [finding, hijack], analysis);
  assert.equal(blocked.feasible, false);
  assert.equal(blocked.feasibility_score, null);
  assert.equal(blocked.evidence_coverage, 0.5);
  assert.equal(builder.rankChains([blocked])[0].score, 50);
  builder.buildChain = async () => { throw new Error('should never call'); };
  assert.deepEqual(await builder.build({}, [{ ...finding, status: 'candidate' }], analysis, {}), []);
  const complete = builder.validateChain({
    ...draft, stages: [draft.stages[0], { ...draft.stages[1], evidence_ids: ['hijackTrace'] }]
  }, template, [finding, hijack], analysis);
  assert.equal(complete.feasible, true);
  assert.equal(builder.rankChains([complete])[0].score, 100);
});

test('analysis shares one telemetry object, labels candidates, and honors --no-chain', async () => {
  const rea = new AdversarialREA();
  const binary = sampleAnalysis();
  rea.binaryAnalyzer.analyze = async () => binary;
  rea.attackSurface.enumerate = async (_target, snapshot) => {
    assert.strictEqual(snapshot, binary);
    return { vectors: [], candidate_score: 0 };
  };
  rea.vulnHunter.hunt = async (_target, _surface, opts) => {
    assert.strictEqual(opts.binaryAnalysis, binary);
    return [{ id: 'model-only', status: 'candidate', pattern: 'UNCHECKED_BOUNDS' }];
  };
  rea.exploitChain.build = async () => { throw new Error('should never call'); };
  const result = await rea.analyzeTarget(binary.target.path, { buildChains: false });
  assert.equal(result.candidates.length, 1);
  assert.deepEqual(result.vulnerabilities, []);
  assert.deepEqual(result.exploitChains, []);
});

test('buildChains flag controls the verified-finding path and passes the shared snapshot', async () => {
  const rea = new AdversarialREA();
  const binary = sampleAnalysis();
  binary.evidence = [{
    id: 'trace', target_sha256: binary.target.sha256, status: 'observed',
    truncated: false, provider: 'fixture', provider_version: '1',
    location_kind: 'trace', location: '0x20', detail: 'Observed trigger',
    primitive: 'memory-corruption'
  }];
  const finding = {
    id: 'v1', pattern: 'UNCHECKED_BOUNDS', status: 'observed', evidence_ids: ['trace']
  };
  const surface = { vectors: [], candidate_score: 0 };
  rea.binaryAnalyzer.analyze = async () => binary;
  rea.attackSurface.enumerate = async () => surface;
  rea.vulnHunter.hunt = async () => [finding];
  let called = 0;
  rea.exploitChain.build = async (target, findings, snapshot, mappedSurface) => {
    called++;
    assert.equal(target.sha256, binary.target.sha256);
    assert.deepEqual(findings, [finding]);
    assert.strictEqual(snapshot, binary);
    assert.strictEqual(mappedSurface, surface);
    return [];
  };
  assert.equal((await rea.analyzeTarget(binary.target.path, { buildChains: false })).vulnerabilities.length, 1);
  assert.equal(called, 0);
  await rea.analyzeTarget(binary.target.path, { buildChains: true });
  assert.equal(called, 1);
});

test('server manifest mirrors registered MCP tools', () => {
  const manifest = JSON.parse(readFileSync(new URL('../../server.json', import.meta.url)));
  assert.deepEqual(
    manifest.tools.map(tool => tool.name).sort(),
    new AdversarialMCPServer().getToolList().map(tool => tool.name).sort()
  );
});
