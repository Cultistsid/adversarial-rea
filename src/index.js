/**
 * Adversarial REA - Red Team Reverse Engineering Harness
 *
 * Native binary telemetry and optional review agents.
 * Claims remain candidates until local evidence is available.
 */

import { AgentSwarm } from './core/swarm.js';
import { AttackSurfaceEnumerator } from './core/attack-surface.js';
import { ExploitChainBuilder } from './core/exploit-chain.js';
import { VulnHunter } from './core/vuln-hunter.js';
import { BinaryAnalyzer } from './core/binary-analyzer.js';
import { CallSiteExtractor } from './core/call-sites.js';
import { CarrierInspector } from './core/carrier-inspector.js';
import { GadgetCandidateFinder } from './core/gadget-candidates.js';
import { isVerifiedFinding } from './core/evidence.js';

export class AdversarialREA {
  constructor(config = {}) {
    this.config = {
      model: config.model || 'claude-opus-5-5',
      maxAgents: config.maxAgents || 8,
      aggressiveMode: config.aggressiveMode ?? true,
      parallelAnalysis: config.parallelAnalysis ?? true,
      timeout: config.timeout || 300000,
      ...config
    };

    this.swarm = new AgentSwarm(this.config);
    this.attackSurface = new AttackSurfaceEnumerator(this.config);
    this.exploitChain = new ExploitChainBuilder(this.config);
    this.vulnHunter = new VulnHunter(this.config);
    this.binaryAnalyzer = new BinaryAnalyzer();
    this.callSites = new CallSiteExtractor(this.binaryAnalyzer);
    this.carriers = new CarrierInspector(this.binaryAnalyzer);
    this.gadgets = new GadgetCandidateFinder(this.binaryAnalyzer);
  }

  async analyzeTarget(targetPath, options = {}) {
    const binaryAnalysis = await this.binaryAnalyzer.analyze(targetPath);
    const type = binaryAnalysis.target.type;
    if (options.type && ![type, `${type}-shared`, `${type}-driver`].includes(options.type)) {
      throw new Error(`Target type mismatch: detected ${type}, requested ${options.type}`);
    }
    const target = {
      path: binaryAnalysis.target.path,
      type,
      sha256: binaryAnalysis.target.sha256
    };
    const callSites = options.traceCalls
      ? await this.callSites.trace(binaryAnalysis, { sinks: options.sinks })
      : null;
    const gadgets = options.findGadgets
      ? await this.gadgets.find(binaryAnalysis, { limit: 50 }) : null;
    binaryAnalysis.evidence = [
      ...(binaryAnalysis.evidence || []),
      ...(callSites?.calls || []).map(call => call.evidence),
      ...(gadgets?.candidates || []).map(candidate => candidate.evidence)
    ];

    const analysis = {
      target,
      callSites,
      gadgets,
      attackSurface: null,
      vulnerabilities: [],
      candidates: [],
      exploitChains: [],
      evidence: binaryAnalysis.evidence,
      timestamp: new Date().toISOString()
    };

    // Phase 1: Attack surface enumeration (parallel agents)
    analysis.attackSurface = await this.attackSurface.enumerate(target, binaryAnalysis);

    // Phase 2: Vulnerability hunting (swarm deployment)
    analysis.candidates = await this.vulnHunter.hunt(
      target,
      analysis.attackSurface,
      { binaryAnalysis, patterns: options.patterns, criticalOnly: options.criticalOnly }
    );
    analysis.vulnerabilities = analysis.candidates.filter(f => isVerifiedFinding(f, binaryAnalysis));

    // Phase 3: Exploit chain construction
    if (options.buildChains !== false && analysis.vulnerabilities.length > 0) {
      analysis.exploitChains = await this.exploitChain.build(
        target,
        analysis.vulnerabilities,
        binaryAnalysis,
        analysis.attackSurface
      );
    }

    return analysis;
  }

  async detectTargetType(targetPath) {
    return this.binaryAnalyzer.getFileType(targetPath);
  }

  async deploySwarm(target, mission, binaryAnalysis = null) {
    return this.swarm.deploy(target, mission, binaryAnalysis);
  }
}

export { AgentSwarm, AttackSurfaceEnumerator, ExploitChainBuilder, VulnHunter };
