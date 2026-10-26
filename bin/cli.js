#!/usr/bin/env node

/**
 * Adversarial REA CLI
 *
 * Command-line interface for native binary triage and review hypotheses.
 */

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { AdversarialREA } from '../src/index.js';
import { HUNTING_PATTERNS } from '../src/core/vuln-hunter.js';
import { BinaryAnalyzer, boundedInteger } from '../src/core/binary-analyzer.js';
import { CallSiteExtractor } from '../src/core/call-sites.js';
import { CarrierInspector } from '../src/core/carrier-inspector.js';
import { FlowFixtureInspector } from '../src/core/flow-fixtures.js';
import { GadgetCandidateFinder } from '../src/core/gadget-candidates.js';

const banner = `
${chalk.red('╔═══════════════════════════════════════════════════════════╗')}
${chalk.red('║')}  ${chalk.bold.white('ADVERSARIAL REA')} ${chalk.gray('- Red Team RE Harness')}                   ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('Evidence-first native binary triage')}                     ${chalk.red('║')}
${chalk.red('╚═══════════════════════════════════════════════════════════╝')}
`;

program
  .name('adv-rea')
  .description('Native binary triage with optional parallel review agents')
  .version('0.1.0');

function requireApiKey() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.log(banner);
    console.error(chalk.red('Error:'), 'ANTHROPIC_API_KEY is not set.');
    console.error(chalk.gray('  The analysis pipeline uses the Anthropic API. Set your key first:'));
    console.error(chalk.gray('    export ANTHROPIC_API_KEY=sk-ant-...'));
    process.exit(1);
  }
}

program
  .command('inspect <target>')
  .description('Local, bounded metadata triage without a remote service')
  .option('-l, --limit <n>', 'Maximum directory entries or call sites', '100')
  .option('--calls', 'List observed native call sites (input flow remains unknown)')
  .option('--gadgets', 'List byte-verified ELF64 x86_64 gadget candidates')
  .option('--flow-fixture', 'Replay a bounded declarative .flow.json fixture in memory only')
  .option('--arch <slice>', 'Mach-O architecture for calls: host, all, x86_64, arm64, arm64e', 'host')
  .action(async (target, options) => {
    try {
      const limit = boundedInteger(Number(options.limit), 100, 200);
      if (options.flowFixture && (options.calls || options.gadgets)) {
        throw new Error('Fixture replay cannot be combined with native call or gadget inspection');
      }
      const analyzer = new BinaryAnalyzer();
      const carrier = await new CarrierInspector(analyzer).inspect(target, { limit });
      const result = { carrier };
      if (options.flowFixture) {
        result.flow_fixture = await new FlowFixtureInspector(analyzer).inspect(target);
      }
      let analysis;
      if (options.calls) {
        if (!['elf', 'macho', 'pe'].includes(carrier.target.type)) {
          throw new Error('Call-site extraction requires a native file');
        }
        analysis = await analyzer.analyze(target);
        result.call_sites = await new CallSiteExtractor(analyzer).trace(analysis, {
          limit, arch: options.arch
        });
      }
      if (options.gadgets) {
        if (!['elf', 'macho', 'pe'].includes(carrier.target.type)) {
          throw new Error('Gadget inspection requires a native file');
        }
        analysis ||= await analyzer.analyze(target);
        result.gadgets = await new GadgetCandidateFinder(analyzer).find(analysis, {
          limit: Math.min(limit, 100)
        });
      }
      console.log(JSON.stringify(result, null, 2));
    } catch (error) {
      console.error('Inspection failed:', error.message);
      process.exitCode = 1;
    }
  });

program
  .command('analyze <target>')
  .description('Full adversarial analysis of a target')
  .option('-t, --type <type>', 'Assert native format (elf, macho, pe)')
  .option('-a, --agents <n>', 'Max parallel agents', '8')
  .option('-o, --output <file>', 'Output file for results')
  .option('--no-aggressive', 'Disable aggressive mode (on by default)')
  .option('--no-chain', 'Skip exploit chain building')
  .option('--trace-calls', 'Add observed native call instructions (not vulnerability claims)')
  .option('--find-gadgets', 'Add ELF64 x86_64 byte-verified gadget candidates')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Initializing adversarial analysis...').start();

    try {
      const rea = new AdversarialREA({
        maxAgents: boundedInteger(Number(options.agents), 8, 16),
        aggressiveMode: options.aggressive
      });

      spinner.text = 'Running full analysis pipeline...';
      const results = await rea.analyzeTarget(target, {
        type: options.type,
        traceCalls: options.traceCalls,
        findGadgets: options.findGadgets,
        buildChains: options.chain !== false
      });

      spinner.succeed('Analysis complete');

      console.log('\n' + chalk.bold.cyan('═══ RESULTS ═══'));
      console.log(chalk.yellow('\nCandidate triage score:'), results.attackSurface?.candidate_score ?? 'unknown');
      console.log(chalk.yellow('Unverified candidates:'), results.candidates?.length || 0);
      console.log(chalk.yellow('Evidence-backed vulnerabilities:'), results.vulnerabilities?.length || 0);
      console.log(chalk.yellow('Evidence-complete chain reviews:'), results.exploitChains?.length || 0);
      if (results.callSites) {
        console.log(chalk.yellow('Observed call instructions:'), results.callSites.calls.length);
        console.log(chalk.gray('Call-site extraction status:'), results.callSites.status);
      }
      if (results.gadgets) {
        console.log(chalk.yellow('Byte-verified gadget candidates:'), results.gadgets.candidates.length);
        console.log(chalk.gray('Gadget extraction status:'), results.gadgets.status);
      }

      if (results.vulnerabilities?.length > 0) {
        console.log('\n' + chalk.bold.red('EVIDENCE-BACKED FINDINGS:'));
        for (const vuln of results.vulnerabilities.slice(0, 5)) {
          console.log(chalk.red('  •'), vuln.pattern, '-', vuln.location);
          console.log(chalk.gray('    Severity:'), vuln.impact?.severity || 'unknown');
        }
      }

      if (results.exploitChains?.length > 0) {
        console.log('\n' + chalk.bold.magenta('EXPLOIT CHAINS:'));
        for (const chain of results.exploitChains.slice(0, 3)) {
          console.log(chalk.magenta('  •'), chain.name);
          console.log(chalk.gray('    Evidence coverage:'), (chain.evidence_coverage * 100).toFixed(0) + '%');
        }
      }

      if (options.output) {
        const fs = await import('fs');
        fs.writeFileSync(options.output, JSON.stringify(results, null, 2));
        console.log(chalk.green('\nResults saved to:'), options.output);
      }

    } catch (err) {
      spinner.fail('Analysis failed');
      console.error(chalk.red('Error:'), err.message);
      process.exit(1);
    }
  });

program
  .command('swarm <target>')
  .description('Deploy agent swarm for targeted analysis')
  .option('-m, --mission <objective>', 'Mission objective')
  .option('-r, --roles <roles>', 'Comma-separated agent roles')
  .option('-a, --agents <n>', 'Max parallel agents', '8')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Deploying agent swarm...').start();

    try {
      const rea = new AdversarialREA({ maxAgents: boundedInteger(Number(options.agents), 8, 16) });

      const mission = {
        objective: options.mission || 'Full vulnerability assessment',
        roles: options.roles?.split(',').map(r => r.trim())
      };
      const binary = await rea.binaryAnalyzer.analyze(target);

      spinner.text = `Running ${options.agents} review agents...`;
      const results = await rea.deploySwarm(
        { path: binary.target.path, type: binary.target.type }, mission, binary
      );

      spinner.succeed('Swarm complete');

      console.log('\n' + chalk.bold.cyan('═══ SWARM RESULTS ═══'));
      for (const agent of results.agentResults) {
        const status = agent.status === 'fulfilled' ? chalk.green('✓') : chalk.red('✗');
        console.log(status, chalk.bold(agent.role));
        if (agent.error) console.log(chalk.gray('  └─'), agent.error);

        if (agent.findings?.parsed?.findings) {
          for (const f of agent.findings.parsed.findings.slice(0, 3)) {
            console.log(chalk.gray('  └─ Candidate:'), f.class, '-', f.severity, '(unverified)');
          }
        }
      }

    } catch (err) {
      spinner.fail('Swarm deployment failed');
      console.error(chalk.red('Error:'), err.message);
      process.exit(1);
    }
  });

program
  .command('hunt <target>')
  .description('Unverified vulnerability triage with specific patterns')
  .option('-p, --patterns <patterns>', 'Comma-separated vulnerability patterns')
  .option('--critical-only', 'Hunt only critical severity patterns')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Initializing vulnerability hunt...').start();

    try {
      const rea = new AdversarialREA();
      const binary = await rea.binaryAnalyzer.analyze(target);
      const targetInfo = { path: binary.target.path, type: binary.target.type };
      const patterns = options.patterns?.split(',').map(p => p.trim().toUpperCase());
      if (patterns?.some(p => !HUNTING_PATTERNS[p])) {
        throw new Error(`Unknown pattern; choose from ${Object.keys(HUNTING_PATTERNS).join(', ')}`);
      }

      spinner.text = 'Enumerating attack surface...';
      const surface = await rea.attackSurface.enumerate(targetInfo, binary);

      spinner.text = 'Hunting vulnerabilities...';
      const vulns = await rea.vulnHunter.hunt(targetInfo, surface, {
        binaryAnalysis: binary, patterns, criticalOnly: options.criticalOnly
      });

      spinner.succeed(`Hunt complete: ${vulns.length} unverified candidates`);

      console.log('\n' + chalk.bold.red('═══ REVIEW CANDIDATES (NOT VERIFIED) ═══'));
      for (const vuln of vulns) {
        const severity = {
          critical: chalk.bgRed.white,
          high: chalk.red,
          medium: chalk.yellow,
          low: chalk.gray
        }[vuln.impact?.severity] || chalk.white;

        console.log(severity(` ${vuln.impact?.severity?.toUpperCase() || 'UNKNOWN'} `), vuln.pattern);
        console.log(chalk.gray('  Location:'), vuln.location);
        console.log(chalk.gray('  CWE:'), vuln.cwe);
        console.log(chalk.gray('  Evidence:'), vuln.missing_evidence.join(', '));
        console.log();
      }

    } catch (err) {
      spinner.fail('Hunt failed');
      console.error(chalk.red('Error:'), err.message);
      process.exit(1);
    }
  });

program
  .command('surface <target>')
  .description('Attack surface enumeration only')
  .option('-t, --type <type>', 'Assert native format (elf, macho, pe)')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Enumerating attack surface...').start();

    try {
      const rea = new AdversarialREA();
      const binary = await rea.binaryAnalyzer.analyze(target);
      if (options.type && options.type !== binary.target.type) {
        throw new Error(`Target type mismatch: detected ${binary.target.type}, requested ${options.type}`);
      }
      const surface = await rea.attackSurface.enumerate({
        path: binary.target.path,
        type: binary.target.type
      }, binary);

      spinner.succeed('Enumeration complete');

      console.log('\n' + chalk.bold.cyan('═══ ATTACK SURFACE ═══'));
      console.log(chalk.yellow('Candidate triage score (not exploitability):'), surface.candidate_score);

      console.log('\n' + chalk.bold('Attack Vectors:'), surface.vectors?.length || 0);
      for (const v of (surface.vectors || []).slice(0, 5)) {
        console.log(chalk.red('  •'), v.vector_type, '-', v.entry_point);
      }

      console.log('\n' + chalk.bold('Trust Boundaries:'), surface.boundaries?.length || 0);
      for (const b of (surface.boundaries || []).slice(0, 5)) {
        console.log(chalk.yellow('  •'), b.boundary_type, ':', b.from_context, '→', b.to_context);
      }

      console.log('\n' + chalk.bold('Unverified primitive hypotheses:'), surface.primitives?.length || 0);
      for (const p of (surface.primitives || []).slice(0, 5)) {
        console.log(chalk.magenta('  •'), p.primitive_type, '-', p.location);
      }

    } catch (err) {
      spinner.fail('Enumeration failed');
      console.error(chalk.red('Error:'), err.message);
      process.exit(1);
    }
  });

program.parse();
