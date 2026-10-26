#!/usr/bin/env node

/**
 * Adversarial REA CLI
 *
 * Command-line interface for offensive reverse engineering operations.
 */

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { AdversarialREA } from '../src/index.js';

const banner = `
${chalk.red('╔═══════════════════════════════════════════════════════════╗')}
${chalk.red('║')}  ${chalk.bold.white('ADVERSARIAL REA')} ${chalk.gray('- Red Team RE Harness')}                   ${chalk.red('║')}
${chalk.red('║')}  ${chalk.yellow('Multi-agent exploitation framework')}                        ${chalk.red('║')}
${chalk.red('╚═══════════════════════════════════════════════════════════╝')}
`;

program
  .name('adv-rea')
  .description('Adversarial reverse engineering harness with multi-agent swarms')
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
  .command('analyze <target>')
  .description('Full adversarial analysis of a target')
  .option('-t, --type <type>', 'Target type (pe, elf, android, etc.)')
  .option('-a, --agents <n>', 'Max parallel agents', '8')
  .option('-o, --output <file>', 'Output file for results')
  .option('--no-aggressive', 'Disable aggressive mode (on by default)')
  .option('--no-chain', 'Skip exploit chain building')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Initializing adversarial analysis...').start();

    try {
      const rea = new AdversarialREA({
        maxAgents: parseInt(options.agents, 10),
        aggressiveMode: options.aggressive
      });

      spinner.text = 'Running full analysis pipeline...';
      const results = await rea.analyzeTarget(target, {
        type: options.type,
        buildChains: options.chain !== false
      });

      spinner.succeed('Analysis complete');

      console.log('\n' + chalk.bold.cyan('═══ RESULTS ═══'));
      console.log(chalk.yellow('\nAttack Surface Score:'), results.attackSurface?.score || 0);
      console.log(chalk.yellow('Vulnerabilities Found:'), results.vulnerabilities?.length || 0);
      console.log(chalk.yellow('Exploit Chains:'), results.exploitChains?.length || 0);

      if (results.vulnerabilities?.length > 0) {
        console.log('\n' + chalk.bold.red('TOP VULNERABILITIES:'));
        for (const vuln of results.vulnerabilities.slice(0, 5)) {
          console.log(chalk.red('  •'), vuln.pattern, '-', vuln.location);
          console.log(chalk.gray('    Severity:'), vuln.impact?.severity || 'unknown');
        }
      }

      if (results.exploitChains?.length > 0) {
        console.log('\n' + chalk.bold.magenta('EXPLOIT CHAINS:'));
        for (const chain of results.exploitChains.slice(0, 3)) {
          console.log(chalk.magenta('  •'), chain.name);
          console.log(chalk.gray('    Feasibility:'), (chain.feasibility_score * 100).toFixed(0) + '%');
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
      const rea = new AdversarialREA({ maxAgents: parseInt(options.agents) });

      const mission = {
        objective: options.mission || 'Full vulnerability assessment',
        roles: options.roles?.split(',').map(r => r.trim())
      };

      spinner.text = `Swarm active: ${options.agents} agents hunting...`;
      const results = await rea.deploySwarm({ path: target }, mission);

      spinner.succeed('Swarm complete');

      console.log('\n' + chalk.bold.cyan('═══ SWARM RESULTS ═══'));
      for (const agent of results.agentResults) {
        const status = agent.status === 'fulfilled' ? chalk.green('✓') : chalk.red('✗');
        console.log(status, chalk.bold(agent.role));

        if (agent.findings?.parsed?.findings) {
          for (const f of agent.findings.parsed.findings.slice(0, 3)) {
            console.log(chalk.gray('  └─'), f.class, '-', f.severity);
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
  .description('Vulnerability hunting with specific patterns')
  .option('-p, --patterns <patterns>', 'Comma-separated vulnerability patterns')
  .option('--critical-only', 'Hunt only critical severity patterns')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Initializing vulnerability hunt...').start();

    try {
      const rea = new AdversarialREA();

      spinner.text = 'Enumerating attack surface...';
      const surface = await rea.attackSurface.enumerate({ path: target, type: 'unknown' });

      spinner.text = 'Hunting vulnerabilities...';
      const vulns = await rea.vulnHunter.hunt({ path: target }, surface);

      spinner.succeed(`Hunt complete: ${vulns.length} findings`);

      console.log('\n' + chalk.bold.red('═══ VULNERABILITIES ═══'));
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
        console.log(chalk.gray('  Confidence:'), (vuln.confidence * 100).toFixed(0) + '%');
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
  .option('-t, --type <type>', 'Target type')
  .action(async (target, options) => {
    requireApiKey();
    console.log(banner);
    const spinner = ora('Enumerating attack surface...').start();

    try {
      const rea = new AdversarialREA();
      const surface = await rea.attackSurface.enumerate({
        path: target,
        type: options.type || 'unknown'
      });

      spinner.succeed('Enumeration complete');

      console.log('\n' + chalk.bold.cyan('═══ ATTACK SURFACE ═══'));
      console.log(chalk.yellow('Score:'), surface.score);

      console.log('\n' + chalk.bold('Attack Vectors:'), surface.vectors?.length || 0);
      for (const v of (surface.vectors || []).slice(0, 5)) {
        console.log(chalk.red('  •'), v.vector_type, '-', v.entry_point);
      }

      console.log('\n' + chalk.bold('Trust Boundaries:'), surface.boundaries?.length || 0);
      for (const b of (surface.boundaries || []).slice(0, 5)) {
        console.log(chalk.yellow('  •'), b.boundary_type, ':', b.from_context, '→', b.to_context);
      }

      console.log('\n' + chalk.bold('Exploitation Primitives:'), surface.primitives?.length || 0);
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
