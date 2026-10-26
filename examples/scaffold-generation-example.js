/**
 * Example: Evidence gate on a native binary
 *
 * No call-site/trigger evidence producer exists in this release; no exploit
 * scaffold is generated or written to disk.
 */

import { pathToFileURL } from 'node:url';
import { BinaryAnalyzer } from '../src/core/binary-analyzer.js';
import { ScaffoldGenerator } from '../src/core/exploit-scaffolds.js';

async function generateExploitScaffold(targetPath) {
  const analyzer = new BinaryAnalyzer();
  const binaryAnalysis = await analyzer.analyze(targetPath);
  const scaffold = new ScaffoldGenerator({}).generate(
    'CODE_EXEC_LINUX', binaryAnalysis, [], {}
  );
  return {
    target: binaryAnalysis.target,
    import_count: binaryAnalysis.imports.length,
    security: binaryAnalysis.security,
    scaffold
  };
}

function displayScaffoldDetails(result) {
  console.log(`Target: ${result.target.name} (${result.target.type})`);
  console.log(`SHA-256: ${result.target.sha256}`);
  console.log(`Imports observed: ${result.import_count}`);
  console.log(`Scaffold: ${result.scaffold.status} - ${result.scaffold.reason}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const targetPath = process.argv[2] || '/bin/ls';
  generateExploitScaffold(targetPath)
    .then(displayScaffoldDetails)
    .catch(err => {
      console.error('Error:', err.message);
      process.exitCode = 1;
    });
}

export { generateExploitScaffold, displayScaffoldDetails };
