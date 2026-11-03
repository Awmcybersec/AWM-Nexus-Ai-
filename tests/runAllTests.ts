/**
 * AWM Nexus — Main Test Runner Entrypoint
 */

import { runComprehensiveVerification } from '../src/tests/testSuite';

async function main() {
  console.log(`[+] Initializing AWM Nexus Human Pentester Tooling Comprehensive Verification...\n`);
  const result = await runComprehensiveVerification();

  console.log(`\n======================================================`);
  console.log(`     AWM NEXUS COMPREHENSIVE VERIFICATION REPORT      `);
  console.log(`======================================================`);
  for (const r of result.results) {
    const statusTag = r.success ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[FAIL]\x1b[0m';
    console.log(` ${statusTag} [${r.category}] ${r.name} ${r.error ? '\x1b[31m(' + r.error + ')\x1b[0m' : ''}`);
  }
  console.log(`------------------------------------------------------`);
  console.log(`TOTAL TESTS: ${result.passed + result.failed} | PASSED: ${result.passed} | FAILED: ${result.failed} | SKIPPED: ${result.skipped}`);
  console.log(`REGISTRY: Registered: ${result.registryStats.registered} | Installed (Live): ${result.registryStats.installed} | Available (Remote Agent): ${result.registryStats.available} | Not Configured: ${result.registryStats.notConfigured} | Not Installed: ${result.registryStats.notInstalled} | Simulated: ${result.registryStats.simulated}`);
  console.log(`======================================================\n`);

  process.exitCode = result.failed > 0 ? 1 : 0;
}

main().catch(err => {
  console.error('[!] Test suite runner failed:', err);
  process.exit(1);
});
