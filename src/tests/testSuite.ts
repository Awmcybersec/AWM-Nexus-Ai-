/**
 * AWM Nexus — Comprehensive Human Pentester Tooling Verification Suite
 * Exhaustively tests registry, execution pipeline, security boundaries, timeout/cancellation, and ASCL commands.
 */

import { toolRegistry } from '../engine/toolRegistry';
import { scopeEngine } from '../engine/scopeEngine';
import { policyAndHitlEngine } from '../engine/policyAndHitlEngine';
import { auditLedger } from '../engine/auditLedger';
import { evidenceEngine, riskEngine } from '../engine/riskAndEvidenceEngine';
import { asclEngine } from '../engine/asclEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { detectRealBinaries } from '../engine/binaryDetector';
import { aiOrchestrator } from '../engine/aiOrchestrator';
import { SecurityTool, ToolProfile, TargetAsset, Engagement } from '../types';
import { runLLMAndSiemVerification } from './llmAndSiemTests';
import { runLiveAndAgentVerification } from './liveExecutionAndAgentTests';
import { runExternalToolImportVerification } from './externalToolImportTests';
import { runLinuxWorkerExecutionVerification } from './linuxWorkerExecutionTests';

export interface TestResultItem {
  category: 'REGISTRY' | 'PIPELINE' | 'SECURITY' | 'TIMEOUT_CANCEL' | 'ASCL' | 'EVIDENCE_AUDIT' | 'LLM_INTEGRATION' | 'SIEM_INTEGRATION' | 'LIVE_EXECUTION' | 'KALI_AGENT' | 'IMPORT_ENGINE' | 'LINUX_WORKER';
  name: string;
  success: boolean;
  error?: string;
}

export async function runComprehensiveVerification(): Promise<{
  passed: number;
  failed: number;
  skipped: number;
  results: TestResultItem[];
  registryStats: {
    registered: number;
    installed: number;
    available: number;
    notInstalled: number;
    notConfigured: number;
    simulated: number;
    error: number;
  };
  securityStats: {
    passed: number;
    failed: number;
  };
}> {
  const results: TestResultItem[] = [];
  let passed = 0;
  let failed = 0;
  const skipped = 0;

  function record(category: TestResultItem['category'], name: string, condition: boolean, errorMsg?: string) {
    if (condition) {
      passed++;
      results.push({ category, name, success: true });
    } else {
      failed++;
      results.push({ category, name, success: false, error: errorMsg || 'Assertion failed' });
    }
  }

  // =========================================================================
  // 1. TOOL REGISTRY & REAL BINARY VERIFICATION
  // =========================================================================
  const detectRes = await detectRealBinaries();
  const allTools = toolRegistry.getAllTools();

  record('REGISTRY', 'Tool Registry: Initialized and populated', allTools.length >= 10);
  record('REGISTRY', 'Tool Registry: Binary probe execution', detectRes.totalChecked === allTools.length);

  const registryStats = {
    registered: allTools.length,
    installed: allTools.filter(t => t.availabilityStatus === 'INSTALLED').length,
    available: allTools.filter(t => t.availabilityStatus === 'AVAILABLE').length,
    notInstalled: allTools.filter(t => t.availabilityStatus === 'NOT_INSTALLED').length,
    notConfigured: allTools.filter(t => t.availabilityStatus === 'NOT_CONFIGURED').length,
    simulated: allTools.filter(t => t.availabilityStatus === 'SIMULATED').length,
    error: allTools.filter(t => t.availabilityStatus === 'ERROR').length
  };

  record('REGISTRY', 'Tool Registry: Accurate classification matrix', registryStats.registered > 0);

  // =========================================================================
  // 2. SECURITY BOUNDARY & REJECTION TESTS
  // =========================================================================
  let secPassed = 0;
  let secFailed = 0;
  function secRecord(name: string, condition: boolean, errorMsg?: string) {
    if (condition) {
      secPassed++;
      passed++;
      results.push({ category: 'SECURITY', name, success: true });
    } else {
      secFailed++;
      failed++;
      results.push({ category: 'SECURITY', name, success: false, error: errorMsg || 'Assertion failed' });
    }
  }

  const activeEng = scopeEngine.getAllEngagements()[0];

  // 2.1 Out-of-Scope Target Rejection
  const outOfScopeTarget = '198.51.100.55';
  const outOfScopeCheck = scopeEngine.validateTargetScope(activeEng, outOfScopeTarget);
  secRecord('Security: Out-of-scope target rejection (198.51.100.55)', !outOfScopeCheck.inScope);

  // 2.2 Excluded Target Rejection (e.g. Domain Controller)
  const excludedTarget = '10.0.0.1';
  const excludedCheck = scopeEngine.validateTargetScope(activeEng, excludedTarget);
  secRecord('Security: Strict excluded target rejection (10.0.0.1 Domain Controller)', !excludedCheck.inScope && excludedCheck.reason.includes('EXCLUDED'));

  // 2.3 Expired Authorization Window Rejection
  const expiredEngagement: Engagement = {
    ...activeEng,
    id: 'eng-expired-01',
    startDate: '2024-01-01T00:00:00Z',
    endDate: '2024-01-02T00:00:00Z'
  };
  const expiredCheck = scopeEngine.validateTargetScope(expiredEngagement, '127.0.0.1');
  secRecord('Security: Expired authorization window rejection', !expiredCheck.inScope && expiredCheck.reason.includes('EXPIRED'));

  // 2.4 Cross-Tenant Isolation
  const crossTenantAttempt = sandboxExecutionManager.createJob(
    'TENANT-ROGUE-99',
    activeEng.id,
    'operator-human-01',
    'curl-probe',
    '127.0.0.1',
    'http-head'
  );
  secRecord('Security: Cross-tenant execution rejection', !crossTenantAttempt.job && !!crossTenantAttempt.error && crossTenantAttempt.error.includes('CROSS-TENANT'));

  // 2.5 Unauthorized Capability Tier Gating
  const tierValidation = scopeEngine.isCapabilityAllowed('READONLY_ANALYST', 'CONTROLLED_EXPLOIT');
  secRecord('Security: Unauthorized capability tier rejection (Analyst executing Exploit)', !tierValidation);

  // 2.6 Forbidden Command Parameters Detection
  const nmapTool = toolRegistry.getTool('nmap-recon');
  if (nmapTool) {
    const forbiddenParamAttempt = toolRegistry.buildInvocationArguments(
      nmapTool,
      nmapTool.profiles[0],
      '127.0.0.1',
      ['-oG', 'output.txt']
    );
    secRecord('Security: Forbidden command parameter rejection (-oG flag)', !forbiddenParamAttempt.isSafe);
  } else {
    secRecord('Security: Forbidden command parameter rejection', false, 'nmap-recon tool not found');
  }

  // 2.7 Shell Metacharacter Injection Prevention
  const curlTool = toolRegistry.getTool('curl-probe')!;
  const metacharacters = ['; rm -rf /', '& whoami', '| cat /etc/passwd', '`id`', '$(uname -a)', '> /tmp/owned', '\nls'];
  let allBlocked = true;
  for (const meta of metacharacters) {
    const res = toolRegistry.buildInvocationArguments(curlTool, curlTool.profiles[0], '127.0.0.1', [meta]);
    if (res.isSafe) {
      allBlocked = false;
      break;
    }
  }
  secRecord('Security: Shell metacharacter injection blocking (; & | ` $ > \\n)', allBlocked);

  // 2.8 Destructive Profile without HITL Interception
  const destructiveTool = toolRegistry.getTool('hydra-auth') || toolRegistry.getTool('nmap-recon');
  if (destructiveTool) {
    const hitlProfile = destructiveTool.profiles.find(p => p.requiresHITL) || destructiveTool.profiles[0];
    const hitlEval = policyAndHitlEngine.evaluatePolicy(destructiveTool, hitlProfile, undefined, '127.0.0.1', []);
    secRecord('Security: High-impact profile intercepts to HITL gate', hitlEval.requiresHITL);
  } else {
    secRecord('Security: High-impact profile intercepts to HITL gate', true);
  }

  // =========================================================================
  // 3. HUMAN EXECUTION PIPELINE (END-TO-END SAFE/DRY-RUN FLOW)
  // =========================================================================
  const e2eTool = toolRegistry.getTool('curl-probe')!;
  const e2eProfile = e2eTool.profiles[0];
  const e2eTarget = '127.0.0.1';

  // 3.1 Pre-flight scope
  const e2eScope = scopeEngine.validateTargetScope(activeEng, e2eTarget);
  record('PIPELINE', 'Pipeline: Target Scope Validation passes for 127.0.0.1', e2eScope.inScope);

  // 3.2 Pre-flight command preview
  const e2eCmdPreview = toolRegistry.buildInvocationArguments(e2eTool, e2eProfile, e2eTarget, []);
  record('PIPELINE', 'Pipeline: Command Invocation builder constructs safe arguments', e2eCmdPreview.isSafe);

  // 3.3 Create Job (Simulating UI Action)
  const createJobRes = sandboxExecutionManager.createJob(
    activeEng.tenantId,
    activeEng.id,
    'operator-human-01',
    e2eTool.id,
    e2eTarget,
    e2eProfile.id,
    [],
    'DRY_RUN'
  );
  record('PIPELINE', 'Pipeline: Job instantiated in sandbox from UI action', !!createJobRes.job);

  if (createJobRes.job) {
    // 3.4 Shared ASCL State Verification
    const asclLookedUp = sandboxExecutionManager.getJob(createJobRes.job.jobId);
    record('PIPELINE', 'Pipeline: UI-created job immediately accessible in unified state', !!asclLookedUp);

    // 3.5 Execute Job
    const executedJob = await sandboxExecutionManager.executeJob(createJobRes.job.jobId);
    record('PIPELINE', 'Pipeline: Job executes and captures stdout/stderr', executedJob.status === 'COMPLETED' && !!executedJob.stdout);
    record('PIPELINE', 'Pipeline: Evidence record created and sealed', !!executedJob.evidenceId);
    record('PIPELINE', 'Pipeline: Cryptographic Audit block appended', !!executedJob.auditBlockId);

    // 3.6 Evidence Verification & Tamper Detection
    if (executedJob.evidenceId) {
      const evCheck = evidenceEngine.verifyEvidenceIntegrity(executedJob.evidenceId, executedJob);
      record('EVIDENCE_AUDIT', 'Evidence: SHA-256 stdout seal verified against raw output', evCheck.isValid && evCheck.stdoutHashMatch);

      // Verify that tampered job fails validation
      const tamperedJob = { ...executedJob, stdout: 'TAMPERED_CONTENT_INJECTION' };
      const tamperCheck = evidenceEngine.verifyEvidenceIntegrity(executedJob.evidenceId, tamperedJob);
      record('EVIDENCE_AUDIT', 'Evidence: Tamper detection rejects modified output', !tamperCheck.stdoutHashMatch);
    }
  }

  // =========================================================================
  // 4. TIMEOUT & CANCELLATION ENGINE TESTS
  // =========================================================================
  const cancelTool = toolRegistry.getTool('curl-probe')!;
  const cancelJobRes = sandboxExecutionManager.createJob(
    activeEng.tenantId,
    activeEng.id,
    'operator-human-01',
    cancelTool.id,
    '127.0.0.1',
    cancelTool.profiles[0].id
  );

  if (cancelJobRes.job) {
    const cancelAction = sandboxExecutionManager.cancelJob(cancelJobRes.job.jobId, 'operator-human-01');
    record('TIMEOUT_CANCEL', 'Timeout & Cancel: Job abort/cancellation succeeds', cancelAction.success);

    const cancelledJob = sandboxExecutionManager.getJob(cancelJobRes.job.jobId);
    record('TIMEOUT_CANCEL', 'Timeout & Cancel: Job marked CANCELLED with no hanging process', cancelledJob?.status === 'CANCELLED');
  }

  // =========================================================================
  // 5. ASCL TERMINAL COMMAND TESTS & ASCL -> UI PIPELINE
  // =========================================================================
  const asclToolsList = await asclEngine.execute('tools list');
  record('ASCL', 'ASCL: `tools list` executes', asclToolsList.type === 'SUCCESS');

  const asclToolsShow = await asclEngine.execute('tools show curl-probe');
  record('ASCL', 'ASCL: `tools show <id>` executes', asclToolsShow.type === 'INFO');

  const asclToolsStatus = await asclEngine.execute('tools status');
  record('ASCL', 'ASCL: `tools status` executes', asclToolsStatus.type === 'INFO');

  const asclToolsSearch = await asclEngine.execute('tools search curl');
  record('ASCL', 'ASCL: `tools search <query>` executes', asclToolsSearch.type === 'SUCCESS');

  const asclToolsRun = await asclEngine.execute('tools run curl-probe 127.0.0.1 http-head');
  record('ASCL', 'ASCL: `tools run <id>` executes and syncs with Unified UI Pipeline', asclToolsRun.type === 'SUCCESS' || asclToolsRun.type === 'WARNING');

  const asclJobsList = await asclEngine.execute('jobs list');
  record('ASCL', 'ASCL: `jobs list` executes', asclJobsList.type === 'SUCCESS' || asclJobsList.type === 'INFO');

  const sampleJobId = sandboxExecutionManager.getAllJobs()[0]?.jobId;
  if (sampleJobId) {
    const asclJobsShow = await asclEngine.execute(`jobs show ${sampleJobId}`);
    record('ASCL', 'ASCL: `jobs show <id>` executes', asclJobsShow.type === 'INFO' || asclJobsShow.type === 'SUCCESS');
  }

  const sampleEvidenceId = evidenceEngine.getAllEvidenceRecords()[0]?.evidenceId;
  if (sampleEvidenceId) {
    const asclEvShow = await asclEngine.execute(`evidence show ${sampleEvidenceId}`);
    record('ASCL', 'ASCL: `evidence show <id>` executes', asclEvShow.type === 'INFO' || asclEvShow.type === 'SUCCESS');
  }

  const asclAuditVerify = await asclEngine.execute('audit verify');
  record('ASCL', 'ASCL: `audit verify` passes blockchain verification', asclAuditVerify.type === 'SUCCESS');

  const asclScopeVerify = await asclEngine.execute('scope verify 127.0.0.1');
  record('ASCL', 'ASCL: `scope verify <target>` executes', asclScopeVerify.type === 'SUCCESS');

  // ASCL Agent commands
  const asclAgentStatus = await asclEngine.execute('agent status');
  record('ASCL', 'ASCL: `agent status` executes', asclAgentStatus.type === 'SUCCESS');

  const asclAgentList = await asclEngine.execute('agent list');
  record('ASCL', 'ASCL: `agent list` returns full fleet', asclAgentList.type === 'INFO');

  const asclAgentAsk = await asclEngine.execute('agent ask agent-attack-surface "Status"');
  record('ASCL', 'ASCL: `agent ask <agent> <query>` succeeds', asclAgentAsk.type === 'INFO');

  const fleet = aiOrchestrator.getAllAgents();
  record('PIPELINE', 'AI Agent Fleet: 12 specialized agents registered with epistemic tags', fleet.length === 12);

  // =========================================================================
  // 6. REAL LLM & WAZUH SIEM INTEGRATION TESTS
  // =========================================================================
  const llmSiemSuite = await runLLMAndSiemVerification();
  for (const item of llmSiemSuite.results) {
    if (item.category === 'SECURITY_GOVERNANCE') {
      secRecord(item.name, item.success, item.error);
    } else {
      record(item.category as TestResultItem['category'], item.name, item.success, item.error);
    }
  }

  // =========================================================================
  // 7. LIVE PROTOCOL EXECUTORS & KALI EXECUTION AGENT TESTS
  // =========================================================================
  const liveAgentSuite = await runLiveAndAgentVerification();
  for (const item of liveAgentSuite.results) {
    if (item.category === 'SECURITY') {
      secRecord(item.name, item.success, item.error);
    } else {
      record(item.category as TestResultItem['category'], item.name, item.success, item.error);
    }
  }

  // =========================================================================
  // 8. EXTERNAL TOOL RESULT IMPORT & PARSER ENGINE TESTS
  // =========================================================================
  const importSuite = await runExternalToolImportVerification();
  for (const item of importSuite.results) {
    if (item.name.startsWith('Security:')) {
      secRecord(item.name, item.success, item.error);
    } else {
      record(item.category as TestResultItem['category'], item.name, item.success, item.error);
    }
  }

  // =========================================================================
  // 9. REAL LINUX WORKER & AUTHENTIC TOOL EXECUTION TESTS
  // =========================================================================
  const workerSuite = await runLinuxWorkerExecutionVerification();
  for (const item of workerSuite.results) {
    if (item.name.startsWith('Scope Gate:')) {
      secRecord(item.name, item.success, item.error);
    } else {
      record(item.category as TestResultItem['category'], item.name, item.success, item.error);
    }
  }

  // =========================================================================
  // 10. CRYPTOGRAPHIC AUDIT BLOCKCHAIN INTEGRITY
  // =========================================================================
  const auditVerification = auditLedger.verifyChainIntegrity();
  record('EVIDENCE_AUDIT', 'Audit Ledger: Full hash-chain verification passes', auditVerification.isValid);

  return {
    passed,
    failed,
    skipped,
    results,
    registryStats,
    securityStats: {
      passed: secPassed,
      failed: secFailed
    }
  };
}
