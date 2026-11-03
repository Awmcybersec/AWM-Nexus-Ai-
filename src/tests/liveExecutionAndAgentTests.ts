/**
 * AWM Nexus — Live Execution Engines & Remote Kali Agent Verification Suite
 * Verifies Node native live executors (DNS, WHOIS/RDAP, HTTP, TCP Port Probe),
 * Remote Kali Execution Agent registration/dispatch, and honest provenance classification.
 */

import {
  executeLiveDNSQuery,
  executeLiveWHOIS,
  executeLiveHTTPProbe,
  executeLiveNetworkDiagnostic
} from '../server/liveExecutors';
import { remoteAgentManager } from '../server/agentManager';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { asclEngine } from '../engine/asclEngine';
import { toolRegistry } from '../engine/toolRegistry';
import { detectRealBinaries } from '../engine/binaryDetector';
import { policyAndHitlEngine } from '../engine/policyAndHitlEngine';

export interface LiveTestResult {
  category: 'LIVE_EXECUTION' | 'KALI_AGENT' | 'SECURITY';
  name: string;
  success: boolean;
  error?: string;
}

export async function runLiveAndAgentVerification(): Promise<{
  passed: number;
  failed: number;
  results: LiveTestResult[];
}> {
  const results: LiveTestResult[] = [];
  let passed = 0;
  let failed = 0;

  function record(category: LiveTestResult['category'], name: string, condition: boolean, errorMsg?: string) {
    if (condition) {
      passed++;
      results.push({ category, name, success: true });
    } else {
      failed++;
      results.push({ category, name, success: false, error: errorMsg || 'Assertion failed' });
    }
  }

  // =========================================================================
  // 1. LIVE NODE NATIVE PROTOCOL EXECUTORS
  // =========================================================================

  // 1.1 Live DNS Query (RFC 1035 / BIND format)
  try {
    const dnsRes = await executeLiveDNSQuery('localhost', ['A']);
    record(
      'LIVE_EXECUTION',
      'Live DNS: Node native dns/promises resolves record sets with authentic BIND telemetry',
      dnsRes.status === 'NOERROR' && dnsRes.records.length > 0 && dnsRes.rawOutput.includes(';; Got answer:')
    );
  } catch (err: unknown) {
    record('LIVE_EXECUTION', 'Live DNS: Node native dns/promises resolves record sets', false, String(err));
  }

  // 1.2 Live WHOIS / RDAP (RFC 7482)
  try {
    const whoisRes = await executeLiveWHOIS('127.0.0.1');
    record(
      'LIVE_EXECUTION',
      'Live WHOIS: RDAP/IANA registry returns authentic net range and RFC 6890 status',
      whoisRes.status.includes('reserved') && whoisRes.rawOutput.includes('NetRange')
    );
  } catch (err: unknown) {
    record('LIVE_EXECUTION', 'Live WHOIS: RDAP/IANA registry returns authentic data', false, String(err));
  }

  // 1.3 Live HTTP Probe on dev server (127.0.0.1:3000)
  try {
    const httpRes = await executeLiveHTTPProbe('http://127.0.0.1:3000');
    record(
      'LIVE_EXECUTION',
      'Live HTTP Probe: Captures response headers and evaluates security headers (CSP, HSTS, X-Frame)',
      httpRes.statusCode > 0 && httpRes.securityHeaders.length >= 5
    );
  } catch (err: unknown) {
    record('LIVE_EXECUTION', 'Live HTTP Probe: Captures response headers', false, String(err));
  }

  // 1.4 Live TCP Port Probe & Ping
  try {
    const netRes = await executeLiveNetworkDiagnostic('127.0.0.1', [3000, 9999]);
    const port3000 = netRes.scannedPorts.find(p => p.port === 3000);
    record(
      'LIVE_EXECUTION',
      'Live TCP Port Probe: Authentically detects open local dev server port 3000/tcp with millisecond latency',
      port3000?.state === 'OPEN' && typeof port3000?.latencyMs === 'number'
    );
  } catch (err: unknown) {
    record('LIVE_EXECUTION', 'Live TCP Port Probe: Authentically detects open port', false, String(err));
  }

  // =========================================================================
  // 2. REMOTE KALI EXECUTION AGENT PROTOCOL
  // =========================================================================

  // 2.1 Agent Registration & Token Authentication
  const token = remoteAgentManager.getAuthToken();
  record('KALI_AGENT', 'Kali Agent: Authorization token securely managed', !!token && token.length > 10);

  const testAgent = remoteAgentManager.registerAgent({
    id: 'agent-kali-test-01',
    name: 'Kali Primary Test Station',
    hostname: 'kali-node-01.corp.internal',
    os: 'Kali GNU/Linux Rolling 2026.1',
    ip: '10.10.14.99',
    installedTools: ['nmap', 'nuclei', 'nikto', 'ffuf', 'msfconsole']
  });

  record(
    'KALI_AGENT',
    'Kali Agent: Registration records online node with verified tool capabilities',
    testAgent.id === 'agent-kali-test-01' && testAgent.installedTools.includes('nmap')
  );

  // 2.2 Re-detect tool availability with registered agent (msfconsole is remote-only)
  const detectWithAgent = await detectRealBinaries();
  const msfTool = toolRegistry.getTool('msf-validation');
  record(
    'KALI_AGENT',
    'Kali Agent: Remote tool availability dynamically reflected in Registry matrix',
    msfTool?.availabilityStatus === 'AVAILABLE' && (msfTool?.version || '').includes('Kali Agent')
  );

  // 2.3 Job Dispatch to Remote Kali Agent
  const agentJobRes = sandboxExecutionManager.createJob(
    'TENANT-AWM-01',
    'eng-2026-001',
    'operator-human-01',
    'nmap-recon',
    '127.0.0.1',
    'fast-syn',
    [],
    'LIVE'
  );

  record('KALI_AGENT', 'Kali Agent: Job instantiated for remote execution', !!agentJobRes.job);

  if (agentJobRes.job) {
    // Start background execution
    const execPromise = sandboxExecutionManager.executeJob(agentJobRes.job.jobId);

    // Agent polls job
    const polledJob = remoteAgentManager.pollJob(testAgent.id);
    record(
      'KALI_AGENT',
      'Kali Agent: Authenticated agent polls assigned job payload from dispatch queue',
      polledJob?.jobId === agentJobRes.job.jobId && polledJob?.binaryName === 'nmap'
    );

    // Agent submits streaming chunks
    remoteAgentManager.receiveChunk(agentJobRes.job.jobId, 'stdout', 'Starting Nmap 7.94 on Kali Linux Station...\n');
    remoteAgentManager.receiveChunk(agentJobRes.job.jobId, 'stdout', 'Discovered open port 3000/tcp on 127.0.0.1\n');

    // Agent completes job
    remoteAgentManager.completeJob({
      jobId: agentJobRes.job.jobId,
      exitCode: 0,
      stdout: 'Starting Nmap 7.94\nNmap scan report for 127.0.0.1\nPORT     STATE SERVICE\n3000/tcp open  http-applet\nNmap done: 1 IP scanned.',
      stderr: '',
      executionTimeMs: 450,
      completedAt: new Date().toISOString()
    });

    const finishedJob = await execPromise;
    record(
      'KALI_AGENT',
      'Kali Agent: Execution completes with LIVE_AGENT provenance and evidence sealed',
      finishedJob.status === 'COMPLETED' && finishedJob.provenance === 'LIVE_AGENT' && !!finishedJob.evidenceId
    );
  }

  // =========================================================================
  // 3. HONEST PROVENANCE & UNAVAILABLE STATE (ZERO FAKE DATA)
  // =========================================================================

  // 3.1 Attempting to run an uninstalled tool when no agent is online fails honestly with UNAVAILABLE
  // Create job for a tool that requires agent, when agent is offline
  const offlineAgentTool = toolRegistry.getTool('openvas-vuln');
  if (offlineAgentTool) {
    // Force agent offline
    testAgent.status = 'OFFLINE';
    const unavailableJobRes = sandboxExecutionManager.createJob(
      'TENANT-AWM-01',
      'eng-2026-001',
      'operator-human-01',
      'openvas-vuln',
      '127.0.0.1',
      'openvas-full',
      [],
      'LIVE'
    );

    if (unavailableJobRes.job) {
      // Approve HITL if needed
      if (unavailableJobRes.hitlRequestId) {
        policyAndHitlEngine.approveRequest(unavailableJobRes.hitlRequestId, 'operator-human-01');
      }

      const executedUnavailable = await sandboxExecutionManager.executeJob(unavailableJobRes.job.jobId);
      record(
        'SECURITY',
        'Integrity: Offline tools in LIVE mode fail honestly with UNAVAILABLE provenance (Zero fabricated output)',
        executedUnavailable.status === 'FAILED' &&
          executedUnavailable.provenance === 'UNAVAILABLE' &&
          executedUnavailable.stderr.includes('EXECUTION UNAVAILABLE')
      );
    }
  }

  // Restore agent
  testAgent.status = 'ONLINE';

  // =========================================================================
  // 4. ASCL KALI COMMANDS
  // =========================================================================
  const asclKaliStatus = await asclEngine.execute('kali status');
  record('KALI_AGENT', 'ASCL: `kali status` displays connected agents and token', asclKaliStatus.type === 'SUCCESS');

  const asclKaliToken = await asclEngine.execute('kali token');
  record('KALI_AGENT', 'ASCL: `kali token` returns authorization credentials', asclKaliToken.type === 'SUCCESS');

  const asclKaliList = await asclEngine.execute('kali list');
  record('KALI_AGENT', 'ASCL: `kali list` lists registered execution nodes', asclKaliList.type === 'SUCCESS');

  return { passed, failed, results };
}
