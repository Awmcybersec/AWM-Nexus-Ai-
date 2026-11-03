/**
 * AWM Nexus — Server API Handlers
 * Express request/response router implementation serving all AWM Nexus core engines
 */

import { toolRegistry } from '../engine/toolRegistry';
import { scopeEngine } from '../engine/scopeEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { policyAndHitlEngine } from '../engine/policyAndHitlEngine';
import { evidenceEngine, riskEngine } from '../engine/riskAndEvidenceEngine';
import { auditLedger } from '../engine/auditLedger';
import {
  attackSurfaceEngine,
  exposureEngine,
  attackPathEngine,
  defensiveTelemetryEngine,
  pentestReportEngine
} from '../engine/offensiveDefensiveEngines';
import { asclEngine } from '../engine/asclEngine';
import { detectRealBinaries } from '../engine/binaryDetector';
import { externalToolImportEngine } from '../engine/externalToolImportEngine';
import { ExternalToolFormat } from '../types';
import { llmManager } from '../services/llm/llmManager';
import { siemManager } from '../services/siem/siemManager';
import { LLMIncidentAnalysisParams, LLMAlertSummarizationParams, LLMReportParams } from '../services/llm/types';
import { SIEMConfig } from '../services/siem/types';
import { remoteAgentManager, AgentResultPayload } from './agentManager';
import { linuxWorkerManager } from './linuxWorkerManager';
import {
  executeLiveDNSQuery,
  executeLiveWHOIS,
  executeLiveTLSInspection,
  executeLiveHTTPProbe,
  executeLiveNetworkDiagnostic
} from './liveExecutors';

// Trigger initial binary detection on server boot
detectRealBinaries().catch(() => {});

export async function handleApiRequest(
  url: string,
  method: string,
  body: Record<string, unknown> = {}
): Promise<{ status: number; data: unknown }> {
  const cleanUrl = url.split('?')[0];

  try {
    // 1. System Status
    if (cleanUrl === '/api/status' && method === 'GET') {
      const eng = scopeEngine.getAllEngagements()[0];
      const audit = auditLedger.verifyChainIntegrity();
      const tools = toolRegistry.getAllTools();
      return {
        status: 200,
        data: {
          status: 'ONLINE',
          operator: 'operator-human-01 (Lead Security Engineer)',
          tenant: 'TENANT-AWM-01 (AWM Defense Corp)',
          engagement: eng,
          auditChainValid: audit.isValid,
          auditBlockCount: audit.blocksCount,
          toolsCount: tools.length,
          toolsInstalled: tools.filter(t => t.availabilityStatus === 'INSTALLED').length,
          pendingHITL: policyAndHitlEngine.getPendingRequests().length
        }
      };
    }

    // 2. Tools
    if (cleanUrl === '/api/tools' && method === 'GET') {
      return { status: 200, data: toolRegistry.getAllTools() };
    }

    if (cleanUrl === '/api/tools/detect' && method === 'POST') {
      const res = await detectRealBinaries();
      return { status: 200, data: res };
    }

    if (cleanUrl.startsWith('/api/tools/') && method === 'GET') {
      const id = cleanUrl.replace('/api/tools/', '');
      const tool = toolRegistry.getTool(id);
      if (!tool) return { status: 404, data: { error: `Tool ${id} not found` } };
      return { status: 200, data: tool };
    }

    // 3. Targets & Scope
    if (cleanUrl === '/api/targets' && method === 'GET') {
      const eng = scopeEngine.getAllEngagements()[0];
      return { status: 200, data: { targets: eng.targets, scopeRules: eng.scopeRules } };
    }

    if (cleanUrl === '/api/scope/verify' && method === 'POST') {
      const { target, engagementId = 'eng-2026-001' } = body as { target: string; engagementId?: string };
      const eng = scopeEngine.getEngagement(engagementId) || scopeEngine.getAllEngagements()[0];
      const res = scopeEngine.validateTargetScope(eng, target);
      return { status: 200, data: res };
    }

    // 4. Jobs & Execution
    if (cleanUrl === '/api/jobs' && method === 'GET') {
      return { status: 200, data: sandboxExecutionManager.getAllJobs() };
    }

    if (cleanUrl === '/api/jobs' && method === 'POST') {
      const {
        tenantId = 'TENANT-AWM-01',
        engagementId = 'eng-2026-001',
        operatorId = 'operator-human-01',
        toolId,
        target,
        profileId,
        params = [],
        resolvedParameters,
        mode = 'LIVE',
        jobId: clientJobId
      } = body as {
        tenantId?: string;
        engagementId?: string;
        operatorId?: string;
        toolId: string;
        target: string;
        profileId: string;
        params?: string[];
        resolvedParameters?: string[];
        mode?: 'LIVE' | 'SIMULATED' | 'DRY_RUN';
        jobId?: string;
      };

      const res = sandboxExecutionManager.createJob(
        tenantId,
        engagementId,
        operatorId,
        toolId,
        target,
        profileId,
        params,
        mode,
        clientJobId,
        resolvedParameters
      );

      if (res.error) {
        return { status: 400, data: { error: res.error } };
      }

      return { status: 201, data: res };
    }

    if (cleanUrl.endsWith('/execute') && method === 'POST') {
      const jobId = cleanUrl.replace('/api/jobs/', '').replace('/execute', '');
      const job = await sandboxExecutionManager.executeJob(jobId);
      return { status: 200, data: job };
    }

    if (cleanUrl.endsWith('/cancel') && method === 'POST') {
      const jobId = cleanUrl.replace('/api/jobs/', '').replace('/cancel', '');
      const { operatorId = 'operator-human-01' } = body as { operatorId?: string };
      linuxWorkerManager.cancelProcess(jobId);
      const res = sandboxExecutionManager.cancelJob(jobId, operatorId);
      return { status: res.success ? 200 : 400, data: res };
    }

    if (cleanUrl.startsWith('/api/jobs/') && cleanUrl.endsWith('/output') && method === 'GET') {
      const jobId = cleanUrl.replace('/api/jobs/', '').replace('/output', '');
      const job = sandboxExecutionManager.getJob(jobId);
      if (!job) return { status: 404, data: { error: `Job ${jobId} not found` } };

      const runningProc = linuxWorkerManager.getRunningProcess(jobId);
      return {
        status: 200,
        data: {
          jobId: job.jobId,
          status: job.status,
          pid: runningProc?.pid,
          stdout: job.stdout,
          stderr: job.stderr,
          exitCode: job.exitCode,
          executionTimeMs: job.executionTimeMs,
          findingsCount: job.findings.length
        }
      };
    }

    if (cleanUrl === '/api/worker/health' && method === 'GET') {
      return { status: 200, data: linuxWorkerManager.getWorkerHealth() };
    }

    // 5. HITL Gate
    if (cleanUrl === '/api/hitl' && method === 'GET') {
      return { status: 200, data: policyAndHitlEngine.getAllRequests() };
    }

    if (cleanUrl.endsWith('/approve') && method === 'POST') {
      const reqId = cleanUrl.replace('/api/hitl/', '').replace('/approve', '');
      const { approverId = 'lead-operator-01' } = body as { approverId?: string };
      const res = policyAndHitlEngine.approveRequest(reqId, approverId);
      return { status: res.success ? 200 : 400, data: res };
    }

    if (cleanUrl.endsWith('/reject') && method === 'POST') {
      const reqId = cleanUrl.replace('/api/hitl/', '').replace('/reject', '');
      const { approverId = 'lead-operator-01', reason = 'Rejected by security lead' } = body as {
        approverId?: string;
        reason?: string;
      };
      const res = policyAndHitlEngine.rejectRequest(reqId, approverId, reason);
      return { status: res.success ? 200 : 400, data: res };
    }

    // 6. Evidence Locker
    if (cleanUrl === '/api/evidence' && method === 'GET') {
      return { status: 200, data: evidenceEngine.getAllEvidence() };
    }

    if (cleanUrl.startsWith('/api/evidence/') && method === 'GET') {
      const id = cleanUrl.replace('/api/evidence/', '');
      const ev = evidenceEngine.getEvidence(id);
      if (!ev) return { status: 404, data: { error: `Evidence ${id} not found` } };
      const integrity = evidenceEngine.verifyEvidenceIntegrity(id);
      return { status: 200, data: { ...ev, integrity } };
    }

    // 7. Audit Core
    if (cleanUrl === '/api/audit' && method === 'GET') {
      return { status: 200, data: auditLedger.getBlocks() };
    }

    if (cleanUrl === '/api/audit/verify' && method === 'GET') {
      return { status: 200, data: auditLedger.verifyChainIntegrity() };
    }

    // 8. Attack Surface & Paths
    if (cleanUrl === '/api/surface' && method === 'GET') {
      return { status: 200, data: attackSurfaceEngine.getAllAssets() };
    }

    if (cleanUrl === '/api/attack-paths' && method === 'GET') {
      return { status: 200, data: attackPathEngine.getAllPaths() };
    }

    // 9. Defensive Telemetry
    if (cleanUrl === '/api/defensive/telemetry' && method === 'GET') {
      return { status: 200, data: defensiveTelemetryEngine.getAllEvents() };
    }

    // 10. ASCL Terminal Command
    if (cleanUrl === '/api/ascl' && method === 'POST') {
      const { command } = body as { command: string };
      const result = await asclEngine.execute(command || '');
      return { status: 200, data: result };
    }

    // 11. Reports
    if (cleanUrl === '/api/report' && method === 'POST') {
      const { engagementId = 'eng-2026-001', type = 'TECHNICAL' } = body as {
        engagementId?: string;
        type?: 'TECHNICAL' | 'EXECUTIVE';
      };
      const jobs = sandboxExecutionManager.getAllJobs();
      const findings = jobs.flatMap(j => j.findings);
      const report = pentestReportEngine.generateReport(engagementId, type, findings);
      return { status: 200, data: report };
    }

    // 11b. External Tool Result Import & Parsers
    if (cleanUrl === '/api/imports' && method === 'GET') {
      return { status: 200, data: externalToolImportEngine.getAllImports() };
    }

    if (cleanUrl === '/api/imports/upload' && method === 'POST') {
      const {
        filename,
        content,
        engagementId = 'eng-2026-001',
        tenantId = 'TENANT-AWM-01',
        operatorId = 'operator-human-01',
        format
      } = body as {
        filename: string;
        content: string;
        engagementId?: string;
        tenantId?: string;
        operatorId?: string;
        format?: ExternalToolFormat;
      };

      if (!filename || typeof content !== 'string') {
        return { status: 400, data: { error: 'Both filename and content are required for external tool upload.' } };
      }

      const result = await externalToolImportEngine.importResults(
        filename,
        content,
        engagementId,
        tenantId,
        operatorId,
        format
      );

      const statusCode = result.status === 'REJECTED' ? 400 : result.status === 'PARTIAL' ? 207 : 201;
      return { status: statusCode, data: result };
    }

    if (cleanUrl.startsWith('/api/imports/') && method === 'GET') {
      const id = cleanUrl.replace('/api/imports/', '');
      const imp = externalToolImportEngine.getImport(id);
      if (!imp) return { status: 404, data: { error: `Import record ${id} not found.` } };
      return { status: 200, data: imp };
    }

    if (cleanUrl === '/api/findings/imported' && method === 'GET') {
      return { status: 200, data: externalToolImportEngine.getAllImportedFindings() };
    }

    if (cleanUrl.startsWith('/api/findings/') && cleanUrl.endsWith('/review') && method === 'POST') {
      const findingId = cleanUrl.replace('/api/findings/', '').replace('/review', '');
      const { status: newStatus, operatorId = 'operator-human-01', notes } = body as {
        status: 'CONFIRMED' | 'FALSE_POSITIVE' | 'REMEDIATED' | 'UNVALIDATED';
        operatorId?: string;
        notes?: string;
      };

      const updated = externalToolImportEngine.updateFindingValidation(findingId, newStatus, operatorId, notes);
      if (!updated) return { status: 404, data: { error: `Finding ${findingId} not found.` } };
      return { status: 200, data: { success: true, findingId, status: newStatus } };
    }

    // 12. Real LLM Provider Integration Endpoints
    if (cleanUrl === '/api/llm/status' && method === 'GET') {
      const config = llmManager.getConfig();
      const lastTest = llmManager.getLastTestResult();
      return {
        status: 200,
        data: {
          config,
          lastTest,
          activeProvider: config.provider,
          model: config.model,
          isConfigured: config.apiKeyConfigured
        }
      };
    }

    if (cleanUrl === '/api/llm/config' && method === 'POST') {
      const { apiKey, provider } = body as { apiKey?: string; provider?: string };
      if (apiKey !== undefined) {
        llmManager.setSessionApiKey(apiKey || null);
      }
      if (provider) {
        llmManager.setActiveProvider(provider);
      }
      return { status: 200, data: { success: true, config: llmManager.getConfig() } };
    }

    if (cleanUrl === '/api/llm/test' && method === 'POST') {
      const { apiKey } = body as { apiKey?: string };
      const testResult = await llmManager.testConnection(apiKey);
      return { status: 200, data: testResult };
    }

    if (cleanUrl === '/api/llm/analyze' && method === 'POST') {
      const params = body as unknown as LLMIncidentAnalysisParams;
      const result = await llmManager.analyzeIncident(params);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/llm/explain-mitre' && method === 'POST') {
      const { techniqueId, context } = body as { techniqueId: string; context?: string };
      if (!techniqueId) {
        return { status: 400, data: { error: 'techniqueId is required' } };
      }
      const result = await llmManager.explainMitreTechnique(techniqueId, context);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/llm/summarize-alerts' && method === 'POST') {
      const params = body as unknown as LLMAlertSummarizationParams;
      const result = await llmManager.summarizeAlerts(params);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/llm/executive-narrative' && method === 'POST') {
      const params = body as unknown as LLMReportParams;
      const result = await llmManager.generateExecutiveNarrative(params);
      return { status: 200, data: result };
    }

    // 13. Real SIEM (Wazuh) Integration Endpoints
    if (cleanUrl === '/api/siem/status' && method === 'GET') {
      const config = siemManager.getConfig();
      const status = siemManager.getLastStatus();
      const stats = siemManager.getStats();
      return {
        status: 200,
        data: {
          config,
          connectionStatus: status,
          stats
        }
      };
    }

    if (cleanUrl === '/api/siem/config' && method === 'POST') {
      const newConfig = body as Partial<SIEMConfig>;
      siemManager.updateConfig(newConfig);
      return { status: 200, data: { success: true, config: siemManager.getConfig() } };
    }

    if (cleanUrl === '/api/siem/test' && method === 'POST') {
      const override = body as Partial<SIEMConfig>;
      const status = await siemManager.testConnection(override);
      return { status: 200, data: status };
    }

    if (cleanUrl === '/api/siem/sync' && method === 'POST') {
      const { minLevel, limit } = body as { minLevel?: number; limit?: number };
      const syncRes = await siemManager.syncAlerts({ minLevel, limit });
      return { status: syncRes.success ? 200 : 502, data: syncRes };
    }

    if (cleanUrl === '/api/siem/demo-ingest' && method === 'POST') {
      const result = siemManager.ingestVerifiedSampleAlerts();
      return { status: 200, data: { success: true, count: result.count, alerts: result.alerts } };
    }

    // 14. Remote Kali Linux Execution Agent Endpoints
    if (cleanUrl === '/api/agent/status' && method === 'GET') {
      const agents = remoteAgentManager.getAllAgents();
      const token = remoteAgentManager.getAuthToken();
      return {
        status: 200,
        data: {
          token,
          totalAgents: agents.length,
          onlineAgentsCount: agents.filter(a => a.status === 'ONLINE' || a.status === 'BUSY').length,
          agents
        }
      };
    }

    if (cleanUrl === '/api/agent/token/regenerate' && method === 'POST') {
      const newToken = remoteAgentManager.regenerateAuthToken();
      return { status: 200, data: { success: true, token: newToken } };
    }

    if (cleanUrl === '/api/agent/register' && method === 'POST') {
      const agentData = body as {
        id?: string;
        name: string;
        hostname: string;
        os?: string;
        ip?: string;
        installedTools?: string[];
      };
      const agent = remoteAgentManager.registerAgent(agentData);
      // Trigger a re-probe so tool availability updates immediately
      detectRealBinaries().catch(() => {});
      return { status: 200, data: agent };
    }

    if (cleanUrl === '/api/agent/heartbeat' && method === 'POST') {
      const { agentId } = body as { agentId: string };
      const success = remoteAgentManager.heartbeat(agentId);
      return { status: success ? 200 : 404, data: { success } };
    }

    if (cleanUrl === '/api/agent/poll-jobs' && method === 'GET') {
      const agentId = (url.split('agentId=')[1]?.split('&')[0]) || 'kali-agent';
      const job = remoteAgentManager.pollJob(agentId);
      return { status: 200, data: job };
    }

    if (cleanUrl === '/api/agent/submit-chunk' && method === 'POST') {
      const { jobId, type, chunk } = body as { jobId: string; type: 'stdout' | 'stderr'; chunk: string };
      if (jobId && chunk) {
        remoteAgentManager.receiveChunk(jobId, type, chunk);
      }
      return { status: 200, data: { received: true } };
    }

    if (cleanUrl === '/api/agent/submit-result' && method === 'POST') {
      const result = body as unknown as AgentResultPayload;
      const success = remoteAgentManager.completeJob(result);
      return { status: success ? 200 : 400, data: { success } };
    }

    if (cleanUrl === '/api/agent/demo-connect' && method === 'POST') {
      const agent = remoteAgentManager.registerDemoKaliAgent();
      detectRealBinaries().catch(() => {});
      return { status: 200, data: { success: true, agent } };
    }

    // 15. Live Protocol Execution Endpoints
    if (cleanUrl === '/api/live/dns' && method === 'POST') {
      const { target = '127.0.0.1', recordTypes } = body as { target?: string; recordTypes?: string[] };
      const result = await executeLiveDNSQuery(target, recordTypes);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/live/whois' && method === 'POST') {
      const { target = '127.0.0.1' } = body as { target?: string };
      const result = await executeLiveWHOIS(target);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/live/tls' && method === 'POST') {
      const { target = '127.0.0.1', port = 443 } = body as { target?: string; port?: number };
      const result = await executeLiveTLSInspection(target, port);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/live/http' && method === 'POST') {
      const { target = 'http://127.0.0.1:3000', method: httpMethod = 'GET', headers = {} } = body as {
        target?: string;
        method?: string;
        headers?: Record<string, string>;
      };
      const result = await executeLiveHTTPProbe(target, httpMethod, headers);
      return { status: 200, data: result };
    }

    if (cleanUrl === '/api/live/network' && method === 'POST') {
      const { target = '127.0.0.1', ports } = body as { target?: string; ports?: number[] };
      const result = await executeLiveNetworkDiagnostic(target, ports);
      return { status: 200, data: result };
    }

    return { status: 404, data: { error: `Endpoint ${method} ${cleanUrl} not found` } };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: 500, data: { error: `Internal API error: ${msg}` } };
  }
}
