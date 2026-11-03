/**
 * AWM Nexus — Tool Execution Engine & Sandbox
 * Safe subprocess execution manager with strict parameter isolation, timeout enforcement,
 * process cancellation, live Node protocol engines (DNS, RDAP/WHOIS, TLS, TCP Port Probe),
 * and Remote Kali Linux Execution Agent coordination.
 */

import { PentestJob, SecurityTool, ToolProfile, JobStatus, ToolExecutionMode, ArtifactFile } from '../types';
import { toolRegistry } from './toolRegistry';
import { scopeEngine } from './scopeEngine';
import { policyAndHitlEngine } from './policyAndHitlEngine';
import { findingParser } from './findingParser';
import { evidenceEngine } from './riskAndEvidenceEngine';
import { auditLedger } from './auditLedger';
import { syncSha256 } from './cryptoUtils';
import { remoteAgentManager } from '../server/agentManager';

async function getLiveExecutors() {
  return await import('../server/liveExecutors');
}

async function getLinuxWorkerManager() {
  if (typeof window !== 'undefined') return null;
  try {
    const workerModule = '../server/linuxWorkerManager';
    const mod = await import(/* @vite-ignore */ workerModule);
    return mod.linuxWorkerManager;
  } catch {
    return null;
  }
}

export class SandboxExecutionManager {
  private jobs: Map<string, PentestJob> = new Map();
  private activeProcesses: Map<string, AbortController> = new Map();

  public createJob(
    tenantId: string,
    engagementId: string,
    operatorId: string,
    toolId: string,
    target: string,
    profileId: string,
    customParams: string[] = [],
    preferredMode: ToolExecutionMode = 'LIVE',
    overrideJobId?: string,
    prebuiltArgs?: string[]
  ): { job?: PentestJob; error?: string; requiresHITL?: boolean; hitlRequestId?: string } {
    const tool = toolRegistry.getTool(toolId);
    if (!tool) return { error: `Tool ${toolId} not found.` };

    const profile = tool.profiles.find(p => p.id === profileId) || tool.profiles[0];
    if (!profile) return { error: `Profile not found for tool ${toolId}.` };

    const engagement = scopeEngine.getEngagement(engagementId);
    if (!engagement) return { error: `Engagement ${engagementId} not found.` };

    const targetAsset = engagement.targets.find(t => t.address === target);

    // 1. Argument Validation
    const argResult = toolRegistry.buildInvocationArguments(tool, profile, target, customParams);
    if (!argResult.isSafe) {
      return { error: `COMMAND SECURITY ERROR: ${argResult.rejectionReason}` };
    }

    // 2. Scope Validation
    const scopeCheck = scopeEngine.validateExecution(
      engagementId,
      tenantId,
      operatorId,
      'LEAD_SECURITY_ENGINEER', // Default operator role in workspace
      target,
      profile.capabilityTier
    );

    if (!scopeCheck.valid) {
      return { error: `SCOPE POLICY REJECTION: ${scopeCheck.reason}` };
    }

    // 3. Policy & HITL Evaluation
    const policyResult = policyAndHitlEngine.evaluatePolicy(tool, profile, targetAsset, target, customParams);

    const jobId = overrideJobId || `JOB-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

    const finalParameters = (prebuiltArgs && prebuiltArgs.length > 0)
      ? [...prebuiltArgs]
      : [...argResult.safeArgs];

    const job: PentestJob = {
      jobId,
      tenantId,
      engagementId,
      operatorId,
      toolId: tool.id,
      toolName: tool.name,
      target,
      profile: profile.name,
      parameters: finalParameters,
      customParams: [...customParams],
      status: policyResult.requiresHITL ? 'APPROVAL_REQUIRED' : 'QUEUED',
      mode: preferredMode,
      startTime: new Date().toISOString(),
      stdout: '',
      stderr: '',
      artifacts: [],
      findings: []
    };

    this.jobs.set(jobId, job);

    // Audit log job creation
    auditLedger.appendBlock(
      operatorId,
      'JOB_CREATED',
      tenantId,
      engagementId,
      target,
      {
        jobId,
        toolId: tool.id,
        toolName: tool.name,
        profile: profile.name,
        parameters: argResult.safeArgs,
        mode: preferredMode,
        requiresHITL: policyResult.requiresHITL
      }
    );

    if (policyResult.requiresHITL) {
      const hitlReq = policyAndHitlEngine.createRequest(
        jobId,
        tool,
        profile,
        target,
        argResult.safeArgs,
        operatorId,
        policyResult.riskLevel,
        policyResult.hitlReason || 'High impact execution requiring confirmation'
      );
      job.hitlRequestId = hitlReq.requestId;
      return { job, requiresHITL: true, hitlRequestId: hitlReq.requestId };
    }

    return { job, requiresHITL: false };
  }

  public getJob(jobId: string): PentestJob | undefined {
    return this.jobs.get(jobId);
  }

  public getAllJobs(): PentestJob[] {
    return Array.from(this.jobs.values()).sort((a, b) => new Date(b.startTime).getTime() - new Date(a.startTime).getTime());
  }

  public cancelJob(jobId: string, operatorId: string): { success: boolean; error?: string } {
    const job = this.jobs.get(jobId);
    if (!job) return { success: false, error: `Job ${jobId} not found.` };

    if (job.status === 'COMPLETED' || job.status === 'FAILED' || job.status === 'CANCELLED') {
      return { success: false, error: `Job ${jobId} is already terminated with state ${job.status}.` };
    }

    job.cancelRequested = true;
    job.status = 'CANCELLED';
    job.endTime = new Date().toISOString();
    job.stderr += `\n[!] Job execution cancelled by operator ${operatorId} at ${job.endTime}`;

    const controller = this.activeProcesses.get(jobId);
    if (controller) {
      controller.abort();
      this.activeProcesses.delete(jobId);
    }

    auditLedger.appendBlock(
      operatorId,
      'JOB_CANCELLED',
      job.tenantId,
      job.engagementId,
      job.target,
      { jobId, reason: 'Operator requested cancellation' }
    );

    return { success: true };
  }

  /**
   * Executes the job through real binary subprocess, live Node protocol engines,
   * remote Kali agent, or deterministic sandbox simulator
   */
  public async executeJob(
    jobId: string,
    onChunk?: (type: 'stdout' | 'stderr', chunk: string) => void
  ): Promise<PentestJob> {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error(`Job ${jobId} not found.`);

    if (job.status === 'APPROVAL_REQUIRED') {
      if (job.hitlRequestId) {
        const hitl = policyAndHitlEngine.getRequest(job.hitlRequestId);
        if (!hitl || hitl.status !== 'APPROVED') {
          job.status = 'BLOCKED';
          job.stderr = '[!] Execution blocked: HITL Operator Approval is pending or rejected.';
          return job;
        }
      }
    }

    const tool = toolRegistry.getTool(job.toolId);
    if (!tool) {
      job.status = 'FAILED';
      job.stderr = `Tool ${job.toolId} definition missing.`;
      return job;
    }

    job.status = 'RUNNING';
    const startTimeMs = Date.now();
    const abortController = new AbortController();
    this.activeProcesses.set(jobId, abortController);

    const logChunk = (type: 'stdout' | 'stderr', data: string) => {
      if (type === 'stdout') job.stdout += data;
      else job.stderr += data;
      if (onChunk) onChunk(type, data);
    };

    logChunk('stdout', `[*] AWM Nexus Security Sandbox Execution Engine v4.8.2\n`);
    logChunk('stdout', `[*] Target: ${job.target} | Tool: ${tool.name} (${tool.binaryName})\n`);
    logChunk('stdout', `[*] Capability Tier: [${tool.capabilityTier}]\n`);
    logChunk('stdout', `[*] Invocation Flags: ${job.parameters.join(' ')}\n`);
    logChunk('stdout', `------------------------------------------------------------\n\n`);

    // In browser client environments, dispatch execution via backend API proxy
    if (typeof window !== 'undefined' && typeof window.fetch === 'function') {
      try {
        await fetch('/api/jobs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tenantId: job.tenantId,
            engagementId: job.engagementId,
            operatorId: job.operatorId,
            toolId: job.toolId,
            target: job.target,
            profileId: tool.profiles.find(p => p.name === job.profile)?.id || tool.profiles[0]?.id,
            params: job.customParams || [],
            resolvedParameters: job.parameters,
            mode: job.mode,
            jobId: job.jobId
          })
        }).catch(() => {});

        const resp = await fetch(`/api/jobs/${jobId}/execute`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        if (resp.ok) {
          const serverJob = (await resp.json()) as PentestJob;
          Object.assign(job, serverJob);
          this.jobs.set(job.jobId, job);
          if (onChunk) {
            if (serverJob.stdout) onChunk('stdout', serverJob.stdout);
            if (serverJob.stderr) onChunk('stderr', serverJob.stderr);
          }
          this.activeProcesses.delete(jobId);
          return job;
        }
      } catch (clientErr) {
        console.warn('[!] Browser API dispatch failed, attempting local fallback:', clientErr);
      }
    }

    try {
      // 0. Dry-run verification mode
      if (job.mode === 'DRY_RUN') {
        job.provenance = 'SIMULATED';
        logChunk('stdout', `[i] NOTICE: Dry-Run Sandbox Verification Mode (No network mutation)\n\n`);
        await this.runSandboxSimulation(job, tool, abortController, logChunk);
        job.exitCode = 0;
      } else if (tool.id === 'dig-dns' || tool.id === 'dnsrecon-recon') {
        job.provenance = 'LIVE_LOCAL';
        logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Node.js Native DNS Engine RFC 1035/2181)\n\n`);
        const { executeLiveDNSQuery } = await getLiveExecutors();
        const dnsResult = await executeLiveDNSQuery(job.target);
        logChunk('stdout', dnsResult.rawOutput);
        job.exitCode = 0;
      } else if (tool.binaryName === 'whois') {
        const localWhois = await this.checkLocalBinary('whois');
        if (localWhois) {
          job.provenance = 'LIVE_LOCAL';
          logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Native WHOIS Binary: ${localWhois})\n\n`);
          try {
            await this.runRealBinary(job, tool, abortController, logChunk);
          } catch (whoisErr) {
            logChunk('stderr', `\n[!] Native whois binary error: ${whoisErr instanceof Error ? whoisErr.message : String(whoisErr)}\n`);
            const { executeLiveWHOIS } = await getLiveExecutors();
            const whoisResult = await executeLiveWHOIS(job.target);
            logChunk('stdout', whoisResult.rawOutput);
            job.exitCode = 0;
          }
        } else {
          job.provenance = 'LIVE_LOCAL';
          logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (ICANN RDAP / WHOIS Socket RFC 7482)\n\n`);
          const { executeLiveWHOIS } = await getLiveExecutors();
          const whoisResult = await executeLiveWHOIS(job.target);
          logChunk('stdout', whoisResult.rawOutput);
          job.exitCode = 0;
        }
      } else if (tool.binaryName === 'curl') {
        job.provenance = 'LIVE_LOCAL';
        logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Native cURL Binary + HTTP Inspector)\n\n`);
        try {
          await this.runRealBinary(job, tool, abortController, logChunk);
        } catch {
          const { executeLiveHTTPProbe } = await getLiveExecutors();
          const httpResult = await executeLiveHTTPProbe(job.target);
          logChunk('stdout', httpResult.rawOutput);
          job.exitCode = httpResult.statusCode > 0 ? 0 : 1;
        }
      } else if (tool.binaryName === 'openssl') {
        job.provenance = 'LIVE_LOCAL';
        logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Native OpenSSL + Node.js TLS)\n\n`);
        try {
          await this.runRealBinary(job, tool, abortController, logChunk);
        } catch {
          const { executeLiveTLSInspection } = await getLiveExecutors();
          const tlsResult = await executeLiveTLSInspection(job.target);
          logChunk('stdout', tlsResult.rawOutput);
          job.exitCode = 0;
        }
      } else if (tool.id === 'nmap-recon') {
        const agentManager = remoteAgentManager;
        const agent = agentManager.getAgentForTool(tool.binaryName);

        if (agent) {
          job.provenance = 'LIVE_AGENT';
          job.agentId = agent.id;
          job.agentName = agent.name;
          logChunk('stdout', `[+] PROVENANCE: LIVE REMOTE AGENT [${agent.name} - ${agent.hostname}]\n\n`);
          const agentRes = await agentManager.dispatchJobToAgent(job, tool, logChunk);
          job.exitCode = agentRes.exitCode;
        } else {
          const localBinary = await this.checkLocalBinary('nmap');
          if (localBinary) {
            job.provenance = 'LIVE_LOCAL';
            logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Native Nmap Binary - ${localBinary})\n\n`);
            // Ensure --unprivileged is present in container environments to avoid gVisor AF_NETLINK issues
            if (!job.parameters.includes('--unprivileged')) {
              job.parameters.unshift('--unprivileged');
            }
            if (!job.parameters.some(p => p === '-sT' || p === '-sS' || p === '-sP' || p === '-sn')) {
              if (job.parameters.length > 0) {
                job.parameters.splice(job.parameters.length - 1, 0, '-sT');
              } else {
                job.parameters.push('-sT');
              }
            }
            try {
              await this.runRealBinary(job, tool, abortController, logChunk);
            } catch {
              const { executeLiveNetworkDiagnostic } = await getLiveExecutors();
              const netResult = await executeLiveNetworkDiagnostic(job.target);
              logChunk('stdout', netResult.rawOutput);
              job.exitCode = 0;
            }
          } else {
            // Fall back to authentic live Node TCP port scanner & ping against authorized target
            job.provenance = 'LIVE_LOCAL';
            logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Node.js Native TCP Port Probe - Nmap Binary Offline)\n`);
            logChunk('stdout', `[i] Note: Nmap binary and Remote Kali Linux Agent not connected. Running native TCP socket audit.\n\n`);
            const { executeLiveNetworkDiagnostic } = await getLiveExecutors();
            const netResult = await executeLiveNetworkDiagnostic(job.target);
            logChunk('stdout', netResult.rawOutput);
            job.exitCode = 0;
          }
        }
      } else {
        // Tools requiring specialized offensive binaries (nuclei, nikto, ffuf, gobuster, feroxbuster, whatweb, masscan, testssl, john, etc.)
        const agentManager = remoteAgentManager;
        const agent = agentManager.getAgentForTool(tool.binaryName);

        if (agent) {
          job.provenance = 'LIVE_AGENT';
          job.agentId = agent.id;
          job.agentName = agent.name;
          logChunk('stdout', `[+] PROVENANCE: LIVE REMOTE AGENT [${agent.name} - ${agent.hostname}]\n\n`);
          const agentRes = await agentManager.dispatchJobToAgent(job, tool, logChunk);
          job.exitCode = agentRes.exitCode;
        } else {
          const localBinary = await this.checkLocalBinary(tool.binaryName);
          if (localBinary && job.mode === 'LIVE') {
            job.provenance = 'LIVE_LOCAL';
            logChunk('stdout', `[+] PROVENANCE: LIVE LOCAL (Native Binary: ${localBinary})\n\n`);
            await this.runRealBinary(job, tool, abortController, logChunk);
          } else if (job.mode === 'LIVE') {
          // Honest failure: do NOT invent mock data for failed live jobs
          job.provenance = 'UNAVAILABLE';
          job.status = 'FAILED';
          job.exitCode = 127;
          const msg =
            `[!] EXECUTION UNAVAILABLE: Tool '${tool.name}' requires binary '${tool.binaryName}' or a connected Remote Kali Execution Agent.\n` +
            `    Binary '${tool.binaryName}' is not installed in this environment.\n\n` +
            `[+] HOW TO EXECUTE GENUINELY:\n` +
            `    1. Go to Settings > Kali Linux Agent to obtain your authorization token.\n` +
            `    2. On your authorized Kali Linux machine, run:\n` +
            `       python3 agents/awm_nexus_agent.py --server <URL> --token <TOKEN>\n` +
            `    3. Once connected, re-run this job to stream real execution telemetry.\n\n` +
            `[i] If you wish to inspect this tool's expected output in an offline training environment,\n` +
            `    re-launch with Execution Mode set to [SIMULATED].\n`;
          logChunk('stderr', msg);
        } else {
          // Explicitly simulated mode for offline training
          job.provenance = 'SIMULATED';
          logChunk('stdout', `[i] NOTICE: Demonstration Mode - Offline Training Sandbox (No raw network packets)\n\n`);
          await this.runSandboxSimulation(job, tool, abortController, logChunk);
          job.exitCode = 0;
        }
      }
    }

      job.endTime = new Date().toISOString();
      job.executionTimeMs = Date.now() - startTimeMs;
      if (job.status === 'RUNNING') {
        job.status = 'COMPLETED';
      }
    } catch (err: unknown) {
      job.endTime = new Date().toISOString();
      job.executionTimeMs = Date.now() - startTimeMs;
      job.status = 'FAILED';
      job.exitCode = 1;
      const errMsg = err instanceof Error ? err.message : String(err);
      logChunk('stderr', `\n[!] EXECUTION ERROR: ${errMsg}\n`);
    } finally {
      this.activeProcesses.delete(jobId);
    }

    // Finding Normalization
    job.findings = findingParser.parseOutput(tool, job.jobId, job.target, job.stdout, job.stderr);

    logChunk('stdout', `\n------------------------------------------------------------\n`);
    logChunk('stdout', `[+] Job ${job.jobId} finished with status: ${job.status} [Provenance: ${job.provenance || 'UNKNOWN'}]\n`);
    logChunk('stdout', `[+] Normalized Findings Discovered: ${job.findings.length}\n`);

    // Artifact generation & capture
    const artifactContent = job.stdout || job.stderr;
    const artifactSha = syncSha256(artifactContent);
    const artifactFile: ArtifactFile = {
      filename: `${job.toolId}-${job.jobId.slice(-6)}-output.log`,
      contentType: 'text/plain',
      sizeBytes: new TextEncoder().encode(artifactContent).length,
      sha256: artifactSha,
      content: artifactContent
    };
    job.artifacts.push(artifactFile);

    // Cryptographic Evidence Generation
    const evidence = evidenceEngine.createEvidenceRecord(job, tool);
    job.evidenceId = evidence.evidenceId;

    // Cryptographic Audit Block
    const auditBlock = auditLedger.appendBlock(
      job.operatorId,
      'JOB_COMPLETED',
      job.tenantId,
      job.engagementId,
      job.target,
      {
        jobId: job.jobId,
        toolId: job.toolId,
        status: job.status,
        exitCode: job.exitCode,
        provenance: job.provenance,
        agentId: job.agentId,
        findingsCount: job.findings.length,
        evidenceId: evidence.evidenceId,
        executionTimeMs: job.executionTimeMs
      }
    );
    job.auditBlockId = auditBlock.hash;

    return job;
  }

  public async checkLocalBinary(binaryName: string): Promise<string | null> {
    if (typeof window !== 'undefined') return null;
    const worker = await getLinuxWorkerManager();
    if (worker) {
      return worker.resolveBinaryPath(binaryName);
    }
    return null;
  }

  private async runRealBinary(
    job: PentestJob,
    tool: SecurityTool,
    abortController: AbortController,
    logChunk: (type: 'stdout' | 'stderr', data: string) => void
  ): Promise<void> {
    const worker = await getLinuxWorkerManager();
    if (worker) {
      const timeoutMs = (tool.profiles.find(p => p.name === job.profile)?.timeoutSeconds || 45) * 1000;
      const res = await worker.executeProcess(
        job.jobId,
        tool.binaryName,
        job.parameters,
        {
          timeoutMs,
          onStdoutChunk: (chunk: string) => logChunk('stdout', chunk),
          onStderrChunk: (chunk: string) => logChunk('stderr', chunk)
        }
      );
      job.exitCode = res.exitCode;
      if (res.status === 'CANCELLED') {
        job.status = 'CANCELLED';
      }
      return;
    }

    const childProcess = await import('node:child_process');
    const binPath = `/app/applet/bin:${(typeof process !== 'undefined' && process.env?.PATH) || '/usr/local/bin:/usr/bin:/bin:/usr/sbin'}`;

    let executableName = tool.binaryName;
    const targetExecutable = executableName;

    const MAX_OUTPUT_BYTES = 2 * 1024 * 1024; // 2MB streaming guard
    let accumulatedBytes = 0;
    let truncatedWarningEmitted = false;

    const guardedLogChunk = (type: 'stdout' | 'stderr', chunkStr: string) => {
      if (accumulatedBytes >= MAX_OUTPUT_BYTES) {
        if (!truncatedWarningEmitted) {
          truncatedWarningEmitted = true;
          logChunk('stderr', `\n[!] BUFFER LIMIT: Output exceeded 2MB stream limit and was truncated for stability.\n`);
        }
        return;
      }
      accumulatedBytes += chunkStr.length;
      logChunk(type, chunkStr);
    };

    return new Promise((resolve, reject) => {
      const proc = childProcess.spawn(targetExecutable, job.parameters, {
        signal: abortController.signal,
        env: {
          PATH: binPath,
          TERM: 'xterm-256color',
          LANG: 'C.UTF-8'
        }
      });

      proc.stdout.on('data', chunk => guardedLogChunk('stdout', chunk.toString()));
      proc.stderr.on('data', chunk => guardedLogChunk('stderr', chunk.toString()));

      proc.on('close', code => {
        job.exitCode = code ?? 0;
        resolve();
      });

      proc.on('error', err => {
        if (err.name === 'AbortError') {
          job.status = 'CANCELLED';
          resolve();
        } else {
          reject(err);
        }
      });
    });
  }

  private async runSandboxSimulation(
    job: PentestJob,
    tool: SecurityTool,
    abortController: AbortController,
    logChunk: (type: 'stdout' | 'stderr', data: string) => void
  ): Promise<void> {
    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

    if (tool.binaryName === 'nuclei') {
      logChunk('stdout', `[INF] Loading Nuclei engine v3.2.4 with 4,200 verified templates...\n`);
      await sleep(250);
      logChunk('stdout', `[INF] Target initialized: ${job.target}\n`);
      await sleep(350);
      logChunk('stdout', `[CVE-2023-4863] [critical] [http] [${job.target}] Discovered heap buffer overflow vulnerability\n`);
      logChunk('stdout', `[tech-detect:express] [info] [http] [${job.target}] ExpressJS framework detected\n`);
      logChunk('stdout', `[cors-misconfig] [medium] [http] [${job.target}] Permissive CORS Access-Control-Allow-Origin: *\n`);
      logChunk('stdout', `\n[INF] Nuclei execution completed: 3 templates triggered.\n`);
    } else if (tool.binaryName === 'ffuf' || tool.binaryName === 'gobuster') {
      logChunk('stdout', `===============================================================\n`);
      logChunk('stdout', `ffuf v2.1.0 - Fast Web Fuzzer (Simulated Environment)\n`);
      logChunk('stdout', `:: Method           : GET\n`);
      logChunk('stdout', `:: URL              : ${job.target}/FUZZ\n`);
      logChunk('stdout', `===============================================================\n\n`);
      await sleep(200);
      logChunk('stdout', `admin                   [Status: 301, Size: 178, Words: 8, Lines: 4]\n`);
      logChunk('stdout', `api                     [Status: 200, Size: 412, Words: 32, Lines: 12]\n`);
      logChunk('stdout', `healthz                 [Status: 200, Size: 15, Words: 1, Lines: 1]\n`);
      logChunk('stdout', `\n:: Progress: [1000/1000] :: 0 errors :: 3 endpoints discovered.\n`);
    } else {
      await sleep(200);
      logChunk('stdout', `[+] Tool ${tool.name} executed in simulated lab sandbox.\n`);
      logChunk('stdout', `[+] Execution parameters: ${job.parameters.join(' ')}\n`);
      logChunk('stdout', `[+] Simulated telemetry recorded in sandbox buffer.\n`);
    }
  }
}

export const sandboxExecutionManager = new SandboxExecutionManager();
