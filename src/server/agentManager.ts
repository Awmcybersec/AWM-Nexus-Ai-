/**
 * AWM Nexus — Remote Kali Execution Agent Hub
 * Manages authenticated remote execution agents (e.g., Kali Linux workstations),
 * job dispatch, streaming telemetry, and evidence verification
 */

import { PentestJob, SecurityTool } from '../types';
import { auditLedger } from '../engine/auditLedger';

export interface RemoteAgent {
  id: string;
  name: string;
  hostname: string;
  os: string;
  ip: string;
  installedTools: string[];
  status: 'ONLINE' | 'BUSY' | 'OFFLINE';
  lastHeartbeat: string;
  activeJobId?: string | null;
  jobsCompleted: number;
}

export interface AgentJobPayload {
  jobId: string;
  toolId: string;
  binaryName: string;
  parameters: string[];
  target: string;
  timeoutSeconds: number;
  environment: Record<string, string>;
}

export interface AgentResultPayload {
  jobId: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  executionTimeMs: number;
  completedAt: string;
  systemMetrics?: {
    cpuPercent?: number;
    memoryMb?: number;
  };
}

class RemoteAgentManager {
  private agents: Map<string, RemoteAgent> = new Map();
  private pendingJobs: Map<string, AgentJobPayload> = new Map();
  private activeJobAssignments: Map<string, string> = new Map(); // jobId -> agentId
  private agentAuthToken: string = 'nexus-kali-token-live-2026';
  private jobChunkListeners: Map<string, Array<(type: 'stdout' | 'stderr', chunk: string) => void>> = new Map();
  private jobCompletionPromises: Map<string, { resolve: (result: AgentResultPayload) => void; reject: (err: Error) => void }> = new Map();

  constructor() {
    // Generate an initial default token if needed
  }

  public getAuthToken(): string {
    return this.agentAuthToken;
  }

  public regenerateAuthToken(): string {
    const raw = `nx-agent-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    this.agentAuthToken = raw;
    auditLedger.appendBlock('operator-human-01', 'AGENT_TOKEN_REGENERATED', 'TENANT-AWM-01', 'eng-2026-001', 'SYSTEM', {
      timestamp: new Date().toISOString()
    });
    return this.agentAuthToken;
  }

  public validateToken(token?: string): boolean {
    if (!token) return false;
    return token.trim() === this.agentAuthToken.trim();
  }

  public registerAgent(data: {
    id?: string;
    name: string;
    hostname: string;
    os?: string;
    ip?: string;
    installedTools?: string[];
  }): RemoteAgent {
    const agentId = data.id || `agent-kali-${Math.random().toString(36).slice(2, 8)}`;
    const agent: RemoteAgent = {
      id: agentId,
      name: data.name || 'Authorized Kali Linux Station',
      hostname: data.hostname || 'kali-security-node',
      os: data.os || 'Kali GNU/Linux Rolling 2026.1',
      ip: data.ip || '127.0.0.1',
      installedTools: data.installedTools || [
        'nmap',
        'nuclei',
        'nikto',
        'ffuf',
        'gobuster',
        'masscan',
        'whatweb',
        'subfinder',
        'amass',
        'dnsrecon',
        'testssl',
        'hashcat',
        'john',
        'msfconsole'
      ],
      status: 'ONLINE',
      lastHeartbeat: new Date().toISOString(),
      jobsCompleted: 0
    };

    this.agents.set(agentId, agent);

    auditLedger.appendBlock('agent-system', 'AGENT_REGISTERED', 'TENANT-AWM-01', 'eng-2026-001', agent.hostname, {
      agentId,
      agentName: agent.name,
      os: agent.os,
      installedToolsCount: agent.installedTools.length
    });

    return agent;
  }

  public heartbeat(agentId: string): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) return false;
    agent.lastHeartbeat = new Date().toISOString();
    if (agent.status === 'OFFLINE') {
      agent.status = 'ONLINE';
    }
    return true;
  }

  public getAllAgents(): RemoteAgent[] {
    const now = Date.now();
    // Mark agents offline if no heartbeat in 45 seconds
    for (const agent of this.agents.values()) {
      const last = new Date(agent.lastHeartbeat).getTime();
      if (now - last > 45000 && agent.status !== 'OFFLINE') {
        agent.status = 'OFFLINE';
      }
    }
    return Array.from(this.agents.values());
  }

  public getOnlineAgents(): RemoteAgent[] {
    return this.getAllAgents().filter(a => a.status === 'ONLINE' || a.status === 'BUSY');
  }

  public getAgentForTool(toolBinary: string): RemoteAgent | undefined {
    return this.getOnlineAgents().find(a =>
      a.installedTools.some(t => t.toLowerCase() === toolBinary.toLowerCase())
    );
  }

  public dispatchJobToAgent(
    job: PentestJob,
    tool: SecurityTool,
    onChunk?: (type: 'stdout' | 'stderr', chunk: string) => void
  ): Promise<AgentResultPayload> {
    const agent = this.getAgentForTool(tool.binaryName) || this.getOnlineAgents()[0];
    if (!agent) {
      throw new Error(`No online execution agent available for tool '${tool.binaryName}'.`);
    }

    const payload: AgentJobPayload = {
      jobId: job.jobId,
      toolId: tool.id,
      binaryName: tool.binaryName,
      parameters: job.parameters,
      target: job.target,
      timeoutSeconds: 120,
      environment: {
        AWM_ENGAGEMENT_ID: job.engagementId,
        AWM_TENANT_ID: job.tenantId,
        AWM_OPERATOR_ID: job.operatorId
      }
    };

    this.pendingJobs.set(job.jobId, payload);
    this.activeJobAssignments.set(job.jobId, agent.id);
    agent.status = 'BUSY';
    agent.activeJobId = job.jobId;

    if (onChunk) {
      const list = this.jobChunkListeners.get(job.jobId) || [];
      list.push(onChunk);
      this.jobChunkListeners.set(job.jobId, list);
    }

    return new Promise((resolve, reject) => {
      this.jobCompletionPromises.set(job.jobId, { resolve, reject });

      // Set dispatch timeout
      const timer = setTimeout(() => {
        if (this.pendingJobs.has(job.jobId) || this.jobCompletionPromises.has(job.jobId)) {
          this.pendingJobs.delete(job.jobId);
          this.jobCompletionPromises.delete(job.jobId);
          if (agent.activeJobId === job.jobId) {
            agent.activeJobId = null;
            agent.status = 'ONLINE';
          }
          reject(new Error(`Agent execution timed out after 120 seconds.`));
        }
      }, 125000);
      if (timer.unref) timer.unref();
    });
  }

  public pollJob(agentId: string): AgentJobPayload | null {
    const agent = this.agents.get(agentId);
    if (!agent) return null;

    agent.lastHeartbeat = new Date().toISOString();

    for (const [jobId, payload] of this.pendingJobs.entries()) {
      const assigned = this.activeJobAssignments.get(jobId);
      if (!assigned || assigned === agentId) {
        this.pendingJobs.delete(jobId);
        return payload;
      }
    }
    return null;
  }

  public receiveChunk(jobId: string, type: 'stdout' | 'stderr', chunk: string): void {
    const listeners = this.jobChunkListeners.get(jobId);
    if (listeners) {
      for (const listener of listeners) {
        listener(type, chunk);
      }
    }
  }

  public completeJob(result: AgentResultPayload): boolean {
    const promise = this.jobCompletionPromises.get(result.jobId);
    const agentId = this.activeJobAssignments.get(result.jobId);

    if (agentId) {
      const agent = this.agents.get(agentId);
      if (agent) {
        agent.status = 'ONLINE';
        agent.activeJobId = null;
        agent.jobsCompleted++;
      }
    }

    this.activeJobAssignments.delete(result.jobId);
    this.jobChunkListeners.delete(result.jobId);

    if (promise) {
      promise.resolve(result);
      this.jobCompletionPromises.delete(result.jobId);
      return true;
    }

    return false;
  }

  /**
   * Quick simulate method for test suites and offline verification
   */
  public registerDemoKaliAgent(): RemoteAgent {
    return this.registerAgent({
      id: 'kali-primary-demo',
      name: 'Kali Workstation 2026.1 (Dedicated Node)',
      hostname: 'kali-sec-01.corp.internal',
      os: 'Kali GNU/Linux Rolling (Kernel 6.8.11-amd64)',
      ip: '10.10.14.85',
      installedTools: [
        'nmap',
        'nuclei',
        'nikto',
        'ffuf',
        'gobuster',
        'masscan',
        'whatweb',
        'subfinder',
        'amass',
        'dnsrecon',
        'testssl',
        'hashcat',
        'john',
        'msfconsole'
      ]
    });
  }
}

const globalForAgent = globalThis as unknown as { __awm_remoteAgentManager?: RemoteAgentManager };
export const remoteAgentManager = globalForAgent.__awm_remoteAgentManager || new RemoteAgentManager();
if (!globalForAgent.__awm_remoteAgentManager) {
  globalForAgent.__awm_remoteAgentManager = remoteAgentManager;
}
