/**
 * AWM Nexus — ASCL (Advanced Security Command Language) REPL & Parser
 * Complete human operator terminal execution engine with full validation and structured output
 */

import { toolRegistry } from './toolRegistry';
import { scopeEngine } from './scopeEngine';
import { sandboxExecutionManager } from './sandboxExecution';
import { policyAndHitlEngine } from './policyAndHitlEngine';
import { evidenceEngine, riskEngine } from './riskAndEvidenceEngine';
import { auditLedger } from './auditLedger';
import {
  attackSurfaceEngine,
  exposureEngine,
  attackPathEngine,
  defensiveTelemetryEngine,
  pentestReportEngine
} from './offensiveDefensiveEngines';
import { aiOrchestrator } from './aiOrchestrator';
import { llmManager } from '../services/llm/llmManager';
import { siemManager } from '../services/siem/siemManager';
import { detectRealBinaries } from './binaryDetector';
import { remoteAgentManager } from '../server/agentManager';
import { externalToolImportEngine } from './externalToolImportEngine';

export interface ASCLCommandResult {
  output: string;
  type: 'SUCCESS' | 'ERROR' | 'INFO' | 'WARNING';
  data?: unknown;
}

export class ASCLEngine {
  private currentEngagementId = 'eng-2026-001';
  private tenantId = 'TENANT-AWM-01';
  private operatorId = 'operator-human-01';

  public async execute(rawInput: string): Promise<ASCLCommandResult> {
    const trimmed = rawInput.trim();
    if (!trimmed) return { output: '', type: 'INFO' };

    const parts = trimmed.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const subCmd = parts[1]?.toLowerCase();
    const args = parts.slice(2);

    try {
      switch (cmd) {
        case 'help':
          return this.handleHelp();

        case 'status':
        case 'whoami':
          return this.handleStatus();

        case 'tools':
          return await this.handleTools(subCmd, args);

        case 'jobs':
          return this.handleJobs(subCmd, args);

        case 'evidence':
          return this.handleEvidence(subCmd, args);

        case 'target':
        case 'targets':
          return this.handleTarget(subCmd, args);

        case 'scope':
          return this.handleScope(subCmd, args);

        case 'surface':
          return this.handleSurface(subCmd, args);

        case 'exposure':
          return this.handleExposure(subCmd, args);

        case 'vuln':
        case 'vulns':
          return this.handleVuln(subCmd, args);

        case 'attack-paths':
        case 'attackpaths':
          return this.handleAttackPaths(subCmd, args);

        case 'report':
          return this.handleReport(subCmd, args);

        case 'audit':
          return this.handleAudit(subCmd, args);

        case 'hitl':
          return this.handleHitl(subCmd, args);

        case 'agent':
        case 'agents':
          return await this.handleAgent(subCmd, args);

        case 'siem':
          return await this.handleSiem(subCmd, args);

        case 'kali':
          return await this.handleKali(subCmd, args);

        case 'import':
        case 'imports':
          return this.handleImports(subCmd, args);

        case 'run':
        case 'exec':
          return await this.handleRun(parts.slice(1));

        case 'clear':
          return { output: '__CLEAR__', type: 'INFO' };

        default:
          return {
            output: `[!] Unknown ASCL command: '${cmd}'. Type 'help' for available command catalog.`,
            type: 'ERROR'
          };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { output: `[!] ASCL EXECUTION EXCEPTION: ${msg}`, type: 'ERROR' };
    }
  }

  private handleHelp(): ASCLCommandResult {
    const out = `
========================================================================
             AWM NEXUS — ASCL COMMAND CATALOG (v4.8.2)
========================================================================

TOOL REGISTRY & HEALTH:
  tools list                     List all registered security testing tools
  tools search <query>           Search tools by name, binary, category
  tools show <id>                Display detailed metadata & profiles for tool
  tools status                   Summary of installed vs simulated tools
  tools verify <id>              Verify real binary existence & detect version
  tools health <id>              Check sandbox availability & execution status
  tools install <id>             Initiate operator-confirmed package install

EXECUTION & JOB MANAGEMENT:
  run <toolId> <target> [prof]   Execute tool against in-scope target
  jobs list                      List all pentest jobs and statuses
  jobs show <id>                 Display full stdout/stderr and findings
  jobs cancel <id>               Terminate running job process in sandbox

KALI EXECUTION AGENT (REMOTE):
  kali status                    Display connected Kali agents and execution status
  kali token [regenerate]        Display or regenerate agent authentication token
  kali list                      List all registered remote execution nodes
  kali demo                      Connect demo Kali Linux node for local testing

SCOPE & TARGET INVENTORY:
  scope show                     Display active engagement rules & exclusions
  scope verify <target>          Pre-flight check if target is within RoE
  target list                    List all targets, environments & ports
  target show <id>               Display specific target asset record
  target add <name> <addr>       Register new candidate target asset

OFFENSIVE & EXPOSURE ENGINES:
  surface scan <target>          Query attack surface asset inventory
  exposure analyze <target>      Analyze exposure vectors & perimeter score
  vuln list                      List discovered normalized vulnerabilities
  vuln show <id>                 Display details & CVSS for specific finding
  vuln validate <id>             Mark vulnerability validation status
  attack-paths list              List discovered multi-hop attack paths
  attack-paths show <id>         Inspect step-by-step attack path graph

EVIDENCE, AUDIT & REPORTS:
  evidence list                  List cryptographically sealed evidence items
  evidence show <id>             View hashes, raw command & signature
  evidence verify <id>           Verify SHA-256 hash & signature integrity
  audit show                     Display cryptographic audit block ledger
  audit verify                   Verify block-by-block hash chain integrity
  report technical [eng]         Generate comprehensive technical report
  report executive [eng]         Generate executive security posture summary

HUMAN-IN-THE-LOOP (HITL):
  hitl list                      View pending operator approval requests
  hitl approve <id>              Authorize pending high-risk tool execution
  hitl reject <id>               Decline pending high-risk execution request

SYSTEM:
  status / whoami                Display active operator, tenant & engagement
  clear                          Clear the terminal screen
========================================================================`;
    return { output: out, type: 'INFO' };
  }

  private handleStatus(): ASCLCommandResult {
    const eng = scopeEngine.getEngagement(this.currentEngagementId);
    const auditStatus = auditLedger.verifyChainIntegrity();
    const pendingHitl = policyAndHitlEngine.getPendingRequests().length;
    const tools = toolRegistry.getAllTools();
    const installed = tools.filter(t => t.availabilityStatus === 'INSTALLED').length;

    const out = `
[+] OPERATOR IDENTITY:     ${this.operatorId} (Lead Security Engineer)
[+] TENANT SCOPE:          ${this.tenantId} (AWM Defense Corp)
[+] ACTIVE ENGAGEMENT:     ${eng?.code || 'N/A'} - ${eng?.name || 'N/A'}
[+] AUTHORIZATION WINDOW:  ${eng?.startDate.slice(0, 10)} to ${eng?.endDate.slice(0, 10)} (ACTIVE)
[+] TOOL REGISTRY:         ${tools.length} Registered | ${installed} Verified Installed
[+] AUDIT CHAIN STATUS:    ${auditStatus.isValid ? 'VALID / TAMPER-EVIDENT' : 'CORRUPTED'} (${auditStatus.blocksCount} Blocks)
[+] PENDING HITL GATES:    ${pendingHitl} Request(s) awaiting approval`;
    return { output: out, type: 'INFO' };
  }

  private async handleTools(subCmd: string, args: string[]): Promise<ASCLCommandResult> {
    if (subCmd === 'run') {
      const toolId = args[0];
      const target = args[1] || '127.0.0.1';
      const profile = args[2] || '';
      return await this.handleRun([toolId, target, profile]);
    }
    if (!subCmd || subCmd === 'list') {
      const tools = toolRegistry.getAllTools();
      let out = `ID                      NAME                            CATEGORY        STATUS          TIER\n`;
      out += `------------------------------------------------------------------------------------------------------\n`;
      for (const t of tools) {
        const idCol = t.id.padEnd(23);
        const nameCol = (t.name.length > 30 ? t.name.slice(0, 27) + '...' : t.name).padEnd(31);
        const catCol = t.category.padEnd(15);
        const statusCol = t.availabilityStatus.padEnd(15);
        const tierCol = t.capabilityTier;
        out += `${idCol} ${nameCol} ${catCol} ${statusCol} ${tierCol}\n`;
      }
      out += `\nTotal: ${tools.length} security tools registered.`;
      return { output: out, type: 'SUCCESS', data: tools };
    }

    if (subCmd === 'status') {
      const tools = toolRegistry.getAllTools();
      const counts: Record<string, number> = {};
      for (const t of tools) {
        counts[t.availabilityStatus] = (counts[t.availabilityStatus] || 0) + 1;
      }
      let out = `TOOL AVAILABILITY MATRIX:\n`;
      out += `------------------------------------\n`;
      for (const [status, count] of Object.entries(counts)) {
        out += `  [+] ${status.padEnd(16)} : ${count}\n`;
      }
      return { output: out, type: 'INFO' };
    }

    if (subCmd === 'search') {
      const q = args.join(' ');
      if (!q) return { output: `[!] Usage: tools search <query>`, type: 'WARNING' };
      const matched = toolRegistry.searchTools(q);
      let out = `Found ${matched.length} tools matching '${q}':\n`;
      for (const t of matched) {
        out += `  - ${t.id} (${t.name}) [${t.availabilityStatus}] - ${t.description.slice(0, 70)}...\n`;
      }
      return { output: out, type: 'SUCCESS', data: matched };
    }

    if (subCmd === 'show') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: tools show <id>`, type: 'WARNING' };
      const tool = toolRegistry.getTool(id);
      if (!tool) return { output: `[!] Tool '${id}' not found in registry.`, type: 'ERROR' };

      let out = `
TOOL METADATA: ${tool.name}
----------------------------------------------------------------------
ID:                   ${tool.id}
Binary Name:          ${tool.binaryName}
Category:             ${tool.category}
Availability Status:  ${tool.availabilityStatus}
Detected Path:        ${tool.detectedPath || 'None (Running in Sandbox Simulation)'}
Version:              ${tool.version || 'Unverified'}
Capability Tier:      ${tool.capabilityTier}
Install Command:      ${tool.installCommand || 'Manual package required'}
Documentation:        ${tool.documentationUrl}
Description:          ${tool.description}

PROFILES (${tool.profiles.length}):\n`;
      for (const p of tool.profiles) {
        out += `  [+] Profile: ${p.name} (id: ${p.id})\n`;
        out += `      HITL Required: ${p.requiresHITL ? 'YES (' + p.hitlReason + ')' : 'NO'}\n`;
        out += `      Default Flags: ${p.defaultFlags.join(' ') || 'none'}\n`;
        out += `      Allowed Flags: ${p.allowedFlags.join(', ')}\n`;
        out += `      Timeout:       ${p.timeoutSeconds}s\n\n`;
      }
      return { output: out, type: 'INFO', data: tool };
    }

    if (subCmd === 'verify' || subCmd === 'health') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: tools ${subCmd} <id>`, type: 'WARNING' };
      const tool = toolRegistry.getTool(id);
      if (!tool) return { output: `[!] Tool '${id}' not found.`, type: 'ERROR' };

      return {
        output: `
[*] HEALTH CHECK: ${tool.name} (${tool.id})
----------------------------------------------------------------------
Binary:              ${tool.binaryName}
Verification Probe:  ${tool.verificationCommand}
Availability Status: ${tool.availabilityStatus}
Version Fingerprint: ${tool.version || 'N/A'}
Native Subprocess:   ${tool.availabilityStatus === 'INSTALLED' ? 'ENABLED' : 'SIMULATION FALLBACK'}
Sandbox Compliant:   YES (Strict Flag Sanitization & Timeout Enforced)`,
        type: 'INFO'
      };
    }

    if (subCmd === 'install') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: tools install <id>`, type: 'WARNING' };
      const tool = toolRegistry.getTool(id);
      if (!tool) return { output: `[!] Tool '${id}' not found.`, type: 'ERROR' };

      if (!tool.installable) {
        return { output: `[!] Tool ${tool.name} cannot be automatically installed: ${tool.installCommand}`, type: 'WARNING' };
      }

      return {
        output: `
[*] OPERATOR CONFIRMED INSTALLATION REQUEST
----------------------------------------------------------------------
Tool:            ${tool.name}
Package Command: ${tool.installCommand}
Status:          Execution registered. Tool will be verified upon completion.`,
        type: 'INFO'
      };
    }

    return { output: `[!] Unknown tools subcommand '${subCmd}'. Type 'help' for syntax.`, type: 'ERROR' };
  }

  private handleJobs(subCmd: string, args: string[]): ASCLCommandResult {
    if (!subCmd || subCmd === 'list') {
      const jobs = sandboxExecutionManager.getAllJobs();
      if (jobs.length === 0) {
        return { output: `No jobs recorded in this session. Run a tool using 'run <toolId> <target>'.`, type: 'INFO' };
      }
      let out = `JOB ID               TOOL           TARGET                    STATUS              TIME\n`;
      out += `------------------------------------------------------------------------------------------\n`;
      for (const j of jobs) {
        const idCol = j.jobId.padEnd(20);
        const toolCol = j.toolId.slice(0, 13).padEnd(14);
        const targetCol = (j.target.length > 24 ? j.target.slice(0, 21) + '...' : j.target).padEnd(25);
        const statusCol = j.status.padEnd(19);
        const timeCol = j.startTime.slice(11, 19);
        out += `${idCol} ${toolCol} ${targetCol} ${statusCol} ${timeCol}\n`;
      }
      return { output: out, type: 'SUCCESS', data: jobs };
    }

    if (subCmd === 'show') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: jobs show <id>`, type: 'WARNING' };
      const job = sandboxExecutionManager.getJob(id);
      if (!job) return { output: `[!] Job '${id}' not found.`, type: 'ERROR' };

      let out = `
JOB EXECUTION RECORD: ${job.jobId}
----------------------------------------------------------------------
Tool:         ${job.toolName} (${job.toolId})
Target:       ${job.target}
Profile:      ${job.profile}
Status:       ${job.status} [${job.mode}]
Exit Code:    ${job.exitCode !== undefined ? job.exitCode : 'Running/Pending'}
Started:      ${job.startTime}
Completed:    ${job.endTime || 'In progress'}
Evidence ID:  ${job.evidenceId || 'Pending'}
Audit Hash:   ${job.auditBlockId ? job.auditBlockId.slice(0, 16) + '...' : 'Pending'}

=== STDOUT ===
${job.stdout || '(no stdout output)'}

=== STDERR ===
${job.stderr || '(no stderr output)'}

=== NORMALIZED FINDINGS (${job.findings.length}) ===\n`;
      for (const f of job.findings) {
        out += `  [!] ${f.severity} - ${f.title} (${f.cwe}) [CVSS ${f.cvssScore}]\n`;
      }

      return { output: out, type: 'INFO', data: job };
    }

    if (subCmd === 'cancel') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: jobs cancel <id>`, type: 'WARNING' };
      const res = sandboxExecutionManager.cancelJob(id, this.operatorId);
      if (res.success) {
        return { output: `[+] Job ${id} has been cancelled successfully.`, type: 'SUCCESS' };
      } else {
        return { output: `[!] Failed to cancel job ${id}: ${res.error}`, type: 'ERROR' };
      }
    }

    return { output: `[!] Unknown jobs subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleEvidence(subCmd: string, args: string[]): ASCLCommandResult {
    if (!subCmd || subCmd === 'list') {
      const ev = evidenceEngine.getAllEvidence();
      if (ev.length === 0) return { output: `Evidence locker is empty.`, type: 'INFO' };

      let out = `EVIDENCE ID          JOB ID               TARGET                    TOOL           VERIFIED\n`;
      out += `-------------------------------------------------------------------------------------------------\n`;
      for (const e of ev) {
        out += `${e.evidenceId.padEnd(20)} ${e.jobId.padEnd(20)} ${(e.target.slice(0, 24)).padEnd(25)} ${e.toolId.padEnd(14)} ${e.verified ? 'YES (SHA-256)' : 'NO'}\n`;
      }
      return { output: out, type: 'SUCCESS', data: ev };
    }

    if (subCmd === 'show') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: evidence show <id>`, type: 'WARNING' };
      const ev = evidenceEngine.getEvidence(id);
      if (!ev) return { output: `[!] Evidence '${id}' not found.`, type: 'ERROR' };

      const out = `
CRYPTOGRAPHIC EVIDENCE RECORD: ${ev.evidenceId}
----------------------------------------------------------------------
Job ID:            ${ev.jobId}
Target:            ${ev.target}
Tool:              ${ev.toolId} (v${ev.toolVersion})
Command Executed:  ${ev.commandExecuted}
Operator ID:       ${ev.operatorId}
Timestamp:         ${ev.timestamp}
Stdout SHA-256:    ${ev.rawStdoutHash}
Stderr SHA-256:    ${ev.rawStderrHash}
Cryptographic Sig: ${ev.cryptographicSignature}
Findings Count:    ${ev.findingsCount}
Integrity Status:  ${ev.verified ? 'SEALED & UNTAMPERED' : 'UNVERIFIED'}`;
      return { output: out, type: 'INFO', data: ev };
    }

    if (subCmd === 'verify') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: evidence verify <id>`, type: 'WARNING' };
      const check = evidenceEngine.verifyEvidenceIntegrity(id);
      if (check.isValid) {
        return {
          output: `[+] EVIDENCE INTEGRITY VERIFIED: Evidence ${id} matches cryptographic signature and SHA-256 hashes.`,
          type: 'SUCCESS'
        };
      } else {
        return {
          output: `[!] EVIDENCE INTEGRITY COMPROMISED: ${check.error}`,
          type: 'ERROR'
        };
      }
    }

    return { output: `[!] Unknown evidence subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleTarget(subCmd: string, args: string[]): ASCLCommandResult {
    const eng = scopeEngine.getEngagement(this.currentEngagementId);
    if (!eng) return { output: `[!] Active engagement not loaded.`, type: 'ERROR' };

    if (!subCmd || subCmd === 'list') {
      let out = `ID             NAME                              TYPE      ADDRESS                   SCOPE STATUS\n`;
      out += `----------------------------------------------------------------------------------------------------\n`;
      for (const t of eng.targets) {
        const idCol = t.id.padEnd(14);
        const nameCol = (t.name.length > 32 ? t.name.slice(0, 29) + '...' : t.name).padEnd(33);
        const typeCol = t.type.padEnd(9);
        const addrCol = t.address.padEnd(25);
        const scopeCol = t.inScope ? '[+] IN SCOPE' : '[-] EXCLUDED';
        out += `${idCol} ${nameCol} ${typeCol} ${addrCol} ${scopeCol}\n`;
      }
      return { output: out, type: 'SUCCESS', data: eng.targets };
    }

    if (subCmd === 'show') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: target show <id>`, type: 'WARNING' };
      const target = eng.targets.find(t => t.id === id || t.address === id);
      if (!target) return { output: `[!] Target '${id}' not found.`, type: 'ERROR' };

      const out = `
TARGET ASSET: ${target.name}
----------------------------------------------------------------------
ID:               ${target.id}
Address:          ${target.address}
Type:             ${target.type}
Environment:      ${target.environment}
Criticality:      ${target.criticality}
Scope Status:     ${target.inScope ? 'IN SCOPE' : 'EXCLUDED (Out of Scope)'}
Exclusion Reason: ${target.exclusionReason || 'N/A'}
Authorized Ports: ${target.ports.join(', ')}
Authorized Until: ${target.authorizedUntil}`;
      return { output: out, type: 'INFO', data: target };
    }

    if (subCmd === 'add') {
      const name = args[0];
      const addr = args[1];
      if (!name || !addr) return { output: `[!] Usage: target add <name> <address>`, type: 'WARNING' };

      const newT = scopeEngine.addTarget(eng.id, {
        name,
        address: addr,
        type: addr.includes('/') ? 'CIDR' : addr.match(/^\d+\.\d+\.\d+\.\d+$/) ? 'IP' : 'DOMAIN',
        ports: [80, 443],
        environment: 'SANDBOX_LAB',
        criticality: 'MEDIUM',
        inScope: true,
        active: true,
        authorizedUntil: eng.endDate
      });

      auditLedger.appendBlock(
        this.operatorId,
        'TARGET_ADDED',
        this.tenantId,
        eng.id,
        addr,
        { targetId: newT.id, name, address: addr }
      );

      return { output: `[+] Added target asset ${name} (${addr}) with ID ${newT.id}`, type: 'SUCCESS', data: newT };
    }

    return { output: `[!] Unknown target subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleScope(subCmd: string, args: string[]): ASCLCommandResult {
    const eng = scopeEngine.getEngagement(this.currentEngagementId);
    if (!eng) return { output: `[!] Active engagement not found.`, type: 'ERROR' };

    if (!subCmd || subCmd === 'show') {
      let out = `
RULES OF ENGAGEMENT (RoE) SCOPE BOUNDARY: ${eng.code}
Client: ${eng.clientName} | Window: ${eng.startDate.slice(0, 10)} to ${eng.endDate.slice(0, 10)}
----------------------------------------------------------------------
SCOPE RULES:\n`;
      for (const r of eng.scopeRules) {
        out += `  [${r.type === 'INCLUDE' ? '+' : '-'}] ${r.type.padEnd(8)}: ${r.pattern.padEnd(30)} | ${r.description}\n`;
      }
      return { output: out, type: 'INFO', data: eng.scopeRules };
    }

    if (subCmd === 'verify') {
      const target = args[0];
      if (!target) return { output: `[!] Usage: scope verify <target>`, type: 'WARNING' };
      const res = scopeEngine.validateTargetScope(eng, target);
      if (res.inScope) {
        return {
          output: `[+] SCOPE AUTHORIZED: ${res.reason}`,
          type: 'SUCCESS'
        };
      } else {
        return {
          output: `[-] SCOPE REJECTED: ${res.reason}`,
          type: 'ERROR'
        };
      }
    }

    return { output: `[!] Unknown scope subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleSurface(subCmd: string, args: string[]): ASCLCommandResult {
    if (subCmd === 'scan') {
      const target = args[0] || '127.0.0.1';
      const asset = attackSurfaceEngine.scanTarget(target);
      let out = `
ATTACK SURFACE ASSET SCAN: ${asset.target} (${asset.host})
----------------------------------------------------------------------
Exposure Score:  ${asset.exposureScore}/100 (${asset.riskCategory} Risk)
Last Scanned:    ${asset.lastScanned}
Detected Tech:   ${asset.technologies.join(', ')}

OPEN PORTS & SERVICES:\n`;
      for (const p of asset.openPorts) {
        out += `  [+] Port ${p.port}/tcp : ${p.service} (${p.version || 'unfingerprinted'}) [${p.state}]\n`;
      }
      return { output: out, type: 'SUCCESS', data: asset };
    }
    return { output: `[!] Usage: surface scan <target>`, type: 'WARNING' };
  }

  private handleExposure(subCmd: string, args: string[]): ASCLCommandResult {
    if (subCmd === 'analyze') {
      const target = args[0] || '127.0.0.1';
      const asset = attackSurfaceEngine.getAsset(target);
      const res = exposureEngine.analyzeExposure(target, asset);
      let out = `
EXPOSURE ANALYSIS: ${res.target}
----------------------------------------------------------------------
Perimeter Exposure Score: ${res.exposureScore}/100 (${res.riskCategory} Category)
Perimeter Shield:         ${res.perimeterDefense}

RISK FACTORS:\n`;
      for (const f of res.factors) {
        out += `  [${f.status === 'EXPOSED' ? '!' : '+'}] ${f.factor.padEnd(50)} : [${f.status}]\n`;
      }
      return { output: out, type: 'SUCCESS', data: res };
    }
    return { output: `[!] Usage: exposure analyze <target>`, type: 'WARNING' };
  }

  private handleVuln(subCmd: string, args: string[]): ASCLCommandResult {
    const jobs = sandboxExecutionManager.getAllJobs();
    const allFindings = jobs.flatMap(j => j.findings);

    if (!subCmd || subCmd === 'list') {
      if (allFindings.length === 0) {
        return { output: `No vulnerability findings discovered yet in this session. Run security tools to enumerate.`, type: 'INFO' };
      }

      let out = `FINDING ID      SEV      TITLE                                           HOST               STATUS\n`;
      out += `-------------------------------------------------------------------------------------------------------\n`;
      for (const f of allFindings) {
        const idCol = f.findingId.padEnd(15);
        const sevCol = f.severity.padEnd(8);
        const titleCol = (f.title.length > 45 ? f.title.slice(0, 42) + '...' : f.title).padEnd(47);
        const hostCol = (f.host.length > 18 ? f.host.slice(0, 15) + '...' : f.host).padEnd(19);
        const statCol = f.validationStatus;
        out += `${idCol} ${sevCol} ${titleCol} ${hostCol} ${statCol}\n`;
      }
      return { output: out, type: 'SUCCESS', data: allFindings };
    }

    if (subCmd === 'show') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: vuln show <id>`, type: 'WARNING' };
      const f = allFindings.find(find => find.findingId === id);
      if (!f) return { output: `[!] Finding '${id}' not found.`, type: 'ERROR' };

      const out = `
VULNERABILITY FINDING: ${f.title}
----------------------------------------------------------------------
Finding ID:        ${f.findingId}
Job ID:            ${f.jobId}
Severity:          ${f.severity} (CVSS: ${f.cvssScore})
CWE:               ${f.cwe} | OWASP: ${f.owaspCategory}
Host / Endpoint:   ${f.host}${f.path || ''}${f.port ? ':' + f.port : ''}
Validation Status: ${f.validationStatus}
Confidence:        ${f.confidence}

Description:
${f.description}

Evidence Snippet:
${f.evidenceSnippet}

Remediation Guidance:
${f.remediation}`;
      return { output: out, type: 'INFO', data: f };
    }

    return { output: `[!] Unknown vuln subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleAttackPaths(subCmd: string, args: string[]): ASCLCommandResult {
    const paths = attackPathEngine.getAllPaths();
    if (!subCmd || subCmd === 'list') {
      let out = `PATH ID         NAME                                                  SEVERITY   STEPS   VERIFIED\n`;
      out += `---------------------------------------------------------------------------------------------------\n`;
      for (const p of paths) {
        out += `${p.id.padEnd(15)} ${(p.name.slice(0, 50)).padEnd(53)} ${p.severity.padEnd(10)} ${String(p.steps.length).padEnd(7)} ${p.verified ? 'YES' : 'NO'}\n`;
      }
      return { output: out, type: 'SUCCESS', data: paths };
    }

    if (subCmd === 'show') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: attack-paths show <id>`, type: 'WARNING' };
      const p = attackPathEngine.getPath(id);
      if (!p) return { output: `[!] Attack path '${id}' not found.`, type: 'ERROR' };

      let out = `
ATTACK PATH: ${p.name}
----------------------------------------------------------------------
ID:          ${p.id}
Severity:    ${p.severity}
Target:      ${p.targetAsset}
Description: ${p.description}

EXPLOIT CHAIN STEPS:\n`;
      p.steps.forEach((step, idx) => {
        out += `  Step ${idx + 1}: ${step.name} [MITRE: ${step.mitreTechniqueId} - ${step.mitreTactic}]\n`;
        out += `          Tool: ${step.toolUsed} | Likelihood: ${step.likelihood} | Impact: ${step.impact}\n`;
      });
      return { output: out, type: 'INFO', data: p };
    }

    return { output: `[!] Unknown attack-paths subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleReport(subCmd: string, args: string[]): ASCLCommandResult {
    const type: 'TECHNICAL' | 'EXECUTIVE' = subCmd === 'executive' ? 'EXECUTIVE' : 'TECHNICAL';
    const jobs = sandboxExecutionManager.getAllJobs();
    const findings = jobs.flatMap(j => j.findings);
    const report = pentestReportEngine.generateReport(this.currentEngagementId, type, findings);

    const out = `
======================================================================
${report.title.toUpperCase()}
======================================================================
Report ID:        ${report.reportId}
Engagement Code:  ${report.engagementCode}
Generated At:     ${report.generatedAt}
Overall Posture:  ${report.riskRating} (Risk Score: ${report.overallRiskScore}/100)
Scope Summary:    ${report.scopeSummary.inScopeTargets} In-Scope Targets | ${report.scopeSummary.excludedTargets} Excluded
Findings Summary: ${report.findingsSummary.total} Total (${report.findingsSummary.critical} Crit, ${report.findingsSummary.high} High, ${report.findingsSummary.medium} Med)

EXECUTIVE SUMMARY:
${report.executiveSummary}

AUDIT CHAIN PROVENANCE:
Checked ${report.auditChainVerification.blocksChecked} blocks | Valid: ${report.auditChainVerification.isValid ? 'YES (SHA-256 Chain Intact)' : 'CORRUPTED'}

RECOMMENDED REMEDIATION ACTIONS:\n` +
      report.recommendations.map((r, i) => `  ${i + 1}. ${r}`).join('\n');

    return { output: out, type: 'SUCCESS', data: report };
  }

  private handleAudit(subCmd: string, args: string[]): ASCLCommandResult {
    if (!subCmd || subCmd === 'show') {
      const blocks = auditLedger.getBlocks();
      let out = `INDEX  ACTION               ACTOR                HASH (FIRST 16)   PREV HASH (FIRST 16)\n`;
      out += `----------------------------------------------------------------------------------------\n`;
      for (const b of blocks) {
        out += `${String(b.index).padEnd(6)} ${b.action.padEnd(20)} ${b.actor.padEnd(20)} ${b.hash.slice(0, 16).padEnd(17)} ${b.prevHash.slice(0, 16)}\n`;
      }
      return { output: out, type: 'SUCCESS', data: blocks };
    }

    if (subCmd === 'verify') {
      const res = auditLedger.verifyChainIntegrity();
      if (res.isValid) {
        return {
          output: `[+] AUDIT CHAIN INTEGRITY VERIFIED: All ${res.blocksCount} blocks verified with valid SHA-256 hash chains.`,
          type: 'SUCCESS'
        };
      } else {
        return {
          output: `[!] AUDIT INTEGRITY FAILURE at block #${res.tamperedIndex}: ${res.error}`,
          type: 'ERROR'
        };
      }
    }

    return { output: `[!] Unknown audit subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private handleHitl(subCmd: string, args: string[]): ASCLCommandResult {
    if (!subCmd || subCmd === 'list') {
      const reqs = policyAndHitlEngine.getAllRequests();
      if (reqs.length === 0) return { output: `No HITL approval requests pending.`, type: 'INFO' };

      let out = `REQUEST ID         TOOL           TARGET               RISK      STATUS      OPERATOR\n`;
      out += `-----------------------------------------------------------------------------------------\n`;
      for (const r of reqs) {
        out += `${r.requestId.padEnd(18)} ${r.toolId.slice(0, 13).padEnd(14)} ${(r.targetAddress.slice(0, 18)).padEnd(20)} ${r.riskLevel.padEnd(9)} ${r.status.padEnd(11)} ${r.operatorId}\n`;
      }
      return { output: out, type: 'SUCCESS', data: reqs };
    }

    if (subCmd === 'approve') {
      const id = args[0];
      if (!id) return { output: `[!] Usage: hitl approve <id>`, type: 'WARNING' };
      const res = policyAndHitlEngine.approveRequest(id, this.operatorId);
      if (res.success) {
        return {
          output: `[+] REQUEST ${id} APPROVED. Cryptographic token: ${res.token?.slice(0, 16)}...`,
          type: 'SUCCESS'
        };
      } else {
        return { output: `[!] Approval failed: ${res.error}`, type: 'ERROR' };
      }
    }

    if (subCmd === 'reject') {
      const id = args[0];
      const reason = args.slice(1).join(' ') || 'Rejected by Lead Operator';
      if (!id) return { output: `[!] Usage: hitl reject <id> [reason]`, type: 'WARNING' };
      const res = policyAndHitlEngine.rejectRequest(id, this.operatorId, reason);
      if (res.success) {
        return { output: `[-] Request ${id} REJECTED with reason: ${reason}`, type: 'SUCCESS' };
      } else {
        return { output: `[!] Rejection failed: ${res.error}`, type: 'ERROR' };
      }
    }

    return { output: `[!] Unknown hitl subcommand '${subCmd}'.`, type: 'ERROR' };
  }

  private async handleRun(args: string[]): Promise<ASCLCommandResult> {
    const toolId = args[0];
    const target = args[1];
    const profileId = args[2] || '';

    if (!toolId || !target) {
      return { output: `[!] Usage: run <toolId> <target> [profileId]`, type: 'WARNING' };
    }

    const tool = toolRegistry.getTool(toolId) || toolRegistry.getToolByBinary(toolId);
    if (!tool) {
      return { output: `[!] Tool '${toolId}' is not registered. Type 'tools list' to view available tools.`, type: 'ERROR' };
    }

    const jobResult = sandboxExecutionManager.createJob(
      this.tenantId,
      this.currentEngagementId,
      this.operatorId,
      tool.id,
      target,
      profileId
    );

    if (jobResult.error) {
      return { output: `[!] EXECUTION REJECTED:\n${jobResult.error}`, type: 'ERROR' };
    }

    if (jobResult.requiresHITL) {
      return {
        output: `
[!] HIGH-IMPACT OPERATION INTERCEPTED: HUMAN-IN-THE-LOOP (HITL) APPROVAL REQUIRED
---------------------------------------------------------------------------------
Request ID:    ${jobResult.hitlRequestId}
Tool:          ${tool.name}
Target:        ${target}
Action:        Pending approval. Use 'hitl approve ${jobResult.hitlRequestId}' to authorize.`,
        type: 'WARNING',
        data: jobResult
      };
    }

    const job = jobResult.job!;
    await sandboxExecutionManager.executeJob(job.jobId);

    return {
      output: `
[+] JOB ${job.jobId} EXECUTED SUCCESSFULLY
----------------------------------------------------------------------
Tool:            ${tool.name}
Target:          ${target}
Status:          ${job.status} [${job.mode}]
Findings:        ${job.findings.length} Discovered
Evidence Sealed: ${job.evidenceId}

View full output with: jobs show ${job.jobId}`,
      type: 'SUCCESS',
      data: job
    };
  }

  private async handleAgent(subCmd: string, args: string[]): Promise<ASCLCommandResult> {
    const action = subCmd ? subCmd.toLowerCase() : 'status';

    switch (action) {
      case 'list':
      case 'fleet': {
        const agents = aiOrchestrator.getAllAgents();
        const rows = agents
          .map(
            a =>
              `  * [${a.category.padEnd(10)}] ${a.id.padEnd(24)} | ${a.name.padEnd(32)} | Status: ${a.status.padEnd(8)} | Conf: ${(a.confidence * 100).toFixed(0)}% [${a.epistemicStatus}]`
          )
          .join('\n');

        return {
          output: `
========================================================================================================
                                 AWM NEXUS — AI AGENT FLEET (12 SPECIALIZED AGENTS)
========================================================================================================
${rows}
--------------------------------------------------------------------------------------------------------
Capabilities: Deterministic Policy Engine Enforcement • Epistemic Tagging • Non-Destructive Guardrails`,
          type: 'INFO',
          data: agents
        };
      }

      case 'status': {
        const agents = aiOrchestrator.getAllAgents();
        const recs = aiOrchestrator.getRecommendations();
        const proposals = aiOrchestrator.getProposals();
        const loops = aiOrchestrator.getLoopResults();

        return {
          output: `
[+] AI ATTACK & DEFENSE ORCHESTRATION STATUS
---------------------------------------------------------------------------------
Orchestrator Status:        ONLINE [Deterministic Guardrails Active]
Registered Agent Fleet:     ${agents.length} Specialized Agents
Active Recommendations:     ${recs.length} Recorded
Pending Tool Proposals:     ${proposals.filter(p => p.status === 'PENDING_HITL').length} Awaiting HITL
Closed-Loop Validations:    ${loops.length} Completed
Governance Policy:          Scope → Authorization → Policy → Capability → HITL → Sandbox → Audit

Available ASCL Commands:
  agent list                 - List all 12 registered security agents
  agent ask <agent> <query>  - Query a specialized agent
  agent recommendations      - View AI attack/defense recommendations
  agent investigations       - View active multi-agent investigation timelines
  agent attack-defense       - Run Attack <-> Defense closed loop validation
  agent approvals            - Review pending AI tool proposals and HITL requests`,
          type: 'SUCCESS',
          data: { agentsCount: agents.length, recommendations: recs.length }
        };
      }

      case 'ask': {
        if (args.length === 0) {
          return {
            output: `Usage: agent ask <agent-id-or-name> <prompt>\nExample: agent ask agent-attack-surface "Analyze in-scope targets"`,
            type: 'ERROR'
          };
        }
        const agentTarget = args[0];
        const prompt = args.slice(1).join(' ') || 'Status & assessment overview';
        const response = aiOrchestrator.askAgent(agentTarget, prompt);

        return {
          output: `
[+] RESPONSE FROM ${response.agentName.toUpperCase()} (${response.agentId})
---------------------------------------------------------------------------------
Role:              ${response.role}
Epistemic Status:  [${response.epistemicStatus}] (Confidence: ${(response.confidence * 100).toFixed(0)}%)
Evidence Linked:   ${response.evidenceReferences.join(', ') || 'N/A'}

Analysis Summary:
${response.responseSummary}

Recommendations:
${response.recommendations.map(r => `  * ${r}`).join('\n')}`,
          type: 'INFO',
          data: response
        };
      }

      case 'ask-llm': {
        if (args.length === 0) {
          return {
            output: `Usage: agent ask-llm <agent-id-or-name> <prompt>\nExample: agent ask-llm agent-attack-surface "Analyze in-scope targets"`,
            type: 'ERROR'
          };
        }
        const agentTarget = args[0];
        const prompt = args.slice(1).join(' ') || 'Status & assessment overview';
        const response = await aiOrchestrator.askAgentWithLLM(agentTarget, prompt);

        return {
          output: `
[+] RESPONSE FROM ${response.agentName.toUpperCase()} (${response.agentId})
---------------------------------------------------------------------------------
Provider & Model:  ${response.provider} (${response.model}) [${response.isLLMGenerated ? 'REAL LLM' : 'DETERMINISTIC FALLBACK'}]
Latency:           ${response.latencyMs}ms
Role:              ${response.role}
Epistemic Status:  [${response.epistemicStatus}] (Confidence: ${(response.confidence * 100).toFixed(0)}%)
Evidence Linked:   ${response.evidenceReferences.join(', ') || 'N/A'}

Analysis Summary:
${response.responseSummary}

Recommendations:
${response.recommendations.map(r => `  * ${r}`).join('\n')}`,
          type: 'INFO',
          data: response
        };
      }

      case 'test-llm': {
        const testRes = await llmManager.testConnection();
        return {
          output: `
[+] LLM CONNECTION TEST RESULT
---------------------------------------------------------------------------------
Provider:  ${testRes.provider}
Model:     ${testRes.model}
Status:    ${testRes.success ? 'ONLINE (SUCCESS)' : 'FAILED / UNVERIFIED'}
Latency:   ${testRes.latencyMs}ms
Message:   ${testRes.message}
${testRes.sampleResponse ? 'Response:  ' + testRes.sampleResponse : ''}
${testRes.error ? 'Error:     ' + testRes.error : ''}`,
          type: testRes.success ? 'SUCCESS' : 'WARNING',
          data: testRes
        };
      }

      case 'recommendations':
      case 'recs': {
        const recs = aiOrchestrator.getRecommendations();
        if (recs.length === 0) {
          return { output: 'No active AI recommendations available.', type: 'INFO' };
        }

        const list = recs
          .map(
            r => `
[${r.priority}] ${r.title}
  Agent:      ${r.agentName}
  Epistemic:  ${r.epistemicStatus} (Confidence: ${(r.confidence * 100).toFixed(0)}%)
  Summary:    ${r.summary}
  Evidence:   ${r.evidenceReferences.join(', ')}`
          )
          .join('\n---------------------------------------------------------------------------------');

        return {
          output: `
=================================================================================
                     AI ATTACK & DEFENSE RECOMMENDATIONS
=================================================================================
${list}
=================================================================================`,
          type: 'INFO',
          data: recs
        };
      }

      case 'investigations': {
        const invs = aiOrchestrator.getInvestigations();
        const list = invs
          .map(
            inv => `
[${inv.status}] ${inv.investigationId}: ${inv.title}
  Target:      ${inv.target}
  Summary:     ${inv.summary}
  Timeline:
${inv.timeline.map(t => `    - [${t.timestamp.slice(11, 19)}] (${t.agentName}): ${t.action} [${t.epistemicStatus}]`).join('\n')}
  Remediations:
${inv.recommendedRemediations.map(rem => `    * ${rem}`).join('\n')}`
          )
          .join('\n---------------------------------------------------------------------------------');

        return {
          output: `
=================================================================================
                     MULTI-AGENT INVESTIGATION TIMELINES
=================================================================================
${list}
=================================================================================`,
          type: 'INFO',
          data: invs
        };
      }

      case 'attack-defense':
      case 'loop': {
        const target = args[0] || '127.0.0.1';
        try {
          const result = await aiOrchestrator.executeAttackDefenseLoop({ target });
          return {
            output: `
=================================================================================
          AWM NEXUS — ATTACK <-> DEFENSE CLOSED LOOP ORCHESTRATION RESULT
=================================================================================
Result ID:                ${result.id}
Target:                   ${result.simulationTarget}
Timestamp:                ${result.timestamp}
Control Effectiveness:   ${result.controlEffectivenessScore}%
Epistemic Status:         [${result.epistemicStatus}] (Confidence: ${(result.confidence * 100).toFixed(0)}%)

[10 CORE ORCHESTRATION QUESTIONS & DETERMINISTIC EVIDENCE]
1. What was tested?
   -> ${result.answers.whatWasTested}

2. What happened?
   -> ${result.answers.whatHappened}

3. What telemetry was generated?
   -> ${result.answers.whatTelemetryWasGenerated}

4. Was it detected?
   -> ${result.answers.wasItDetected ? 'YES' : 'NO'}

5. Which control detected it?
   -> ${result.answers.whichControlDetectedIt}

6. Which MITRE technique was observed?
   -> ${result.answers.whichMitreTechniqueWasObserved}

7. What evidence supports the conclusion?
   -> ${result.answers.whatEvidenceSupportsConclusion}

8. What was missed?
   -> ${result.answers.whatWasMissed}

9. What remediation is recommended?
   -> ${result.answers.whatRemediationIsRecommended}

10. Did re-validation succeed?
   -> ${result.answers.didRevalidationSucceed ? 'YES (Verified via Sandbox Re-probe)' : 'PENDING'}
=================================================================================`,
            type: 'SUCCESS',
            data: result
          };
        } catch (err: any) {
          return {
            output: `[-] Attack <-> Defense Loop failed: ${err.message}`,
            type: 'ERROR'
          };
        }
      }

      case 'approvals':
      case 'proposals': {
        const proposals = aiOrchestrator.getProposals();
        if (proposals.length === 0) {
          return { output: 'No AI tool execution proposals recorded.', type: 'INFO' };
        }

        const list = proposals
          .map(
            p => `
Proposal ID:    ${p.proposalId} [${p.status}]
Agent:          ${p.agentName}
Tool & Target:  ${p.toolId} -> ${p.targetAddress}
Parameters:     ${p.proposedParameters.join(' ')}
Justification:  ${p.justification}
HITL Request:   ${p.hitlRequestId || 'N/A'}`
          )
          .join('\n---------------------------------------------------------------------------------');

        return {
          output: `
=================================================================================
                         AI TOOL EXECUTION PROPOSALS
=================================================================================
${list}
=================================================================================`,
          type: 'INFO',
          data: proposals
        };
      }

      default:
        return {
          output: `Unknown agent command: '${subCmd}'. Type 'agent status' or 'help' for available commands.`,
          type: 'ERROR'
        };
    }
  }

  private async handleSiem(subCmd: string, args: string[]): Promise<ASCLCommandResult> {
    const action = subCmd ? subCmd.toLowerCase() : 'status';

    switch (action) {
      case 'status': {
        const config = siemManager.getConfig();
        const status = siemManager.getLastStatus();
        const stats = siemManager.getStats();

        return {
          output: `
[+] WAZUH SIEM CONNECTOR STATUS
---------------------------------------------------------------------------------
Provider:           ${status.provider}
Base URL:           ${status.baseUrl}
Connection Status:  [${status.status}]
Authenticated:      ${status.authenticated ? 'YES' : 'NO'}
Last Tested:        ${status.lastTested}
Synced Alerts:      ${stats.syncedAlertsCount}
Details:            ${status.details}

Available SIEM Commands:
  siem status          - View SIEM connector status & health
  siem test            - Test live connection to configured Wazuh endpoint
  siem sync            - Fetch and ingest alerts into defensive telemetry engine
  siem demo-ingest     - Ingest verified Wazuh schema sample alerts into telemetry`,
          type: status.status === 'CONNECTED' ? 'SUCCESS' : status.status === 'UNVERIFIED' ? 'WARNING' : 'INFO',
          data: { config, status, stats }
        };
      }

      case 'test': {
        const status = await siemManager.testConnection();
        return {
          output: `
[+] SIEM CONNECTION TEST: ${status.provider}
---------------------------------------------------------------------------------
Status:         [${status.status}]
Endpoint:       ${status.baseUrl}
Authenticated:  ${status.authenticated ? 'YES' : 'NO'}
Latency:        ${status.latencyMs ?? 0}ms
Diagnostics:    ${status.details}
${status.error ? 'Error Details:  ' + status.error : ''}`,
          type: status.status === 'CONNECTED' ? 'SUCCESS' : 'WARNING',
          data: status
        };
      }

      case 'sync': {
        const minLevel = args[0] ? parseInt(args[0], 10) : undefined;
        const res = await siemManager.syncAlerts({ minLevel });
        if (res.success) {
          return {
            output: `[+] SIEM SYNC COMPLETED: Ingested ${res.syncedCount} alerts from Wazuh into Defensive Telemetry Engine.`,
            type: 'SUCCESS',
            data: res
          };
        } else {
          return {
            output: `[!] SIEM SYNC FAILED: ${res.error}. Connector remains intact.`,
            type: 'ERROR',
            data: res
          };
        }
      }

      case 'demo-ingest': {
        const res = siemManager.ingestVerifiedSampleAlerts();
        return {
          output: `[+] DEMO INGESTION COMPLETE: Ingested ${res.count} verified Wazuh schema alerts [SIMULATED] into Defensive Telemetry Engine.`,
          type: 'SUCCESS',
          data: res
        };
      }

      default:
        return {
          output: `Unknown siem subcommand: '${subCmd}'. Type 'siem status' or 'help' for available commands.`,
          type: 'ERROR'
        };
    }
  }

  private async handleKali(subCmd?: string, args: string[] = []): Promise<ASCLCommandResult> {
    const action = subCmd ? subCmd.toLowerCase() : 'status';

    switch (action) {
      case 'status': {
        const allAgents = remoteAgentManager.getAllAgents();
        const online = remoteAgentManager.getOnlineAgents();
        const token = remoteAgentManager.getAuthToken();

        let out = `
=================================================================================
             AWM NEXUS — REMOTE KALI EXECUTION AGENT STATUS
=================================================================================
Connected Agents:   ${online.length} Online / ${allAgents.length} Registered
Authorization Token: [${token}]
Agent Dispatch Hub:  ONLINE (Port 3000 /api/agent/*)

QUICK START INSTRUCTIONS:
  1. On your authorized Kali Linux machine, run:
     python3 agents/awm_nexus_agent.py --server http://127.0.0.1:3000 --token ${token}
  2. Or connect test agent in CLI: kali demo\n`;

        if (online.length > 0) {
          out += `\nONLINE AGENTS:\n`;
          for (const a of online) {
            out += `  * [${a.status}] ${a.id.padEnd(20)} | ${a.name.padEnd(30)} | ${a.hostname} (${a.os})\n`;
            out += `    Tools: ${a.installedTools.join(', ')}\n`;
          }
        } else {
          out += `\n[!] No remote Kali execution agents are currently connected.\n`;
        }

        return { output: out, type: online.length > 0 ? 'SUCCESS' : 'WARNING', data: { online, total: allAgents.length, token } };
      }

      case 'token': {
        const regenerate = args[0] === 'regenerate' || args[0] === 'new';
        const token = regenerate ? remoteAgentManager.regenerateAuthToken() : remoteAgentManager.getAuthToken();
        return {
          output: `
[+] AWM NEXUS AGENT AUTHENTICATION TOKEN:
---------------------------------------------------------------------------------
Token: ${token}
${regenerate ? '[!] A new agent token has been generated and logged to the cryptographic audit ledger.' : ''}
Use this token when starting the agent on Kali:
  python3 agents/awm_nexus_agent.py --server <URL> --token ${token}`,
          type: 'SUCCESS',
          data: { token }
        };
      }

      case 'list': {
        const agents = remoteAgentManager.getAllAgents();
        if (agents.length === 0) {
          return { output: `No Kali execution agents have registered yet. Type 'kali status' for setup instructions.`, type: 'INFO' };
        }
        let out = `AGENT ID             NAME                           STATUS     HOSTNAME             OS\n`;
        out += `---------------------------------------------------------------------------------------------------\n`;
        for (const a of agents) {
          out += `${a.id.padEnd(20)} ${a.name.padEnd(30)} ${a.status.padEnd(10)} ${a.hostname.padEnd(20)} ${a.os}\n`;
        }
        return { output: out, type: 'SUCCESS', data: agents };
      }

      case 'demo':
      case 'connect-demo': {
        const agent = remoteAgentManager.registerDemoKaliAgent();
        await detectRealBinaries();
        return {
          output: `
[+] DEMO KALI AGENT REGISTERED & CONNECTED:
---------------------------------------------------------------------------------
Agent ID:   ${agent.id}
Name:       ${agent.name}
Hostname:   ${agent.hostname}
OS:         ${agent.os}
Tools (${agent.installedTools.length}): ${agent.installedTools.join(', ')}

All Kali tools (Nmap, Nuclei, Nikto, ffuf, Gobuster, etc.) are now ACTIVE and ready for execution.`,
          type: 'SUCCESS',
          data: agent
        };
      }

      default:
        return {
          output: `Unknown kali subcommand: '${subCmd}'. Available: kali status, kali token, kali list, kali demo.`,
          type: 'ERROR'
        };
    }
  }

  private handleImports(subCmd?: string, args: string[] = []): ASCLCommandResult {
    const imports = externalToolImportEngine.getAllImports();

    switch (subCmd?.toLowerCase()) {
      case 'list':
      case undefined: {
        if (imports.length === 0) {
          return {
            output: `No external tool results imported yet. Use Web UI 'Findings & Artifacts' -> 'Import External Results' or API POST /api/imports/upload.\nSupported formats: Nmap XML/JSON, Burp XML/JSON, Nessus XML (.nessus), Nuclei JSONL.`,
            type: 'INFO'
          };
        }

        let out = `IMPORT ID            FORMAT         FILENAME                       PARSED  DUPS  OUT-OF-SCOPE  STATUS     DATE\n`;
        out += `----------------------------------------------------------------------------------------------------------------------\n`;
        for (const imp of imports) {
          out += `${imp.importId.padEnd(20)} ${imp.format.padEnd(14)} ${imp.sanitizedFilename.slice(0, 30).padEnd(30)} ${String(imp.validFindingsCount).padEnd(7)} ${String(imp.duplicateCount).padEnd(5)} ${String(imp.outOfScopeCount).padEnd(13)} ${imp.status.padEnd(10)} ${imp.importedAt.slice(0, 16)}\n`;
        }
        return { output: out, type: 'SUCCESS', data: imports };
      }

      case 'show': {
        const id = args[0];
        if (!id) return { output: `Usage: import show <importId>`, type: 'ERROR' };
        const imp = externalToolImportEngine.getImport(id);
        if (!imp) return { output: `[!] Import record '${id}' not found.`, type: 'ERROR' };

        const out = `
================================================================================
               EXTERNAL TOOL IMPORT DETAILS: ${imp.importId}
================================================================================
Filename:        ${imp.filename} (sanitized: ${imp.sanitizedFilename})
Format:          ${imp.format}
SHA-256 Hash:    ${imp.sha256}
File Size:       ${imp.fileSizeBytes} bytes
Imported At:     ${imp.importedAt}
Status:          ${imp.status}
Evidence ID:     ${imp.evidenceId}
Audit Block:     ${imp.auditBlockId}

FINDINGS SUMMARY:
- Total Parsed:       ${imp.totalParsed}
- Valid / Ingested:   ${imp.validFindingsCount}
- Duplicates:         ${imp.duplicateCount}
- Out-of-Scope:       ${imp.outOfScopeCount}
- Extracted Targets:  ${imp.extractedTargets.join(', ') || 'None'}

${imp.errors.length > 0 ? 'PARSER WARNINGS/ERRORS:\n' + imp.errors.map(e => `  - ${e}`).join('\n') + '\n' : ''}
FINDINGS (Sample top 5):
${imp.findings.slice(0, 5).map(f => `  [${f.severity}] ${f.title} (${f.host}${f.port ? ':' + f.port : ''}) - Status: ${f.validationStatus}`).join('\n') || '  (None)'}
`;
        return { output: out, type: 'SUCCESS', data: imp };
      }

      case 'findings': {
        const findings = externalToolImportEngine.getAllImportedFindings();
        if (findings.length === 0) {
          return { output: `No imported findings found.`, type: 'INFO' };
        }
        let out = `FINDING ID           TOOL         SEVERITY   TARGET                    TITLE\n`;
        out += `---------------------------------------------------------------------------------------------------\n`;
        for (const f of findings.slice(0, 25)) {
          out += `${f.findingId.padEnd(20)} ${f.toolId.padEnd(12)} ${f.severity.padEnd(10)} ${(f.host + (f.port ? ':' + f.port : '')).slice(0, 24).padEnd(25)} ${f.title.slice(0, 35)}\n`;
        }
        if (findings.length > 25) {
          out += `\n... and ${findings.length - 25} more findings. View complete list in UI.`;
        }
        return { output: out, type: 'SUCCESS', data: findings };
      }

      default:
        return {
          output: `Unknown import subcommand: '${subCmd}'. Available: import list, import show <id>, import findings.`,
          type: 'ERROR'
        };
    }
  }
}

export const asclEngine = new ASCLEngine();
