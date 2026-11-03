# AWM NEXUS — Multi-Stage Penetration Testing & Autonomous Assessment Workflow Engine
## Revised Implementation Plan & Architecture Specification

---

### A. Current Architecture Audit & Verified Functionality

After direct inspection of the codebase, runtime environment, and test suites, the operational state of AWM NEXUS is confirmed as follows:

1. **Tool Registry (`src/engine/toolRegistry.ts`)**:
   - 26 security tools registered across 10 categories (`RECON`, `WEB_ENUM`, `WEB_API`, `VULNERABILITY`, `NETWORK`, `DNS_TLS`, `CLOUD`, `KUBERNETES`, `PASSWORD_HASH`, `CONTROLLED_VAL`).
   - Profile parameter builders enforce strict flag whitelisting, prohibited flag blacklisting, and prevent flag/target duplication.
2. **Dedicated Linux Worker (`src/server/linuxWorkerManager.ts`)**:
   - Manages native subprocesses via `child_process.spawn()` with validated argument arrays (zero shell concatenation).
   - Real binary path resolution (`resolveBinaryPath()`) checks `/app/applet/bin` first, followed by system `PATH` (`/usr/bin`, `/bin`, etc.).
   - Verified active binaries on local worker: `/usr/bin/nmap`, `/usr/bin/whois`, `/usr/bin/whatweb`, `/usr/bin/curl`, `/usr/bin/openssl`, `/app/applet/bin/feroxbuster`, `/app/applet/bin/ffuf`, `/app/applet/bin/gobuster`, `/app/applet/bin/subfinder`, `/app/applet/bin/dnsx`.
3. **Remote Kali Linux Agent Hub (`src/server/agentManager.ts`)**:
   - Supports authenticated remote Kali Linux workers with streaming STDOUT/STDERR, heartbeat monitoring, and token-based authentication (`nexus-kali-token-live-2026`).
4. **Execution Pipeline & Sandbox (`src/engine/sandboxExecution.ts`)**:
   - `createJob()` creates `PentestJob` instances, validates argument safety, checks scope, evaluates HITL policy, and creates jobs in `QUEUED` state.
   - `executeJob()` routes execution to `RemoteAgentManager` if a live agent is assigned, or to `LinuxWorkerManager` for live local execution.
   - Captures unbuffered stdout/stderr, execution duration, exit code, and emits status events.
   - **Critical verification**: `nmap` execution against `127.0.0.1` runs the authentic `/usr/bin/nmap` binary with `-sT` Connect scanning, producing genuine provenance `LIVE_LOCAL` and exit code 0.
5. **Scope & Authorization Engine (`src/engine/scopeEngine.ts`)**:
   - Default engagement `eng-2026-001` (`ENG-2026-ALPHA`) covers client `AWM Defense Corp` (`TENANT-AWM-01`).
   - Includes authorized targets: `127.0.0.1` (`target-01`, ports 80, 443, 3000), `localhost`, `10.0.100.0/24`, `192.168.1.50`, `*.nexus-staging.internal`.
   - Excludes critical assets: `10.0.0.1` (Domain Controller), `payment-gateway.internal` (PCI-DSS core), `10.0.0.0/24`.
   - Method `validateTarget(engagementId, targetAddress, operatorRole, requestedTier, toolRequiresHITL)` rigorously checks CIDR, domain matching, temporal bounds, and role permissions.
6. **Policy Engine & HITL Gate (`src/engine/policyAndHitlEngine.ts`)**:
   - Evaluates `requiresHITL` based on tool profile flags, `CONTROLLED_EXPLOIT` capability tier, production environments, and aggressive packet rates.
   - Manages approval lifecycle: `createApprovalRequest()`, `approveRequest()`, `rejectRequest()`.
7. **Risk Engine & Evidence Locker (`src/engine/riskAndEvidenceEngine.ts`)**:
   - `evidenceEngine.sealEvidenceRecord()` generates cryptographic SHA-256 signatures over stdout, stderr, and execution metadata, creating an immutable `EvidenceRecord`.
   - `riskEngine.calculateRiskScore()` produces weighted CVSS risk metrics.
8. **Audit Ledger (`src/engine/auditLedger.ts`)**:
   - Cryptographically linked SHA-256 blockchain (`AuditBlock`) with `verifyChainIntegrity()`.
9. **Result Parser (`src/engine/findingParser.ts`)**:
   - Parses raw tool stdout into `NormalizedFinding[]` (for curl, openssl, nmap, nuclei, ffuf, gobuster, dig).
   - *Current limitation to address*: Does not yet parse structured service records (`DiscoveredService`) or support multi-stage correlation.
10. **Test Suite Status**:
   - All 94 test assertions in `tests/runAllTests.ts` (`src/tests/testSuite.ts`) currently pass (0 failures).

---

### B. Exact Files to Create and Modify (With Reasons)

#### 1. Files to CREATE

1. **`src/engine/workflowOrchestrator.ts`**
   - *Reason*: Houses the core 10-stage autonomous assessment state machine, tracks workflow sessions, manages parent-child job lineage, and implements the service-to-next-step recommendation logic.
   - *No Duplicate Pipeline*: Does not execute jobs directly; calls existing `sandboxExecutionManager.createJob()` and `executeJob()`.
2. **`src/components/AutonomousWorkflowView.tsx`**
   - *Reason*: Provides a dedicated console for the operator to monitor the 10 assessment stages, inspect the discovered service & technology inventory, review/approve/reject proposed follow-up tasks, view the execution dependency graph, and observe the live validation taxonomy.
3. **`src/tests/workflowOrchestratorTests.ts`**
   - *Reason*: Isolated test suite validating the 10-stage progression, structured service dissection, context-aware task proposals, worker availability filtering, scope revalidation, and HITL gate enforcement.

#### 2. Files to MODIFY

1. **`src/types/index.ts`**
   - *Reason*: Add domain interfaces for multi-stage workflow:
     - `AssessmentStage`: The 10 discrete methodology stages.
     - `DiscoveredService`: Structured port, protocol, service, version, banner, and probe latency.
     - `DiscoveredTechnology`: Web framework, server, CMS, language identified on a target.
     - `WorkflowTask`: Proposed/queued follow-up task with parentage, required tool, proposed parameters, stage, approval status, and justification.
     - `WorkflowSession`: State of a multi-stage assessment session (target, current stage, depth, max depth, max jobs, history).
     - Update `NormalizedFinding`: Ensure strict `validationStatus: 'CONFIRMED' | 'POTENTIAL' | 'FALSE_POSITIVE' | 'NOT_VERIFIED'`.
2. **`src/engine/findingParser.ts`**
   - *Reason*: Implement the `Structured Service & Banner Dissector`. Add methods:
     - `extractDiscoveredServices(tool, target, stdout)`: Extracts all open ports, service names, and version strings (e.g. `3000/tcp open http Node.js Express/Vite`).
     - `extractTechnologies(tool, target, stdout)`: Extracts web technologies from `whatweb` / `curl` banners.
     - Update vulnerability parser to enforce the 4-tier validation taxonomy (preventing banner matches alone from becoming `CONFIRMED`).
3. **`src/engine/sandboxExecution.ts`**
   - *Reason*: Add parent-job metadata (`parentJobId`, `workflowSessionId`, `depth`) to `PentestJob`.
   - Add completion hook/event listener so completed jobs notify the `workflowOrchestrator` without polling.
4. **`src/components/PentestSidebar.tsx` & `src/App.tsx`**
   - *Reason*: Add the "Autonomous Workflow" navigation tab under the `OFFENSIVE & PENTEST` section in the sidebar with active stage indicator.
5. **`src/components/AttackSurfaceView.tsx`**
   - *Reason*: Display discovered services and technologies dynamically fed by the multi-stage workflow engine.
6. **`src/components/ReportGeneratorView.tsx`**
   - *Reason*: Add the Multi-Stage Assessment section to executive & technical reports, summarizing the 10-stage execution trail, discovered assets, validation status counts, and cryptographic evidence hashes.
7. **`src/tests/testSuite.ts` & `tests/runAllTests.ts`**
   - *Reason*: Register and execute the new `workflowOrchestratorTests.ts` suite.

---

### C. Existing Functions & Interfaces to Reuse

The workflow engine will strictly reuse verified existing components:
- **Process Spawning**: `linuxWorkerManager.executeProcess(jobId, binaryName, args, options)` — uses real native binaries with PID, exit codes, unbuffered stdout/stderr.
- **Binary Resolution**: `linuxWorkerManager.resolveBinaryPath(binaryName)` — checks persistent `/app/applet/bin` and system paths.
- **Remote Agent Dispatch**: `remoteAgentManager.getAgentForTool(toolId)`, `dispatchJob()`, `getConnectedAgents()`.
- **Tool Definitions & Validation**: `toolRegistry.getTool(toolId)`, `toolRegistry.validateParameters(tool, profile, args)`.
- **Scope Verification**: `scopeEngine.validateTarget(engagementId, targetAddress, operatorRole, requestedTier, toolRequiresHITL)` and `scopeEngine.validateTargetScope(engagement, target)`.
- **Safety & HITL**: `policyAndHitlEngine.evaluatePolicy()`, `createApprovalRequest()`, `approveRequest()`, `rejectRequest()`.
- **Job Creation & Execution**: `sandboxExecutionManager.createJob()` and `sandboxExecutionManager.executeJob()`.
- **Evidence Sealing**: `evidenceEngine.sealEvidenceRecord()` — creates immutable SHA-256 evidence blocks.
- **Audit Logging**: `auditLedger.recordAction()` — records every stage transition, proposed task, operator decision, and execution in the tamper-evident hash chain.
- **Cryptographic Hashing**: `syncSha256(data)`.

---

### D. Proposed Workflow Data Model & Event Flow

#### 1. Workflow Data Model (`src/types/index.ts`)
```typescript
export type AssessmentStage =
  | 'INITIAL_RECONNAISSANCE'
  | 'ASSET_DISCOVERY'
  | 'PORT_DISCOVERY'
  | 'SERVICE_IDENTIFICATION'
  | 'TECHNOLOGY_ENUMERATION'
  | 'VULNERABILITY_ASSESSMENT'
  | 'EVIDENCE_VALIDATION'
  | 'RISK_ANALYSIS'
  | 'ATTACK_PATH_ANALYSIS'
  | 'REPORTING';

export type ValidationStatus =
  | 'CONFIRMED'       // Supported by verifiable positive evidence
  | 'POTENTIAL'       // Indicator/version match requiring validation
  | 'FALSE_POSITIVE'  // Secondary validation contradicted or disproved
  | 'NOT_VERIFIED';   // Inconclusive / insufficient evidence

export interface DiscoveredService {
  id: string;
  target: string;
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'filtered' | 'closed';
  serviceName: string;
  product?: string;
  version?: string;
  banner?: string;
  cpe?: string;
  discoveredByJobId: string;
  discoveredAt: string;
}

export interface DiscoveredTechnology {
  name: string;
  category: 'FRAMEWORK' | 'SERVER' | 'LANGUAGE' | 'CMS' | 'LIBRARY' | 'SECURITY';
  version?: string;
  confidence: number;
  evidence: string;
  sourceJobId: string;
}

export interface WorkflowTask {
  taskId: string;
  sessionId: string;
  parentJobId?: string;
  stage: AssessmentStage;
  target: string;
  toolId: string;
  profileId: string;
  parameters: string[];
  justification: string;
  status: 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  requiresHITL: boolean;
  hitlRequestId?: string;
  executionJobId?: string;
  createdTime: string;
  decidedTime?: string;
  workerType: 'LOCAL_LINUX_WORKER' | 'KALI_AGENT';
  depth: number;
}

export interface WorkflowSession {
  sessionId: string;
  engagementId: string;
  tenantId: string;
  operatorId: string;
  targetAddress: string;
  currentStage: AssessmentStage;
  stageProgress: Record<AssessmentStage, { status: 'PENDING' | 'ACTIVE' | 'COMPLETED' | 'SKIPPED'; startedAt?: string; completedAt?: string }>;
  maxDepth: number;          // Default: 4
  maxJobs: number;           // Default: 10
  currentJobCount: number;
  discoveredServices: DiscoveredService[];
  discoveredTechnologies: DiscoveredTechnology[];
  tasks: WorkflowTask[];
  findings: NormalizedFinding[];
  status: 'ACTIVE' | 'PAUSED' | 'COMPLETED' | 'CANCELLED';
  createdAt: string;
  updatedAt: string;
}
```

#### 2. Event Flow & State Transitions
1. **Initiation**: Operator selects in-scope target (`127.0.0.1`) and starts assessment session. Session initializes at `PORT_DISCOVERY` (or `INITIAL_RECONNAISSANCE`).
2. **Initial Job Execution**: Nmap TCP Connect scan (`-sT -sV -T3 -Pn 127.0.0.1`) is dispatched via existing `sandboxExecutionManager.executeJob()`.
3. **Output Dissection**: Upon job completion, `findingParser.extractDiscoveredServices()` parses stdout lines (`PORT STATE SERVICE VERSION`). For example:
   - `3000/tcp open http-applet-dev Node.js / Vite`
4. **Context-Aware Follow-Up Generation**:
   - `workflowOrchestrator` correlates `3000/tcp (HTTP)`:
     - Task 1: `whatweb` for technology enumeration (`whatweb -v -a 1 http://127.0.0.1:3000`).
     - Task 2: `curl` for HTTP response & security header analysis (`curl -i -s -k -m 10 http://127.0.0.1:3000`).
   - For each candidate task, the engine verifies:
     - [x] Binary available? Checks `linuxWorkerManager.resolveBinaryPath('whatweb')` and `'curl'`.
     - [x] Scope check? Calls `scopeEngine.validateTarget('eng-2026-001', '127.0.0.1', 'LEAD_SECURITY_ENGINEER', 'NON_DESTRUCTIVE_SCAN')`.
     - [x] Exclusions? Verifies target is not in excluded rules.
     - [x] Max depth & job limit? Verifies `currentJobCount < maxJobs` and `depth <= maxDepth`.
     - [x] HITL policy? Evaluates `policyAndHitlEngine.evaluatePolicy()`.
5. **Operator Gate**:
   - Proposed tasks appear in `AutonomousWorkflowView` with full justification, tool binary, arguments, and required approval status.
   - Operator reviews and clicks "Approve & Execute" or "Reject".
6. **Real Pipeline Execution**:
   - Approved task is dispatched through `sandboxExecutionManager.createJob()` and `executeJob()`.
   - Runs on local Linux worker, streaming STDOUT in real time, capturing PID, duration, and exit code.
   - Seals cryptographic SHA-256 evidence record and logs audit block.
7. **Validation & Stage Progression**:
   - `curl` output shows missing `Content-Security-Policy` and `Strict-Transport-Security`. Finding is marked `CONFIRMED` because actual response headers lack these controls.
   - If version banner indicates a software version with an alleged CVE, it is marked `POTENTIAL` until active verification confirms exploitable behavior.
   - Workflow transitions through `VULNERABILITY_ASSESSMENT` → `EVIDENCE_VALIDATION` → `RISK_ANALYSIS` → `ATTACK_PATH_ANALYSIS` → `REPORTING`.
8. **Final Deliverable**: Operator navigates to `ReportGeneratorView` to export the comprehensive penetration testing report containing verified evidence hashes and audit block chain.

---

### E. Implementation Phases & Dependencies

```
Phase 1: Types & Core Contracts ──► Phase 2: Dissector in findingParser
                                            │
Phase 4: UI Console ◄── Phase 3: Workflow Orchestrator Engine
         │
         ▼
Phase 5: Report Integration & Test Suite ──► Phase 6: Localhost Live Demonstration
```

- **Phase 1: Domain Contracts & Taxonomy (`src/types/index.ts`)**
  - Define `AssessmentStage`, `DiscoveredService`, `DiscoveredTechnology`, `WorkflowTask`, `WorkflowSession`, and 4-tier `ValidationStatus`.
  - Add lineage properties (`parentJobId`, `workflowSessionId`, `depth`) to `PentestJob`.
  - *Zero breaking changes to existing types.*

- **Phase 2: Structured Service & Banner Dissector (`src/engine/findingParser.ts`)**
  - Implement `extractDiscoveredServices()` for Nmap and generic tool outputs.
  - Implement `extractTechnologies()` from web responses.
  - Update findings parser to enforce 4-tier taxonomy (`CONFIRMED`, `POTENTIAL`, `FALSE_POSITIVE`, `NOT_VERIFIED`).

- **Phase 3: Workflow Orchestration Engine (`src/engine/workflowOrchestrator.ts`)**
  - Implement `WorkflowOrchestrator` singleton.
  - Implement session lifecycle: `createSession()`, `getSession()`, `pauseSession()`, `cancelSession()`.
  - Implement `ingestCompletedJob()`: evaluates completed job, extracts services, advances stages.
  - Implement rule matrix: maps open services (HTTP, HTTPS, SSH, DNS, Database) to follow-up tool profiles.
  - Enforce worker availability, scope validation, depth limits, and HITL gate before proposing tasks.
  - Hook job completion events from `sandboxExecutionManager`.

- **Phase 4: Autonomous Assessment UI Console (`src/components/AutonomousWorkflowView.tsx`)**
  - 10-stage horizontal timeline with interactive status indicators.
  - Discovered services & technology inventory table.
  - Proposed tasks queue with "Approve & Execute", "Approve All", "Reject", and "Cancel".
  - Job dependency & lineage graph.
  - Add navigation item in `PentestSidebar.tsx` and route in `App.tsx`.

- **Phase 5: Report Integration & Verification Suite**
  - Update `ReportGeneratorView.tsx` with Multi-Stage Assessment section, stage timeline, service inventory, validation taxonomy metrics, and evidence block references.
  - Create `src/tests/workflowOrchestratorTests.ts`.
  - Register in `src/tests/testSuite.ts` and verify with `npm test` and `npm run build`.

- **Phase 6: Real Localhost Assessment Demonstration**
  - Launch real initial Nmap scan on `127.0.0.1`.
  - Demonstrate service dissection of active port 3000.
  - Demonstrate proposal of `whatweb` and `curl`.
  - Approve follow-up tasks and execute on real Linux worker.
  - Verify evidence sealing and validation taxonomy in the UI and report.

---

### F. Tests for Every Phase

1. **Phase 1 & 2 Tests (Dissector & Taxonomy)**:
   - Verify `extractDiscoveredServices()` correctly extracts port, protocol, service, and version from real Nmap output on `127.0.0.1`.
   - Verify version banners without exploit evidence are classified as `POTENTIAL`.
   - Verify absent security headers in verified curl output are classified as `CONFIRMED`.
2. **Phase 3 Tests (Orchestrator Logic & Guardrails)**:
   - Verify workflow initializes with 10 stages in proper initial state.
   - Verify Nmap HTTP discovery proposes `whatweb` and `curl`.
   - Verify availability filter rejects tools not found on worker (returns only installed tools).
   - Verify scope filter rejects out-of-scope targets (e.g., `10.0.0.1` DC is blocked).
   - Verify max depth and max jobs limits prevent unbounded task recursion.
   - Verify high-impact or active probes require HITL.
3. **Phase 4 & 5 Tests (Lineage & Audit)**:
   - Verify follow-up jobs record `parentJobId` and `sessionId`.
   - Verify every executed job produces a valid `EvidenceRecord` and `AuditBlock`.
   - Verify report generator extracts and displays multi-stage audit summary.
4. **Regression Guarantee**:
   - All 94 existing test assertions in `tests/runAllTests.ts` must continue to pass (100% pass rate).

---

### G. Risks, Compatibility Concerns & Rollback Strategy

1. **Risk: Breaking Existing Job Execution Flow**
   - *Mitigation*: The workflow orchestrator is strictly additive. `sandboxExecutionManager.createJob()` and `executeJob()` will keep their exact existing signatures and contracts. The orchestrator registers as a listener for job completion events without mutating existing execution paths.
2. **Risk: Uncontrolled Tool Proliferation (Runaway Loops)**
   - *Mitigation*: Hard limits enforced in code:
     - `maxDepth`: default 4 levels (e.g. Nmap -> WhatWeb -> Curl -> Done).
     - `maxJobs`: default 10 jobs per session.
     - Mandatory operator approval for all proposed tasks (or strict non-destructive auto-queue only when explicitly enabled by the operator).
3. **Risk: Out-of-Scope Leakage**
   - *Mitigation*: `scopeEngine.validateTarget()` is called before any task is created and again before execution. If a follow-up task points to an excluded IP or unauthorized port, it is immediately discarded with an audit log entry.
4. **Risk: Rollback Strategy**
   - All new state logic is encapsulated in `src/engine/workflowOrchestrator.ts` and `src/components/AutonomousWorkflowView.tsx`.
   - If needed, removing the sidebar navigation item in `PentestSidebar.tsx` and disconnecting the listener in `sandboxExecutionManager.ts` fully reverts the system to its prior state with zero data loss or side effects.

---

### H. Final Local Lab Demonstration Procedure (127.0.0.1)

1. **Pre-flight Status**:
   - Verify local Linux worker has `/usr/bin/nmap`, `/usr/bin/curl`, and `/usr/bin/whatweb` installed.
   - Target: `127.0.0.1` (In-scope target `target-01` under engagement `eng-2026-001`).
   - Active listener: Local Node.js / Vite web application running on port 3000.
2. **Step 1 — Start Assessment**:
   - In `AutonomousWorkflowView`, select target `127.0.0.1` and click **"Start Autonomous Assessment"**.
   - Session starts in `PORT_DISCOVERY` stage.
3. **Step 2 — Initial Scan Execution**:
   - Dispatches real Nmap scan: `/usr/bin/nmap -sT -sV --version-intensity 5 -T3 -Pn 127.0.0.1`.
   - Execution provenance displays `LIVE_LOCAL`, authentic PID, and unbuffered stdout.
4. **Step 3 — Structured Dissection**:
   - Dissector identifies `3000/tcp open http-applet-dev Node.js / Vite`.
   - Discovered service is registered in the session inventory.
   - Workflow advances to `SERVICE_IDENTIFICATION` and `TECHNOLOGY_ENUMERATION`.
5. **Step 4 — Follow-up Task Generation**:
   - Orchestrator checks tool availability (`whatweb` and `curl` are INSTALLED), re-validates scope (`127.0.0.1` is in scope), and proposes:
     - Task A: `whatweb -v -a 1 http://127.0.0.1:3000` (Technology Enumeration).
     - Task B: `curl -i -s -k -m 10 http://127.0.0.1:3000` (Security Headers Analysis).
6. **Step 5 — Operator Approval & Real Execution**:
   - Operator inspects proposed tasks and clicks **"Approve & Execute"**.
   - Tasks execute via `linuxWorkerManager.executeProcess()`.
   - Genuine output streams to the terminal with exit code 0.
7. **Step 6 — Vulnerability Validation & Evidence Sealing**:
   - Results show missing CSP and missing HSTS headers.
   - Classified as `CONFIRMED` based on direct response header evidence.
   - SHA-256 evidence records are sealed in the Evidence Locker.
   - Tamper-evident blocks are appended to the Audit Ledger.
8. **Step 7 — Technical & Executive Report**:
   - Operator views final report in `ReportGeneratorView`, showing the complete 10-stage methodology, asset inventory, confirmed findings, and cryptographic audit proofs.
