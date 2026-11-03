/**
 * AWM Nexus — Types & Data Contracts
 * Complete domain models for Human Pentest Tooling, ASCL, Scope, HITL, Sandbox, Audit & Telemetry
 */

export type ToolCategory =
  | 'RECON'
  | 'WEB_ENUM'
  | 'WEB_API'
  | 'VULNERABILITY'
  | 'NETWORK'
  | 'DNS_TLS'
  | 'CLOUD'
  | 'KUBERNETES'
  | 'PASSWORD_HASH'
  | 'CONTROLLED_VAL';

export type ToolAvailabilityStatus =
  | 'INSTALLED'
  | 'AVAILABLE'
  | 'NOT_INSTALLED'
  | 'NOT_CONFIGURED'
  | 'SIMULATED'
  | 'OFFLINE'
  | 'ERROR';

export type ToolExecutionMode = 'LIVE' | 'SIMULATED' | 'DRY_RUN';

export type ExecutionProvenance =
  | 'LIVE_LOCAL'
  | 'LIVE_AGENT'
  | 'CACHED'
  | 'SIMULATED'
  | 'UNAVAILABLE';

export type CapabilityTier =
  | 'RECON_READONLY'
  | 'NON_DESTRUCTIVE_SCAN'
  | 'ACTIVE_PROBE'
  | 'CONTROLLED_EXPLOIT';

export type JobStatus =
  | 'QUEUED'
  | 'VALIDATING'
  | 'APPROVAL_REQUIRED'
  | 'APPROVED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'TIMEOUT'
  | 'BLOCKED';

export type OperatorRole =
  | 'READONLY_ANALYST'
  | 'CERTIFIED_PENTESTER'
  | 'LEAD_SECURITY_ENGINEER'
  | 'SYSTEM_ADMIN';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type DetectionStatus = 'LIVE' | 'SIMULATED' | 'OFFLINE' | 'UNAVAILABLE';

export interface ToolProfile {
  id: string;
  name: string;
  description: string;
  capabilityTier: CapabilityTier;
  requiresHITL: boolean;
  hitlReason?: string;
  defaultFlags: string[];
  allowedFlags: string[];
  forbiddenFlags: string[];
  timeoutSeconds: number;
}

export interface SecurityTool {
  id: string;
  name: string;
  category: ToolCategory;
  binaryName: string;
  description: string;
  version?: string;
  availabilityStatus: ToolAvailabilityStatus;
  detectedPath?: string;
  capabilityTier: CapabilityTier;
  profiles: ToolProfile[];
  documentationUrl: string;
  installCommand?: string;
  installable: boolean;
  verificationCommand: string;
  isNativeBinary: boolean;
  lastChecked?: string;
}

export interface TargetAsset {
  id: string;
  name: string;
  type: 'HOST' | 'IP' | 'CIDR' | 'DOMAIN' | 'URL' | 'API_ENDPOINT' | 'CLOUD_ACCOUNT';
  address: string;
  ports: number[];
  environment: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT' | 'SANDBOX_LAB';
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  inScope: boolean;
  exclusionReason?: string;
  active: boolean;
  authorizedUntil: string;
}

export interface ScopeRule {
  ruleId: string;
  pattern: string;
  type: 'INCLUDE' | 'EXCLUDE';
  description: string;
  portsAllowed?: string;
}

export interface Engagement {
  id: string;
  code: string;
  name: string;
  clientName: string;
  tenantId: string;
  scopeRules: ScopeRule[];
  targets: TargetAsset[];
  startDate: string;
  endDate: string;
  allowedCapabilityTier: CapabilityTier;
  leadOperator: string;
  active: boolean;
}

export interface ScopeValidationResult {
  valid: boolean;
  inScope: boolean;
  excluded: boolean;
  reason: string;
  targetAddress: string;
  matchedRule?: string;
  capabilityPermitted: boolean;
  hitlRequired: boolean;
  hitlReason?: string;
}

export interface HITLApprovalRequest {
  requestId: string;
  jobId: string;
  toolId: string;
  toolName: string;
  targetAddress: string;
  profileName: string;
  parameters: string[];
  operatorId: string;
  riskLevel: Severity;
  reason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED';
  requestedAt: string;
  decidedAt?: string;
  approverId?: string;
  rejectionReason?: string;
  approvalToken?: string;
}

export interface ArtifactFile {
  filename: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  content: string;
}

export interface NormalizedFinding {
  findingId: string;
  jobId: string;
  toolId: string;
  sourceTool?: string;
  sourceFile?: string;
  importId?: string;
  title: string;
  description: string;
  severity: Severity;
  cvssScore: number;
  cwe: string;
  owaspCategory: string;
  host: string;
  port?: number;
  protocol?: string;
  path?: string;
  evidenceSnippet: string;
  remediation: string;
  references?: string[];
  cveList?: string[];
  cve?: string;
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  validationStatus: 'UNVALIDATED' | 'VALIDATING' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'REMEDIATED';
  outOfScope?: boolean;
  fingerprint?: string;
  importedAt?: string;
}

export type ExternalToolFormat =
  | 'NMAP_XML'
  | 'NMAP_JSON'
  | 'BURP_XML'
  | 'BURP_JSON'
  | 'NESSUS_XML'
  | 'NUCLEI_JSONL';

export interface ExternalToolImportRecord {
  importId: string;
  filename: string;
  sanitizedFilename: string;
  format: ExternalToolFormat;
  fileSizeBytes: number;
  sha256: string;
  importedAt: string;
  engagementId: string;
  tenantId: string;
  operatorId: string;
  totalParsed: number;
  validFindingsCount: number;
  duplicateCount: number;
  outOfScopeCount: number;
  extractedTargets: string[];
  findings: NormalizedFinding[];
  evidenceId: string;
  auditBlockId: string;
  status: 'SUCCESS' | 'PARTIAL' | 'REJECTED';
  errors: string[];
  rawArtifactName: string;
}

export interface ImportValidationResult {
  isValid: boolean;
  format?: ExternalToolFormat;
  error?: string;
  sanitizedFilename: string;
  fileSizeBytes: number;
  sha256: string;
}


export interface PentestJob {
  jobId: string;
  tenantId: string;
  engagementId: string;
  operatorId: string;
  toolId: string;
  toolName: string;
  target: string;
  profile: string;
  parameters: string[];
  customParams?: string[];
  status: JobStatus;
  mode: ToolExecutionMode;
  provenance?: ExecutionProvenance;
  agentId?: string;
  agentName?: string;
  startTime: string;
  endTime?: string;
  exitCode?: number;
  stdout: string;
  stderr: string;
  executionTimeMs?: number;
  artifacts: ArtifactFile[];
  findings: NormalizedFinding[];
  evidenceId?: string;
  auditBlockId?: string;
  hitlRequestId?: string;
  cancelRequested?: boolean;
}

export interface EvidenceRecord {
  evidenceId: string;
  jobId: string;
  engagementId: string;
  tenantId: string;
  operatorId: string;
  toolId: string;
  toolVersion: string;
  target: string;
  commandExecuted: string;
  rawStdoutHash: string;
  rawStderrHash: string;
  artifactHashes: { filename: string; sha256: string }[];
  findingsCount: number;
  timestamp: string;
  cryptographicSignature: string;
  verified: boolean;
}

export interface AuditBlock {
  index: number;
  timestamp: string;
  prevHash: string;
  hash: string;
  actor: string;
  action: string;
  tenantId: string;
  engagementId: string;
  target?: string;
  details: Record<string, unknown>;
  signature: string;
}

export interface AttackSurfaceAsset {
  id: string;
  target: string;
  host: string;
  openPorts: { port: number; service: string; version?: string; state: string }[];
  detectedServices: string[];
  technologies: string[];
  lastScanned: string;
  exposureScore: number;
  riskCategory: Severity;
}

export interface AttackPathStep {
  stepId: string;
  name: string;
  technique: string;
  toolUsed: string;
  likelihood: 'HIGH' | 'MEDIUM' | 'LOW';
  impact: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitreTactic: string;
  mitreTechniqueId: string;
}

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  targetAsset: string;
  steps: AttackPathStep[];
  verified: boolean;
}

export interface DefensiveTelemetryEvent {
  eventId: string;
  timestamp: string;
  sourceControl: string;
  eventName: string;
  matchedTechnique: string;
  mitreId: string;
  target: string;
  severity: Severity;
  detected: boolean;
  correlationJobId?: string;
  detectionStatus: DetectionStatus;
  controlEffectiveness: number; // 0 - 100%
}

export interface PentestReport {
  reportId: string;
  engagementId: string;
  engagementCode: string;
  generatedAt: string;
  title: string;
  type: 'TECHNICAL' | 'EXECUTIVE';
  executiveSummary: string;
  overallRiskScore: number;
  riskRating: Severity;
  scopeSummary: {
    totalTargets: number;
    inScopeTargets: number;
    excludedTargets: number;
  };
  findingsSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  findings: NormalizedFinding[];
  evidenceList: { evidenceId: string; toolId: string; target: string; hash: string }[];
  auditChainVerification: {
    blocksChecked: number;
    isValid: boolean;
    latestHash: string;
  };
  recommendations: string[];
}

export type EpistemicStatus = 'OBSERVED' | 'INFERRED' | 'SUSPECTED' | 'UNVERIFIED';

export type AgentCategory = 'OFFENSIVE' | 'DEFENSIVE' | 'ANALYTICAL' | 'EXECUTIVE';

export type AgentRole =
  | 'ATTACK_SURFACE_AGENT'
  | 'OFFENSIVE_PENTEST_AGENT'
  | 'VULNERABILITY_ANALYST'
  | 'ATTACK_PATH_ANALYST'
  | 'THREAT_HUNTER'
  | 'DETECTION_ANALYST'
  | 'DEFENSE_SOC_AGENT'
  | 'INVESTIGATOR_AGENT'
  | 'RISK_ANALYST'
  | 'SECURITY_CONTROL_ANALYST'
  | 'REMEDIATION_AGENT'
  | 'EXECUTIVE_SECURITY_ANALYST';

export interface AgentCapabilityBoundary {
  maxTier: CapabilityTier;
  requiresHitl: boolean;
  allowedActions: string[];
  forbiddenActions: string[];
  deterministicAuthoritative: boolean;
}

export interface AIAgentProfile {
  id: string;
  name: string;
  role: AgentRole;
  category: AgentCategory;
  description: string;
  status: 'IDLE' | 'ANALYZING' | 'WAITING_APPROVAL' | 'EXECUTING' | 'ERROR';
  capabilityBoundary: AgentCapabilityBoundary;
  epistemicStatus: EpistemicStatus;
  confidence: number; // 0.00 to 1.00
  lastActive: string;
  auditIdentity: string;
  supportedInputTypes: string[];
  allowedToolIds: string[];
}

export interface AIToolExecutionProposal {
  proposalId: string;
  agentId: string;
  agentName: string;
  toolId: string;
  targetAddress: string;
  profileName: string;
  proposedParameters: string[];
  justification: string;
  expectedFindingHypothesis: string;
  epistemicClassification: EpistemicStatus;
  confidence: number;
  status: 'PENDING_HITL' | 'APPROVED' | 'REJECTED' | 'EXECUTED';
  hitlRequestId?: string;
  jobId?: string;
  createdAt: string;
  reviewedAt?: string;
  reviewedBy?: string;
  rejectionReason?: string;
}

export interface AIRecommendation {
  id: string;
  agentId: string;
  agentName: string;
  category: 'ATTACK' | 'DEFENSE' | 'REMEDIATION' | 'GOVERNANCE';
  title: string;
  summary: string;
  epistemicStatus: EpistemicStatus;
  confidence: number;
  evidenceReferences: string[];
  actionableProposal?: AIToolExecutionProposal;
  createdAt: string;
  priority: Severity;
}

export interface AttackDefenseLoopResult {
  id: string;
  timestamp: string;
  simulationTarget: string;
  testDescription: string;
  answers: {
    whatWasTested: string;
    whatHappened: string;
    whatTelemetryWasGenerated: string;
    wasItDetected: boolean;
    whichControlDetectedIt: string;
    whichMitreTechniqueWasObserved: string;
    whatEvidenceSupportsConclusion: string;
    whatWasMissed: string;
    whatRemediationIsRecommended: string;
    didRevalidationSucceed: boolean | 'PENDING';
  };
  offensiveJobId?: string;
  defensiveEventId?: string;
  evidenceId?: string;
  auditBlockId?: string;
  controlEffectivenessScore: number;
  epistemicStatus: EpistemicStatus;
  confidence: number;
  remediationAction?: {
    actionId: string;
    description: string;
    patchGuidance: string;
    revalidationToolId: string;
    revalidationTarget: string;
    revalidationStatus: 'NOT_STARTED' | 'VALIDATING' | 'VERIFIED_FIXED' | 'STILL_VULNERABLE';
  };
}

export interface AIInvestigationRecord {
  investigationId: string;
  title: string;
  initiatorAgentId: string;
  target: string;
  status: 'OPEN' | 'INVESTIGATING' | 'REMEDIATION_PROPOSED' | 'CLOSED';
  timeline: {
    timestamp: string;
    agentId: string;
    agentName: string;
    action: string;
    epistemicStatus: EpistemicStatus;
    confidence: number;
    evidenceRef?: string;
  }[];
  correlatedFindingIds: string[];
  correlatedJobIds: string[];
  correlatedTelemetryIds: string[];
  evidenceReferences: string[];
  summary: string;
  recommendedRemediations: string[];
  createdAt: string;
  updatedAt: string;
}

