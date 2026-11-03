/**
 * AWM Nexus — Policy Engine & Human-In-The-Loop (HITL) Gate
 * Intercepts high-risk operations, validates safety boundaries, and manages cryptographically sealed operator approvals
 */

import { SecurityTool, ToolProfile, TargetAsset, HITLApprovalRequest, Severity } from '../types';
import { syncSha256 } from './cryptoUtils';

export interface PolicyEvaluationResult {
  allowed: boolean;
  requiresHITL: boolean;
  hitlReason?: string;
  riskLevel: Severity;
  policyViolations: string[];
}

class PolicyAndHitlEngine {
  private requests: Map<string, HITLApprovalRequest> = new Map();

  /**
   * Evaluates security policy rules against the execution parameters
   */
  public evaluatePolicy(
    tool: SecurityTool,
    profile: ToolProfile,
    targetAsset: TargetAsset | undefined,
    rawTarget: string,
    parameters: string[]
  ): PolicyEvaluationResult {
    const violations: string[] = [];
    let requiresHITL = false;
    let hitlReason = '';
    let riskLevel: Severity = 'LOW';

    // 1. Tool Profile HITL requirement
    if (profile.requiresHITL) {
      requiresHITL = true;
      hitlReason = profile.hitlReason || `Tool profile '${profile.name}' has been designated as high-impact by policy.`;
      riskLevel = 'HIGH';
    }

    // 2. Controlled Exploit Tier ALWAYS requires HITL
    if (profile.capabilityTier === 'CONTROLLED_EXPLOIT' || tool.capabilityTier === 'CONTROLLED_EXPLOIT') {
      requiresHITL = true;
      hitlReason = 'Controlled exploitation actions require explicit Lead Pentester approval.';
      riskLevel = 'CRITICAL';
    }

    // 3. Sensitive / Production Environment Target
    if (targetAsset && targetAsset.environment === 'PRODUCTION') {
      requiresHITL = true;
      hitlReason = `Target '${targetAsset.name}' is a PRODUCTION environment asset.`;
      if (riskLevel !== 'CRITICAL') riskLevel = 'HIGH';
    }

    // 4. Rate-limit or dangerous custom parameters
    for (const param of parameters) {
      if (param.includes('rate=1000') || param.includes('-T5') || param.includes('--flood')) {
        requiresHITL = true;
        hitlReason = 'Aggressive packet transmission flags detected.';
        riskLevel = 'HIGH';
      }
    }

    if (profile.capabilityTier === 'ACTIVE_PROBE' && riskLevel === 'LOW') {
      riskLevel = 'MEDIUM';
    }

    return {
      allowed: violations.length === 0,
      requiresHITL,
      hitlReason: requiresHITL ? hitlReason : undefined,
      riskLevel,
      policyViolations: violations
    };
  }

  /**
   * Creates a formal HITL approval ticket
   */
  public createRequest(
    jobId: string,
    tool: SecurityTool,
    profile: ToolProfile,
    targetAddress: string,
    parameters: string[],
    operatorId: string,
    riskLevel: Severity,
    reason: string
  ): HITLApprovalRequest {
    const requestId = `HITL-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;

    const request: HITLApprovalRequest = {
      requestId,
      jobId,
      toolId: tool.id,
      toolName: tool.name,
      targetAddress,
      profileName: profile.name,
      parameters,
      operatorId,
      riskLevel,
      reason,
      status: 'PENDING',
      requestedAt: new Date().toISOString()
    };

    this.requests.set(requestId, request);
    return request;
  }

  public getRequest(requestId: string): HITLApprovalRequest | undefined {
    return this.requests.get(requestId);
  }

  public getPendingRequests(): HITLApprovalRequest[] {
    return Array.from(this.requests.values()).filter(r => r.status === 'PENDING');
  }

  public getAllRequests(): HITLApprovalRequest[] {
    return Array.from(this.requests.values());
  }

  /**
   * Approves a pending HITL request and issues a cryptographic approval token
   */
  public approveRequest(requestId: string, approverId: string): { success: boolean; token?: string; error?: string } {
    const request = this.requests.get(requestId);
    if (!request) {
      return { success: false, error: `Request ${requestId} not found.` };
    }

    if (request.status !== 'PENDING') {
      return { success: false, error: `Request ${requestId} is already in state ${request.status}.` };
    }

    const decidedAt = new Date().toISOString();
    const approvalToken = syncSha256(`${requestId}:${request.jobId}:${request.toolId}:${approverId}:${decidedAt}`);

    request.status = 'APPROVED';
    request.approverId = approverId;
    request.decidedAt = decidedAt;
    request.approvalToken = approvalToken;

    return { success: true, token: approvalToken };
  }

  /**
   * Rejects a pending HITL request
   */
  public rejectRequest(requestId: string, approverId: string, rejectionReason: string): { success: boolean; error?: string } {
    const request = this.requests.get(requestId);
    if (!request) {
      return { success: false, error: `Request ${requestId} not found.` };
    }

    if (request.status !== 'PENDING') {
      return { success: false, error: `Request ${requestId} is already in state ${request.status}.` };
    }

    request.status = 'REJECTED';
    request.approverId = approverId;
    request.decidedAt = new Date().toISOString();
    request.rejectionReason = rejectionReason || 'Rejected by Security Lead.';

    return { success: true };
  }
}

const globalForHitl = globalThis as unknown as { __awm_policyAndHitlEngine?: PolicyAndHitlEngine };
export const policyAndHitlEngine = globalForHitl.__awm_policyAndHitlEngine || new PolicyAndHitlEngine();
if (!globalForHitl.__awm_policyAndHitlEngine) {
  globalForHitl.__awm_policyAndHitlEngine = policyAndHitlEngine;
}
