/**
 * AWM Nexus — Scope & Authorization Engine
 * Enforces strict multi-tenant boundaries, CIDR/Domain scope rules, explicit exclusions, and RBAC capability limits
 */

import { Engagement, TargetAsset, ScopeRule, ScopeValidationResult, CapabilityTier, OperatorRole } from '../types';

export const INITIAL_ENGAGEMENTS: Engagement[] = [
  {
    id: 'eng-2026-001',
    code: 'ENG-2026-ALPHA',
    name: 'Q3 Enterprise Perimeter & API Penetration Test',
    clientName: 'AWM Defense Corp',
    tenantId: 'TENANT-AWM-01',
    startDate: '2026-08-01T00:00:00Z',
    endDate: '2026-12-31T23:59:59Z',
    allowedCapabilityTier: 'CONTROLLED_EXPLOIT',
    leadOperator: 'lead-sec-operator-01',
    active: true,
    scopeRules: [
      {
        ruleId: 'rule-01',
        pattern: '127.0.0.1',
        type: 'INCLUDE',
        description: 'Localhost Sandbox & Container Test Target'
      },
      {
        ruleId: 'rule-02',
        pattern: 'localhost',
        type: 'INCLUDE',
        description: 'Local loopback service testing'
      },
      {
        ruleId: 'rule-03',
        pattern: '10.0.100.0/24',
        type: 'INCLUDE',
        description: 'Authorized Staging DMZ Subnet',
        portsAllowed: '80,443,8080,8443,22,3306,5432'
      },
      {
        ruleId: 'rule-04',
        pattern: '192.168.1.0/24',
        type: 'INCLUDE',
        description: 'Internal Pentest Lab Subnet'
      },
      {
        ruleId: 'rule-05',
        pattern: '*.nexus-staging.internal',
        type: 'INCLUDE',
        description: 'Staging Environment Domain Wildcard'
      },
      {
        ruleId: 'rule-06',
        pattern: 'api.corp.internal',
        type: 'INCLUDE',
        description: 'Internal API Gateway'
      },
      {
        ruleId: 'rule-ex-01',
        pattern: '10.0.0.1',
        type: 'EXCLUDE',
        description: 'EXCLUDED: Active Directory Root Domain Controller (Production Critical)'
      },
      {
        ruleId: 'rule-ex-02',
        pattern: 'payment-gateway.internal',
        type: 'EXCLUDE',
        description: 'EXCLUDED: PCI-DSS Payment Processing Core (Strictly Out of Scope)'
      },
      {
        ruleId: 'rule-ex-03',
        pattern: '10.0.0.0/24',
        type: 'EXCLUDE',
        description: 'EXCLUDED: Core Infrastructure Backbone & Hypervisors'
      }
    ],
    targets: [
      {
        id: 'target-01',
        name: 'Local Container Sandbox Target',
        type: 'HOST',
        address: '127.0.0.1',
        ports: [80, 443, 3000],
        environment: 'SANDBOX_LAB',
        criticality: 'LOW',
        inScope: true,
        active: true,
        authorizedUntil: '2026-12-31T23:59:59Z'
      },
      {
        id: 'target-02',
        name: 'Nexus Staging API Gateway',
        type: 'DOMAIN',
        address: 'api.nexus-staging.internal',
        ports: [80, 443, 8443],
        environment: 'STAGING',
        criticality: 'HIGH',
        inScope: true,
        active: true,
        authorizedUntil: '2026-12-31T23:59:59Z'
      },
      {
        id: 'target-03',
        name: 'DMZ Microservices Cluster',
        type: 'CIDR',
        address: '10.0.100.0/24',
        ports: [80, 443, 8080],
        environment: 'STAGING',
        criticality: 'MEDIUM',
        inScope: true,
        active: true,
        authorizedUntil: '2026-12-31T23:59:59Z'
      },
      {
        id: 'target-04',
        name: 'Internal Security Test Lab Host',
        type: 'IP',
        address: '192.168.1.50',
        ports: [22, 80, 443, 8000],
        environment: 'SANDBOX_LAB',
        criticality: 'LOW',
        inScope: true,
        active: true,
        authorizedUntil: '2026-12-31T23:59:59Z'
      },
      {
        id: 'target-ex-01',
        name: 'Primary Domain Controller [OUT OF SCOPE]',
        type: 'IP',
        address: '10.0.0.1',
        ports: [53, 88, 389, 445],
        environment: 'PRODUCTION',
        criticality: 'CRITICAL',
        inScope: false,
        exclusionReason: 'Production Active Directory Controller — Explicitly excluded by RoE',
        active: false,
        authorizedUntil: '2026-12-31T23:59:59Z'
      },
      {
        id: 'target-ex-02',
        name: 'Payment Processing Core [OUT OF SCOPE]',
        type: 'DOMAIN',
        address: 'payment-gateway.internal',
        ports: [443, 8443],
        environment: 'PRODUCTION',
        criticality: 'CRITICAL',
        inScope: false,
        exclusionReason: 'PCI-DSS Payment Core — Third-party audit restriction',
        active: false,
        authorizedUntil: '2026-12-31T23:59:59Z'
      }
    ]
  }
];

export class ScopeEngine {
  private engagements: Map<string, Engagement> = new Map();

  constructor() {
    for (const eng of INITIAL_ENGAGEMENTS) {
      this.engagements.set(eng.id, { ...eng });
    }
  }

  public getAllEngagements(): Engagement[] {
    return Array.from(this.engagements.values());
  }

  public getEngagement(id: string): Engagement | undefined {
    return this.engagements.get(id);
  }

  public getEngagementByCode(code: string): Engagement | undefined {
    return Array.from(this.engagements.values()).find(e => e.code.toUpperCase() === code.toUpperCase());
  }

  public addTarget(engagementId: string, target: Omit<TargetAsset, 'id'>): TargetAsset {
    const eng = this.engagements.get(engagementId);
    if (!eng) throw new Error(`Engagement ${engagementId} not found`);

    const newTarget: TargetAsset = {
      ...target,
      id: `target-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`
    };

    eng.targets.push(newTarget);
    return newTarget;
  }

  /**
   * Evaluates if an IP falls within a CIDR subnet
   */
  public isIpInCidr(ip: string, cidr: string): boolean {
    try {
      const [cidrIp, prefixStr] = cidr.split('/');
      if (!prefixStr) {
        return ip === cidrIp;
      }
      const prefix = parseInt(prefixStr, 10);
      if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

      const ipNum = this.ipToNumber(ip);
      const cidrNum = this.ipToNumber(cidrIp);
      if (ipNum === null || cidrNum === null) return false;

      const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
      return (ipNum & mask) === (cidrNum & mask);
    } catch {
      return false;
    }
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return null;
    let num = 0;
    for (let i = 0; i < 4; i++) {
      const part = parseInt(parts[i], 10);
      if (isNaN(part) || part < 0 || part > 255) return null;
      num = ((num << 8) + part) >>> 0;
    }
    return num;
  }

  /**
   * Matches hostname against wildcard pattern (*.example.com)
   */
  public matchDomain(hostname: string, pattern: string): boolean {
    const cleanHost = hostname.toLowerCase().trim();
    const cleanPattern = pattern.toLowerCase().trim();

    if (cleanPattern.startsWith('*.')) {
      const suffix = cleanPattern.slice(1); // e.g. .nexus-staging.internal
      return cleanHost.endsWith(suffix) || cleanHost === cleanPattern.slice(2);
    }
    return cleanHost === cleanPattern;
  }

  /**
   * Validates target against engagement scope rules and exclusions
   */
  public validateTargetScope(engagement: Engagement, rawTarget: string): { inScope: boolean; excluded: boolean; reason: string; matchedRule?: string } {
    if (!engagement.active) {
      return {
        inScope: false,
        excluded: false,
        reason: `Engagement ${engagement.code} is inactive or suspended.`
      };
    }

    const now = new Date();
    const startDate = new Date(engagement.startDate);
    const endDate = new Date(engagement.endDate);
    if (now < startDate || now > endDate) {
      return {
        inScope: false,
        excluded: false,
        reason: `EXPIRED AUTHORIZATION: Engagement ${engagement.code} authorized window is ${engagement.startDate} to ${engagement.endDate}.`
      };
    }

    let cleanTarget = rawTarget.trim();
    // Strip protocol or port if present for scope checking
    cleanTarget = cleanTarget.replace(/^https?:\/\//i, '').replace(/:\d+$/, '').split('/')[0];

    // 1. Check Explicit Exclusions FIRST
    for (const rule of engagement.scopeRules.filter(r => r.type === 'EXCLUDE')) {
      if (rule.pattern.includes('/')) {
        if (this.isIpInCidr(cleanTarget, rule.pattern)) {
          return {
            inScope: false,
            excluded: true,
            reason: `Target ${cleanTarget} is in strictly EXCLUDED CIDR block ${rule.pattern} (${rule.description})`,
            matchedRule: rule.ruleId
          };
        }
      } else if (rule.pattern.startsWith('*.')) {
        if (this.matchDomain(cleanTarget, rule.pattern)) {
          return {
            inScope: false,
            excluded: true,
            reason: `Target ${cleanTarget} matches EXCLUDED domain pattern ${rule.pattern} (${rule.description})`,
            matchedRule: rule.ruleId
          };
        }
      } else if (cleanTarget === rule.pattern) {
        return {
          inScope: false,
          excluded: true,
          reason: `Target ${cleanTarget} is explicitly EXCLUDED: ${rule.description}`,
          matchedRule: rule.ruleId
        };
      }
    }

    // Also check targets marked inScope: false
    const excludedTarget = engagement.targets.find(t => !t.inScope && (t.address === cleanTarget || (t.type === 'CIDR' && this.isIpInCidr(cleanTarget, t.address))));
    if (excludedTarget) {
      return {
        inScope: false,
        excluded: true,
        reason: `Target ${cleanTarget} is explicitly excluded: ${excludedTarget.exclusionReason || 'Target marked out of scope'}`,
        matchedRule: excludedTarget.id
      };
    }

    // 2. Check Explicit Inclusions
    for (const rule of engagement.scopeRules.filter(r => r.type === 'INCLUDE')) {
      if (rule.pattern.includes('/')) {
        if (this.isIpInCidr(cleanTarget, rule.pattern)) {
          return {
            inScope: true,
            excluded: false,
            reason: `Target ${cleanTarget} matched authorized CIDR scope: ${rule.pattern} (${rule.description})`,
            matchedRule: rule.ruleId
          };
        }
      } else if (rule.pattern.startsWith('*.')) {
        if (this.matchDomain(cleanTarget, rule.pattern)) {
          return {
            inScope: true,
            excluded: false,
            reason: `Target ${cleanTarget} matched authorized domain pattern: ${rule.pattern} (${rule.description})`,
            matchedRule: rule.ruleId
          };
        }
      } else if (cleanTarget === rule.pattern) {
        return {
          inScope: true,
          excluded: false,
          reason: `Target ${cleanTarget} matched authorized target: ${rule.description}`,
          matchedRule: rule.ruleId
        };
      }
    }

    // Also check explicit target assets
    const matchedTargetAsset = engagement.targets.find(t => t.inScope && (t.address === cleanTarget || (t.type === 'CIDR' && this.isIpInCidr(cleanTarget, t.address))));
    if (matchedTargetAsset) {
      return {
        inScope: true,
        excluded: false,
        reason: `Target ${cleanTarget} matched authorized asset inventory: ${matchedTargetAsset.name}`,
        matchedRule: matchedTargetAsset.id
      };
    }

    return {
      inScope: false,
      excluded: false,
      reason: `Target ${cleanTarget} is NOT in the authorized Scope of Work (RoE) for engagement ${engagement.code}`
    };
  }

  /**
   * RBAC Capability Tier Check
   */
  public isCapabilityAllowed(role: OperatorRole, requestedTier: CapabilityTier): boolean {
    const roleTierMap: Record<OperatorRole, CapabilityTier[]> = {
      READONLY_ANALYST: ['RECON_READONLY'],
      CERTIFIED_PENTESTER: ['RECON_READONLY', 'NON_DESTRUCTIVE_SCAN', 'ACTIVE_PROBE'],
      LEAD_SECURITY_ENGINEER: ['RECON_READONLY', 'NON_DESTRUCTIVE_SCAN', 'ACTIVE_PROBE', 'CONTROLLED_EXPLOIT'],
      SYSTEM_ADMIN: ['RECON_READONLY', 'NON_DESTRUCTIVE_SCAN', 'ACTIVE_PROBE', 'CONTROLLED_EXPLOIT']
    };

    return roleTierMap[role]?.includes(requestedTier) ?? false;
  }

  /**
   * Full Pre-flight Authorization & Scope Validation Pipeline
   */
  public validateExecution(
    engagementId: string,
    tenantId: string,
    operatorId: string,
    operatorRole: OperatorRole,
    target: string,
    capabilityTier: CapabilityTier
  ): ScopeValidationResult {
    const engagement = this.engagements.get(engagementId);

    // Tenant Isolation Check
    if (!engagement) {
      return {
        valid: false,
        inScope: false,
        excluded: false,
        reason: `Engagement ${engagementId} does not exist.`,
        targetAddress: target,
        capabilityPermitted: false,
        hitlRequired: false
      };
    }

    if (engagement.tenantId !== tenantId) {
      return {
        valid: false,
        inScope: false,
        excluded: false,
        reason: `CROSS-TENANT VIOLATION: Operator tenant ${tenantId} cannot execute actions in tenant ${engagement.tenantId}.`,
        targetAddress: target,
        capabilityPermitted: false,
        hitlRequired: false
      };
    }

    // Engagement Active & Time-bound Authorization Check
    const now = new Date();
    const startDate = new Date(engagement.startDate);
    const endDate = new Date(engagement.endDate);

    if (!engagement.active) {
      return {
        valid: false,
        inScope: false,
        excluded: false,
        reason: `Engagement ${engagement.code} is inactive or suspended.`,
        targetAddress: target,
        capabilityPermitted: false,
        hitlRequired: false
      };
    }

    if (now < startDate || now > endDate) {
      return {
        valid: false,
        inScope: false,
        excluded: false,
        reason: `EXPIRED AUTHORIZATION: Engagement ${engagement.code} authorized window is ${engagement.startDate} to ${engagement.endDate}.`,
        targetAddress: target,
        capabilityPermitted: false,
        hitlRequired: false
      };
    }

    // Role vs Capability Check
    if (!this.isCapabilityAllowed(operatorRole, capabilityTier)) {
      return {
        valid: false,
        inScope: false,
        excluded: false,
        reason: `RBAC DENIED: Operator role '${operatorRole}' is not permitted to execute '${capabilityTier}' actions.`,
        targetAddress: target,
        capabilityPermitted: false,
        hitlRequired: false
      };
    }

    // Scope Validation Check
    const scopeResult = this.validateTargetScope(engagement, target);
    if (!scopeResult.inScope) {
      return {
        valid: false,
        inScope: false,
        excluded: scopeResult.excluded,
        reason: scopeResult.reason,
        targetAddress: target,
        matchedRule: scopeResult.matchedRule,
        capabilityPermitted: true,
        hitlRequired: false
      };
    }

    return {
      valid: true,
      inScope: true,
      excluded: false,
      reason: scopeResult.reason,
      targetAddress: target,
      matchedRule: scopeResult.matchedRule,
      capabilityPermitted: true,
      hitlRequired: false
    };
  }
}

export const scopeEngine = new ScopeEngine();
