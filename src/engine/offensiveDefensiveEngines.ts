/**
 * AWM Nexus — Offensive & Defensive Engine Integrations
 * Attack Surface discovery, Exposure analysis, Attack Path modeling, Defensive Telemetry correlation & Report Generation
 */

import {
  AttackSurfaceAsset,
  AttackPath,
  DefensiveTelemetryEvent,
  NormalizedFinding,
  PentestReport,
  Severity,
  DetectionStatus
} from '../types';
import { scopeEngine } from './scopeEngine';
import { riskEngine, evidenceEngine } from './riskAndEvidenceEngine';
import { auditLedger } from './auditLedger';

export class AttackSurfaceEngine {
  private assets: Map<string, AttackSurfaceAsset> = new Map();

  constructor() {
    this.seedInitialAssets();
  }

  private seedInitialAssets() {
    const defaultAssets: AttackSurfaceAsset[] = [
      {
        id: 'asset-01',
        target: '127.0.0.1',
        host: 'localhost (Dev Container)',
        openPorts: [
          { port: 3000, service: 'http', version: 'Vite/Node 22', state: 'open' },
          { port: 80, service: 'http', version: 'nginx/1.24', state: 'open' }
        ],
        detectedServices: ['HTTP/1.1', 'Node.js', 'Express.js'],
        technologies: ['Vite', 'React 19', 'Tailwind v4', 'TypeScript'],
        lastScanned: new Date().toISOString(),
        exposureScore: 24,
        riskCategory: 'LOW'
      },
      {
        id: 'asset-02',
        target: 'api.nexus-staging.internal',
        host: 'api.nexus-staging.internal',
        openPorts: [
          { port: 80, service: 'http', version: 'nginx 1.24.0', state: 'open' },
          { port: 443, service: 'https', version: 'OpenSSL 3.0.2', state: 'open' },
          { port: 8080, service: 'http-api', version: 'REST Gateway 2.1', state: 'open' }
        ],
        detectedServices: ['REST API', 'TLSv1.3', 'Reverse Proxy'],
        technologies: ['Ubuntu 22.04', 'Nginx', 'Node.js Express', 'JSON Web Tokens'],
        lastScanned: new Date().toISOString(),
        exposureScore: 68,
        riskCategory: 'HIGH'
      },
      {
        id: 'asset-03',
        target: '10.0.100.25',
        host: 'dmz-app-node-01.corp.internal',
        openPorts: [
          { port: 22, service: 'ssh', version: 'OpenSSH 8.9p1', state: 'open' },
          { port: 80, service: 'http', version: 'nginx 1.24.0', state: 'open' },
          { port: 443, service: 'https', version: 'OpenSSL 3.0.2', state: 'open' }
        ],
        detectedServices: ['SSH', 'HTTP', 'HTTPS'],
        technologies: ['Linux 5.15', 'Nginx', 'OpenSSH'],
        lastScanned: new Date().toISOString(),
        exposureScore: 45,
        riskCategory: 'MEDIUM'
      }
    ];

    for (const a of defaultAssets) {
      this.assets.set(a.target, a);
    }
  }

  public scanTarget(target: string): AttackSurfaceAsset {
    const existing = this.assets.get(target);
    if (existing) {
      existing.lastScanned = new Date().toISOString();
      return existing;
    }

    const newAsset: AttackSurfaceAsset = {
      id: `asset-${Date.now().toString(36)}`,
      target,
      host: target,
      openPorts: [
        { port: 80, service: 'http', state: 'open' },
        { port: 443, service: 'https', state: 'open' }
      ],
      detectedServices: ['HTTP', 'HTTPS'],
      technologies: ['Standard Web Daemon'],
      lastScanned: new Date().toISOString(),
      exposureScore: 35,
      riskCategory: 'LOW'
    };

    this.assets.set(target, newAsset);
    return newAsset;
  }

  public getAllAssets(): AttackSurfaceAsset[] {
    return Array.from(this.assets.values());
  }

  public getAsset(target: string): AttackSurfaceAsset | undefined {
    return this.assets.get(target);
  }
}

export class ExposureEngine {
  public analyzeExposure(target: string, asset?: AttackSurfaceAsset): {
    target: string;
    exposureScore: number;
    riskCategory: Severity;
    factors: { factor: string; weight: number; status: 'EXPOSED' | 'PROTECTED' | 'MONITORED' }[];
    perimeterDefense: string;
  } {
    const score = asset ? asset.exposureScore : 40;
    let riskCategory: Severity = 'LOW';
    if (score >= 70) riskCategory = 'HIGH';
    else if (score >= 40) riskCategory = 'MEDIUM';

    return {
      target,
      exposureScore: score,
      riskCategory,
      perimeterDefense: 'Cloudflare WAF / AWS Security Group Filter Active',
      factors: [
        { factor: 'Public Ingress Ports (80/443)', weight: 20, status: 'EXPOSED' },
        { factor: 'Management Port Exposure (SSH 22 / RDP 3389)', weight: 35, status: asset?.openPorts.some(p => p.port === 22 || p.port === 3389) ? 'EXPOSED' : 'PROTECTED' },
        { factor: 'TLS Configuration & Legacy Ciphers', weight: 15, status: 'MONITORED' },
        { factor: 'API Authentication Perimeter', weight: 30, status: 'MONITORED' }
      ]
    };
  }
}

export class AttackPathEngine {
  private paths: AttackPath[] = [
    {
      id: 'path-01',
      name: 'External API Misconfiguration to Internal Pivot',
      description: 'Exploitation of permissive CORS and exposed Swagger docs on API Gateway leading to internal staging pivot.',
      severity: 'HIGH',
      targetAsset: 'api.nexus-staging.internal',
      verified: true,
      steps: [
        {
          stepId: 'step-1',
          name: 'Passive Recon & DNS Discovery',
          technique: 'Subdomain Enumeration',
          toolUsed: 'Amass / Subfinder',
          likelihood: 'HIGH',
          impact: 'LOW',
          mitreTactic: 'Reconnaissance',
          mitreTechniqueId: 'T1595'
        },
        {
          stepId: 'step-2',
          name: 'Directory Discovery of /swagger.json',
          technique: 'Web Content Enumeration',
          toolUsed: 'ffuf / Gobuster',
          likelihood: 'HIGH',
          impact: 'MEDIUM',
          mitreTactic: 'Discovery',
          mitreTechniqueId: 'T1083'
        },
        {
          stepId: 'step-3',
          name: 'JWT Signature Bypass / Default Secret',
          technique: 'Broken Authentication',
          toolUsed: 'curl / Burp Suite API',
          likelihood: 'MEDIUM',
          impact: 'HIGH',
          mitreTactic: 'Initial Access',
          mitreTechniqueId: 'T1190'
        },
        {
          stepId: 'step-4',
          name: 'Internal DMZ Microservice Access',
          technique: 'Lateral Movement',
          toolUsed: 'Nmap / curl',
          likelihood: 'LOW',
          impact: 'CRITICAL',
          mitreTactic: 'Lateral Movement',
          mitreTechniqueId: 'T1021'
        }
      ]
    }
  ];

  public getAllPaths(): AttackPath[] {
    return [...this.paths];
  }

  public getPath(id: string): AttackPath | undefined {
    return this.paths.find(p => p.id === id);
  }
}

export class DefensiveTelemetryEngine {
  private events: DefensiveTelemetryEvent[] = [
    {
      eventId: 'DEF-EVT-01',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      sourceControl: 'WAF - ModSecurity / Cloudflare',
      eventName: 'Directory Traversal & Fuzzing Wave Detected',
      matchedTechnique: 'Active Scanning',
      mitreId: 'T1595.002',
      target: 'api.nexus-staging.internal',
      severity: 'MEDIUM',
      detected: true,
      detectionStatus: 'LIVE',
      controlEffectiveness: 92
    },
    {
      eventId: 'DEF-EVT-02',
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      sourceControl: 'SIEM - Wazuh / Splunk Cluster',
      eventName: 'Nmap SYN Port Sweep Telemetry Alert',
      matchedTechnique: 'Network Service Discovery',
      mitreId: 'T1046',
      target: '10.0.100.25',
      severity: 'LOW',
      detected: true,
      detectionStatus: 'LIVE',
      controlEffectiveness: 88
    },
    {
      eventId: 'DEF-EVT-03',
      timestamp: new Date(Date.now() - 900000).toISOString(),
      sourceControl: 'EDR - CrowdStrike Falcon / OSSEC',
      eventName: 'Unusual TLS Handshake with Self-Signed Certificate',
      matchedTechnique: 'Encrypted Channel',
      mitreId: 'T1573',
      target: '127.0.0.1',
      severity: 'LOW',
      detected: false,
      detectionStatus: 'SIMULATED',
      controlEffectiveness: 65
    }
  ];

  public getAllEvents(): DefensiveTelemetryEvent[] {
    return [...this.events];
  }

  public recordEvent(event: Omit<DefensiveTelemetryEvent, 'eventId' | 'timestamp'>): DefensiveTelemetryEvent {
    const newEvent: DefensiveTelemetryEvent = {
      ...event,
      eventId: `DEF-EVT-${Date.now().toString(36).toUpperCase()}`,
      timestamp: new Date().toISOString()
    };
    this.events.unshift(newEvent);
    return newEvent;
  }
}

export class PentestReportEngine {
  public generateReport(
    engagementId: string,
    type: 'TECHNICAL' | 'EXECUTIVE',
    findings: NormalizedFinding[]
  ): PentestReport {
    const eng = scopeEngine.getEngagement(engagementId) || scopeEngine.getAllEngagements()[0];
    const risk = riskEngine.calculateRiskScore(findings);
    const evidenceList = evidenceEngine.getAllEvidence().map(e => ({
      evidenceId: e.evidenceId,
      toolId: e.toolId,
      target: e.target,
      hash: e.rawStdoutHash
    }));

    const auditStatus = auditLedger.verifyChainIntegrity();

    const inScopeCount = eng.targets.filter(t => t.inScope).length;
    const excludedCount = eng.targets.filter(t => !t.inScope).length;

    const reportId = `RPT-${eng.code}-${type.slice(0, 4)}-${Date.now().toString(36).toUpperCase()}`;

    const executiveSummary = `During the authorized penetration testing window (${eng.startDate} - ${eng.endDate}), the AWM Nexus operations team evaluated ${inScopeCount} authorized assets. A total of ${findings.length} findings were discovered and cryptographically sealed into evidence. Overall posture evaluation indicates a ${risk.rating} risk level with an aggregate risk score of ${risk.score}/100. Priority remediation should focus on ${risk.criticalCount} Critical and ${risk.highCount} High severity vulnerability findings to close identified attack vectors.`;

    const recommendations = [
      'Enforce strict Content-Security-Policy and HSTS response headers across all public-facing web gateways.',
      'Deprecate legacy TLS 1.0 and TLS 1.1 protocols; restrict cipher suites to TLS 1.2/1.3 with Forward Secrecy.',
      'Restrict management services (SSH, RDP, Web Admin panels) to internal bastion VPN networks with MFA.',
      'Deploy automated secret scanning to prevent accidental exposure of .env and .git metadata in web roots.'
    ];

    return {
      reportId,
      engagementId: eng.id,
      engagementCode: eng.code,
      generatedAt: new Date().toISOString(),
      title: `${eng.name} — ${type === 'TECHNICAL' ? 'Technical Vulnerability Assessment' : 'Executive Security Posture Review'}`,
      type,
      executiveSummary,
      overallRiskScore: risk.score,
      riskRating: risk.rating,
      scopeSummary: {
        totalTargets: eng.targets.length,
        inScopeTargets: inScopeCount,
        excludedTargets: excludedCount
      },
      findingsSummary: {
        critical: risk.criticalCount,
        high: risk.highCount,
        medium: risk.mediumCount,
        low: risk.lowCount,
        info: risk.infoCount,
        total: findings.length
      },
      findings,
      evidenceList,
      auditChainVerification: {
        blocksChecked: auditStatus.blocksCount,
        isValid: auditStatus.isValid,
        latestHash: auditLedger.getBlocks().slice(-1)[0]?.hash || ''
      },
      recommendations
    };
  }
}

export const attackSurfaceEngine = new AttackSurfaceEngine();
export const exposureEngine = new ExposureEngine();
export const attackPathEngine = new AttackPathEngine();
export const defensiveTelemetryEngine = new DefensiveTelemetryEngine();
export const pentestReportEngine = new PentestReportEngine();
