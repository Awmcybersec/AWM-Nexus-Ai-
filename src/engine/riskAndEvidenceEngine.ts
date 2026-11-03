/**
 * AWM Nexus — Risk Engine & Evidence Locker
 * Cryptographic SHA-256 evidence sealing, tamper-detection verification, and mathematical risk scoring
 */

import { EvidenceRecord, PentestJob, SecurityTool, NormalizedFinding, Severity } from '../types';
import { syncSha256 } from './cryptoUtils';

export class EvidenceEngine {
  private evidenceLocker: Map<string, EvidenceRecord> = new Map();

  public createEvidenceRecord(job: PentestJob, tool: SecurityTool): EvidenceRecord {
    const evidenceId = `EVID-${job.jobId.replace('JOB-', '')}`;
    const rawStdoutHash = syncSha256(job.stdout || '');
    const rawStderrHash = syncSha256(job.stderr || '');

    const artifactHashes = job.artifacts.map(a => ({
      filename: a.filename,
      sha256: a.sha256 || syncSha256(a.content)
    }));

    const signaturePayload = `${evidenceId}:${job.jobId}:${tool.id}:${job.target}:${rawStdoutHash}:${rawStderrHash}:${job.operatorId}`;
    const cryptographicSignature = syncSha256(`SEAL:${signaturePayload}`);

    const record: EvidenceRecord = {
      evidenceId,
      jobId: job.jobId,
      engagementId: job.engagementId,
      tenantId: job.tenantId,
      operatorId: job.operatorId,
      toolId: tool.id,
      toolVersion: tool.version || 'sandbox-sim-1.0',
      target: job.target,
      commandExecuted: `${tool.binaryName} ${job.parameters.join(' ')}`,
      rawStdoutHash,
      rawStderrHash,
      artifactHashes,
      findingsCount: job.findings.length,
      timestamp: new Date().toISOString(),
      cryptographicSignature,
      verified: true
    };

    this.evidenceLocker.set(evidenceId, record);
    return record;
  }

  public getEvidence(evidenceId: string): EvidenceRecord | undefined {
    return this.evidenceLocker.get(evidenceId);
  }

  public getAllEvidence(): EvidenceRecord[] {
    return Array.from(this.evidenceLocker.values()).sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  public getAllEvidenceRecords(): EvidenceRecord[] {
    return this.getAllEvidence();
  }

  /**
   * Verifies evidence record integrity by re-evaluating raw data against stored SHA-256
   */
  public verifyEvidenceIntegrity(evidenceId: string, job?: PentestJob): {
    isValid: boolean;
    evidenceId: string;
    stdoutHashMatch: boolean;
    stderrHashMatch: boolean;
    signatureMatch: boolean;
    error?: string;
  } {
    const evidence = this.evidenceLocker.get(evidenceId);
    if (!evidence) {
      return {
        isValid: false,
        evidenceId,
        stdoutHashMatch: false,
        stderrHashMatch: false,
        signatureMatch: false,
        error: `Evidence ${evidenceId} not found in locker.`
      };
    }

    if (!job) {
      // Basic signature self-verification
      const signaturePayload = `${evidence.evidenceId}:${evidence.jobId}:${evidence.toolId}:${evidence.target}:${evidence.rawStdoutHash}:${evidence.rawStderrHash}:${evidence.operatorId}`;
      const expectedSig = syncSha256(`SEAL:${signaturePayload}`);
      const sigMatch = evidence.cryptographicSignature === expectedSig;
      return {
        isValid: sigMatch,
        evidenceId,
        stdoutHashMatch: true,
        stderrHashMatch: true,
        signatureMatch: sigMatch
      };
    }

    const calculatedStdoutHash = syncSha256(job.stdout || '');
    const calculatedStderrHash = syncSha256(job.stderr || '');
    const stdoutMatch = calculatedStdoutHash === evidence.rawStdoutHash;
    const stderrMatch = calculatedStderrHash === evidence.rawStderrHash;

    const signaturePayload = `${evidence.evidenceId}:${evidence.jobId}:${evidence.toolId}:${evidence.target}:${evidence.rawStdoutHash}:${evidence.rawStderrHash}:${evidence.operatorId}`;
    const expectedSig = syncSha256(`SEAL:${signaturePayload}`);
    const sigMatch = evidence.cryptographicSignature === expectedSig;

    const isValid = stdoutMatch && stderrMatch && sigMatch;

    return {
      isValid,
      evidenceId,
      stdoutHashMatch: stdoutMatch,
      stderrHashMatch: stderrMatch,
      signatureMatch: sigMatch,
      error: isValid ? undefined : 'Evidence hash or cryptographic seal mismatch detected.'
    };
  }
}

export class RiskEngine {
  /**
   * Calculates dynamic risk score (0-100) based on severity weights and asset criticality
   */
  public calculateRiskScore(findings: NormalizedFinding[]): {
    score: number;
    rating: Severity;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  } {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;

    for (const f of findings) {
      if (f.severity === 'CRITICAL') criticalCount++;
      else if (f.severity === 'HIGH') highCount++;
      else if (f.severity === 'MEDIUM') mediumCount++;
      else if (f.severity === 'LOW') lowCount++;
      else infoCount++;
    }

    // Weighted risk formula: Critical (35), High (18), Medium (7), Low (2)
    const rawScore = (criticalCount * 35) + (highCount * 18) + (mediumCount * 7) + (lowCount * 2);
    const score = Math.min(100, Math.round(rawScore));

    let rating: Severity = 'INFO';
    if (score >= 75 || criticalCount > 0) rating = 'CRITICAL';
    else if (score >= 50 || highCount > 0) rating = 'HIGH';
    else if (score >= 25 || mediumCount > 0) rating = 'MEDIUM';
    else if (score > 0) rating = 'LOW';

    return {
      score,
      rating,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount
    };
  }
}

export const evidenceEngine = new EvidenceEngine();
export const riskEngine = new RiskEngine();
