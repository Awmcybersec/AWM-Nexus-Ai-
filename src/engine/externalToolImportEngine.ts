/**
 * AWM Nexus — External Tool Result Import & Normalization Engine
 * Securely imports, validates, parses, normalizes, and cryptographically seals results from:
 * 1. Nmap XML
 * 2. Nmap JSON
 * 3. Burp Suite XML & JSON exports
 * 4. Nessus / Nessus XML (.nessus)
 * 5. Nuclei JSONL
 */

import { XMLParser, XMLValidator } from 'fast-xml-parser';
import {
  ExternalToolFormat,
  ExternalToolImportRecord,
  ImportValidationResult,
  NormalizedFinding,
  Severity,
  ArtifactFile,
  Engagement
} from '../types';
import { syncSha256 } from './cryptoUtils';
import { scopeEngine } from './scopeEngine';
import { auditLedger } from './auditLedger';
import { evidenceEngine } from './riskAndEvidenceEngine';
import { attackSurfaceEngine } from './offensiveDefensiveEngines';

export const MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024; // 15 Megabytes

export class ExternalToolImportEngine {
  private static instance: ExternalToolImportEngine;
  private importHistory: Map<string, ExternalToolImportRecord> = new Map();
  private importedFindings: Map<string, NormalizedFinding> = new Map();
  private knownFingerprints: Set<string> = new Set();

  private xmlParser: XMLParser;

  public constructor() {
    this.xmlParser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      allowBooleanAttributes: true,
      parseAttributeValue: true,
      trimValues: true,
      processEntities: false, // Prevents XML External Entity (XXE) attacks
      stopNodes: []
    });
  }

  public static getInstance(): ExternalToolImportEngine {
    if (!ExternalToolImportEngine.instance) {
      ExternalToolImportEngine.instance = new ExternalToolImportEngine();
    }
    return ExternalToolImportEngine.instance;
  }

  /**
   * Sanitizes a filename to protect against Path Traversal, Null Byte Injections, and Shell Metacharacters.
   */
  public sanitizeFilename(filename: string): string {
    if (!filename || typeof filename !== 'string') {
      return `import_${Date.now()}.log`;
    }
    // Remove directory traversal sequences (../, ..\, etc.)
    let clean = filename.replace(/^.*[\\\/]/, '');
    // Strip null bytes and non-printable characters
    clean = clean.replace(/[\x00-\x1F\x7F]/g, '');
    // Replace risky characters with underscores
    clean = clean.replace(/[^a-zA-Z0-9._\-]/g, '_');
    // Ensure not empty
    if (!clean || clean === '.' || clean === '..') {
      return `import_${Date.now()}.log`;
    }
    return clean;
  }

  /**
   * Validates file upload: checks file size, prevents XXE patterns, and detects format.
   */
  public validateUpload(
    filename: string,
    content: string,
    declaredFormat?: ExternalToolFormat
  ): ImportValidationResult {
    const sanitizedFilename = this.sanitizeFilename(filename);
    const fileSizeBytes = Buffer.byteLength(content, 'utf8');
    const sha256 = syncSha256(content);

    // 1. File size enforcement
    if (fileSizeBytes > MAX_FILE_SIZE_BYTES) {
      return {
        isValid: false,
        error: `File size exceeds maximum allowed limit of ${MAX_FILE_SIZE_BYTES / (1024 * 1024)}MB. Actual: ${(fileSizeBytes / (1024 * 1024)).toFixed(2)}MB.`,
        sanitizedFilename,
        fileSizeBytes,
        sha256
      };
    }

    if (fileSizeBytes === 0 || !content.trim()) {
      return {
        isValid: false,
        error: 'Uploaded file is empty.',
        sanitizedFilename,
        fileSizeBytes,
        sha256
      };
    }

    // 2. XXE and External Entity Injection Protection (pre-scan)
    // Matches <!ENTITY name SYSTEM "..." or <!ENTITY name PUBLIC "..." or general entity declarations
    const isXxe = /<!ENTITY\s+[^>]+(SYSTEM|PUBLIC)/i.test(content) || (content.includes('<!ENTITY') && content.includes('%'));
    if (isXxe) {
      return {
        isValid: false,
        error: 'SECURITY VIOLATION: Malicious XML External Entity (XXE) / DTD declaration rejected.',
        sanitizedFilename,
        fileSizeBytes,
        sha256
      };
    }

    // 3. Format Detection & Validation
    const detectedFormat = declaredFormat || this.detectFormat(sanitizedFilename, content);
    if (!detectedFormat) {
      return {
        isValid: false,
        error: 'Unsupported or unrecognizable file format. Supported: Nmap XML, Nmap JSON, Burp XML/JSON, Nessus XML, Nuclei JSONL.',
        sanitizedFilename,
        fileSizeBytes,
        sha256
      };
    }

    // 4. Basic Syntax Verification
    if (detectedFormat.endsWith('_XML')) {
      const xmlValidation = XMLValidator.validate(content);
      if (xmlValidation !== true) {
        return {
          isValid: false,
          error: `Malformed XML syntax: ${xmlValidation.err.msg} (Line ${xmlValidation.err.line})`,
          format: detectedFormat,
          sanitizedFilename,
          fileSizeBytes,
          sha256
        };
      }
    } else if (detectedFormat === 'NMAP_JSON' || detectedFormat === 'BURP_JSON') {
      try {
        JSON.parse(content);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          isValid: false,
          error: `Malformed JSON syntax: ${msg}`,
          format: detectedFormat,
          sanitizedFilename,
          fileSizeBytes,
          sha256
        };
      }
    } else if (detectedFormat === 'NUCLEI_JSONL') {
      // Validate that at least one valid JSON line exists
      const lines = content.split('\n').filter(l => l.trim().length > 0);
      let validLineFound = false;
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          if (parsed && (parsed['template-id'] || parsed['templateID'] || parsed.info)) {
            validLineFound = true;
            break;
          }
        } catch {}
      }
      if (!validLineFound) {
        return {
          isValid: false,
          error: 'Malformed Nuclei JSONL: No valid Nuclei result lines containing template-id found.',
          format: detectedFormat,
          sanitizedFilename,
          fileSizeBytes,
          sha256
        };
      }
    }

    return {
      isValid: true,
      format: detectedFormat,
      sanitizedFilename,
      fileSizeBytes,
      sha256
    };
  }

  /**
   * Automatically detects the external tool output format from filename and structure.
   */
  public detectFormat(filename: string, content: string): ExternalToolFormat | null {
    const trimmed = content.trim();
    const lowerName = filename.toLowerCase();

    // 1. Nessus XML
    if (
      lowerName.endsWith('.nessus') ||
      trimmed.includes('<NessusClientData_v2') ||
      (trimmed.includes('<Report') && trimmed.includes('<ReportHost'))
    ) {
      return 'NESSUS_XML';
    }

    // 2. Nmap XML
    if (
      trimmed.startsWith('<?xml') &&
      (trimmed.includes('<nmaprun') || trimmed.includes('<!DOCTYPE nmaprun'))
    ) {
      return 'NMAP_XML';
    }

    // 3. Burp Suite XML
    if (
      (trimmed.startsWith('<?xml') || trimmed.startsWith('<issues')) &&
      (trimmed.includes('<issues') || trimmed.includes('<issue>'))
    ) {
      return 'BURP_XML';
    }

    // 4. Nuclei JSONL
    if (lowerName.endsWith('.jsonl') || (trimmed.startsWith('{') && (trimmed.includes('"template-id"') || trimmed.includes('"templateID"') || trimmed.includes('"matched-at"')))) {
      return 'NUCLEI_JSONL';
    }

    // 5. JSON formats (Nmap JSON vs Burp JSON)
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const json = JSON.parse(trimmed);
        if (json.nmaprun || json.scanner === 'nmap' || (Array.isArray(json) && json[0]?.addresses)) {
          return 'NMAP_JSON';
        }
        if (json.issues || (Array.isArray(json) && (json[0]?.issueType || json[0]?.issueBackground))) {
          return 'BURP_JSON';
        }
        if (Array.isArray(json) && json[0]?.['template-id']) {
          return 'NUCLEI_JSONL';
        }
      } catch {}
    }

    return null;
  }

  /**
   * Main import pipeline: validates, parses, deduplicates, checks scope, seals evidence, and logs audit block.
   */
  public async importResults(
    filename: string,
    rawContent: string,
    engagementId: string,
    tenantId: string,
    operatorId: string,
    declaredFormat?: ExternalToolFormat
  ): Promise<ExternalToolImportRecord> {
    const importId = `IMP-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

    // 1. Pre-flight Validation
    const validation = this.validateUpload(filename, rawContent, declaredFormat);
    if (!validation.isValid || !validation.format) {
      const rejectedRecord: ExternalToolImportRecord = {
        importId,
        filename,
        sanitizedFilename: validation.sanitizedFilename,
        format: declaredFormat || 'NMAP_XML',
        fileSizeBytes: validation.fileSizeBytes,
        sha256: validation.sha256,
        importedAt: new Date().toISOString(),
        engagementId,
        tenantId,
        operatorId,
        totalParsed: 0,
        validFindingsCount: 0,
        duplicateCount: 0,
        outOfScopeCount: 0,
        extractedTargets: [],
        findings: [],
        evidenceId: '',
        auditBlockId: '',
        status: 'REJECTED',
        errors: [validation.error || 'Validation failed'],
        rawArtifactName: `${importId}_${validation.sanitizedFilename}`
      };

      // Audit rejection
      const audit = auditLedger.appendBlock(
        operatorId,
        'EXTERNAL_TOOL_IMPORT_REJECTED',
        tenantId,
        engagementId,
        'N/A',
        {
          importId,
          filename: validation.sanitizedFilename,
          sha256: validation.sha256,
          reason: validation.error
        }
      );
      rejectedRecord.auditBlockId = `BLK-${audit.index}`;
      this.importHistory.set(importId, rejectedRecord);
      return rejectedRecord;
    }

    // 2. Engagement Scope Lookup
    const engagement = scopeEngine.getEngagement(engagementId) || scopeEngine.getAllEngagements()[0];
    if (!engagement) {
      throw new Error(`Engagement ${engagementId} not found.`);
    }

    // 3. Parse Based on Detected Format
    const errors: string[] = [];
    let parsedFindings: NormalizedFinding[] = [];
    const extractedTargetsSet = new Set<string>();

    try {
      switch (validation.format) {
        case 'NMAP_XML':
          parsedFindings = this.parseNmapXml(rawContent, importId, validation.sanitizedFilename, extractedTargetsSet, errors);
          break;
        case 'NMAP_JSON':
          parsedFindings = this.parseNmapJson(rawContent, importId, validation.sanitizedFilename, extractedTargetsSet, errors);
          break;
        case 'BURP_XML':
          parsedFindings = this.parseBurpXml(rawContent, importId, validation.sanitizedFilename, extractedTargetsSet, errors);
          break;
        case 'BURP_JSON':
          parsedFindings = this.parseBurpJson(rawContent, importId, validation.sanitizedFilename, extractedTargetsSet, errors);
          break;
        case 'NESSUS_XML':
          parsedFindings = this.parseNessusXml(rawContent, importId, validation.sanitizedFilename, extractedTargetsSet, errors);
          break;
        case 'NUCLEI_JSONL':
          parsedFindings = this.parseNucleiJsonl(rawContent, importId, validation.sanitizedFilename, extractedTargetsSet, errors);
          break;
      }
    } catch (parseErr: unknown) {
      const msg = parseErr instanceof Error ? parseErr.message : String(parseErr);
      errors.push(`Parser execution failed: ${msg}`);
    }

    // 4. Scope Validation & Deduplication
    let duplicateCount = 0;
    let outOfScopeCount = 0;
    const finalFindings: NormalizedFinding[] = [];

    for (const finding of parsedFindings) {
      // Scope validation
      const scopeCheck = scopeEngine.validateTargetScope(engagement, finding.host);
      if (!scopeCheck.inScope) {
        finding.outOfScope = true;
        outOfScopeCount++;
      }

      // Fingerprint calculation for deduplication
      const fingerprint = syncSha256(
        `${finding.host}:${finding.port || '0'}:${finding.title}:${finding.path || ''}`
      );
      finding.fingerprint = fingerprint;

      if (this.knownFingerprints.has(fingerprint)) {
        duplicateCount++;
        // Note: we track duplicate count, but still associate finding to import for audit visibility
        finding.validationStatus = 'UNVALIDATED';
      } else {
        this.knownFingerprints.add(fingerprint);
      }

      this.importedFindings.set(finding.findingId, finding);
      finalFindings.push(finding);

      // Link in-scope targets to Attack Surface Engine
      if (!finding.outOfScope && finding.host) {
        const asset = attackSurfaceEngine.scanTarget(finding.host);
        if (finding.port && !asset.openPorts.some(p => p.port === finding.port)) {
          asset.openPorts.push({
            port: finding.port,
            service: finding.protocol || 'tcp',
            state: 'open'
          });
        }
      }
    }

    // 5. Evidence Locker Sealing
    const artifactName = `${importId}_${validation.sanitizedFilename}`;
    const evidenceId = `EVID-IMP-${importId.replace('IMP-', '')}`;
    const evidenceRecord = evidenceEngine.createEvidenceRecord(
      {
        jobId: `JOB-${importId}`,
        tenantId,
        engagementId,
        operatorId,
        toolId: `ext-${validation.format.toLowerCase()}`,
        toolName: `External Import [${validation.format}]`,
        target: Array.from(extractedTargetsSet)[0] || '127.0.0.1',
        profile: 'External Ingest',
        parameters: ['--import', validation.sanitizedFilename],
        status: 'COMPLETED',
        mode: 'LIVE',
        startTime: new Date().toISOString(),
        stdout: `[+] External tool result file ingested: ${validation.sanitizedFilename} (${validation.fileSizeBytes} bytes). SHA-256: ${validation.sha256}`,
        stderr: errors.join('\n'),
        artifacts: [
          {
            filename: artifactName,
            contentType: validation.format.endsWith('_XML') ? 'application/xml' : 'application/json',
            sizeBytes: validation.fileSizeBytes,
            sha256: validation.sha256,
            content: rawContent
          }
        ],
        findings: finalFindings
      },
      {
        id: `ext-${validation.format.toLowerCase()}`,
        name: `External Ingestion: ${validation.format}`,
        category: 'VULNERABILITY',
        binaryName: validation.format.toLowerCase(),
        description: 'External security assessment tool results ingestion engine.',
        availabilityStatus: 'INSTALLED',
        capabilityTier: 'RECON_READONLY',
        profiles: [],
        documentationUrl: '',
        installable: false,
        verificationCommand: '',
        isNativeBinary: false
      }
    );

    // 6. Cryptographic Audit Blockchain Record
    const auditBlock = auditLedger.appendBlock(
      operatorId,
      'EXTERNAL_TOOL_IMPORT_COMPLETED',
      tenantId,
      engagementId,
      Array.from(extractedTargetsSet).join(', ') || 'N/A',
      {
        importId,
        filename: validation.sanitizedFilename,
        format: validation.format,
        fileSizeBytes: validation.fileSizeBytes,
        sha256: validation.sha256,
        evidenceId: evidenceRecord.evidenceId,
        totalParsed: parsedFindings.length,
        duplicateCount,
        outOfScopeCount,
        validFindingsCount: finalFindings.length - duplicateCount,
        extractedTargets: Array.from(extractedTargetsSet)
      }
    );

    const record: ExternalToolImportRecord = {
      importId,
      filename,
      sanitizedFilename: validation.sanitizedFilename,
      format: validation.format,
      fileSizeBytes: validation.fileSizeBytes,
      sha256: validation.sha256,
      importedAt: new Date().toISOString(),
      engagementId,
      tenantId,
      operatorId,
      totalParsed: parsedFindings.length,
      validFindingsCount: finalFindings.length,
      duplicateCount,
      outOfScopeCount,
      extractedTargets: Array.from(extractedTargetsSet),
      findings: finalFindings,
      evidenceId: evidenceRecord.evidenceId,
      auditBlockId: `BLK-${auditBlock.index}`,
      status: errors.length > 0 && finalFindings.length === 0 ? 'REJECTED' : errors.length > 0 ? 'PARTIAL' : 'SUCCESS',
      errors,
      rawArtifactName: artifactName
    };

    this.importHistory.set(importId, record);
    return record;
  }

  // =========================================================================
  // PARSER IMPLEMENTATIONS
  // =========================================================================

  /**
   * Nmap XML Parser: Extracts hosts, addresses, ports, scripts, and vulnerabilities.
   */
  private parseNmapXml(
    content: string,
    importId: string,
    sourceFile: string,
    targetsSet: Set<string>,
    errors: string[]
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const parsed = this.xmlParser.parse(content);
    const nmaprun = parsed?.nmaprun;

    if (!nmaprun) {
      errors.push('Root <nmaprun> element not found in Nmap XML output.');
      return findings;
    }

    const rawHosts = nmaprun.host ? (Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host]) : [];

    for (const host of rawHosts) {
      try {
        let addr = '';
        if (host.address) {
          const addrs = Array.isArray(host.address) ? host.address : [host.address];
          const ipv4 = addrs.find((a: any) => a['@_addrtype'] === 'ipv4');
          addr = (ipv4 || addrs[0])?.['@_addr'] || '';
        }
        if (!addr) continue;

        targetsSet.add(addr);

        let hostname = '';
        if (host.hostnames?.hostname) {
          const hnames = Array.isArray(host.hostnames.hostname) ? host.hostnames.hostname : [host.hostnames.hostname];
          hostname = hnames[0]?.['@_name'] || '';
        }

        const ports = host.ports?.port ? (Array.isArray(host.ports.port) ? host.ports.port : [host.ports.port]) : [];

        for (const p of ports) {
          const portNum = parseInt(p['@_portid'], 10);
          const proto = (p['@_protocol'] || 'tcp').toUpperCase();
          const state = p.state?.['@_state'] || 'unknown';

          if (state !== 'open') continue;

          const service = p.service?.['@_name'] || 'unknown';
          const product = p.service?.['@_product'] || '';
          const version = p.service?.['@_version'] || '';
          const fullService = [product, version].filter(Boolean).join(' ') || service;

          // Check for scripts
          const scripts = p.script ? (Array.isArray(p.script) ? p.script : [p.script]) : [];

          if (scripts.length > 0) {
            for (const s of scripts) {
              const scriptId = s['@_id'] || 'nmap-script';
              const output = s['@_output'] || '';

              let severity: Severity = 'LOW';
              let cvss = 4.0;
              let cwe = 'CWE-200';

              if (scriptId.includes('vuln') || output.toLowerCase().includes('vulnerable')) {
                severity = 'HIGH';
                cvss = 7.5;
                cwe = 'CWE-937';
              } else if (scriptId.includes('cve') || scriptId.includes('exploit')) {
                severity = 'CRITICAL';
                cvss = 9.0;
                cwe = 'CWE-94';
              }

              findings.push({
                findingId: `FIND-NMAP-${findings.length + 1}-${importId.slice(-4)}`,
                jobId: `JOB-${importId}`,
                toolId: 'nmap-recon',
                sourceTool: 'Nmap Network Scanner',
                sourceFile,
                importId,
                title: `${scriptId}: ${fullService} on ${addr}:${portNum}`,
                description: `Nmap script probe '${scriptId}' detected findings on ${addr}:${portNum} (${fullService}). Output details:\n${output.slice(0, 500)}`,
                severity,
                cvssScore: cvss,
                cwe,
                owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
                host: addr,
                port: portNum,
                protocol: proto,
                evidenceSnippet: output.slice(0, 300),
                remediation: `Inspect and patch ${fullService} on port ${portNum} or restrict network exposure.`,
                confidence: 'CONFIRMED',
                validationStatus: 'UNVALIDATED',
                importedAt: new Date().toISOString()
              });
            }
          } else {
            // General open port exposure finding
            findings.push({
              findingId: `FIND-NMAP-${findings.length + 1}-${importId.slice(-4)}`,
              jobId: `JOB-${importId}`,
              toolId: 'nmap-recon',
              sourceTool: 'Nmap Network Scanner',
              sourceFile,
              importId,
              title: `Open Network Port: ${fullService} (${portNum}/${proto})`,
              description: `Nmap port scan identified open ${proto} service '${fullService}' listening on ${addr}:${portNum}.`,
              severity: 'INFO',
              cvssScore: 0.0,
              cwe: 'CWE-200',
              owaspCategory: 'A05:2021-Security Misconfiguration',
              host: addr,
              port: portNum,
              protocol: proto,
              evidenceSnippet: `Port: ${portNum}/${proto} | State: open | Service: ${fullService}`,
              remediation: `Verify if port ${portNum} is required for legitimate operations. Filter via firewall if unneeded.`,
              confidence: 'CONFIRMED',
              validationStatus: 'UNVALIDATED',
              importedAt: new Date().toISOString()
            });
          }
        }
      } catch (err: unknown) {
        errors.push(`Error parsing Nmap host block: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return findings;
  }

  /**
   * Nmap JSON Parser
   */
  private parseNmapJson(
    content: string,
    importId: string,
    sourceFile: string,
    targetsSet: Set<string>,
    errors: string[]
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const json = JSON.parse(content);
    const hosts = Array.isArray(json) ? json : json.hosts || (json.nmaprun ? [json.nmaprun.host].flat() : []);

    for (const h of hosts) {
      const addr = h.ip || h.address || h.host || h['@_addr'];
      if (!addr) continue;
      targetsSet.add(addr);

      const ports = h.ports || [];
      for (const p of ports) {
        const portNum = parseInt(p.port || p.portid || p['@_portid'], 10);
        const proto = (p.protocol || p['@_protocol'] || 'tcp').toUpperCase();
        const service = p.service?.name || p.service || 'unknown';

        findings.push({
          findingId: `FIND-NMAPJSON-${findings.length + 1}-${importId.slice(-4)}`,
          jobId: `JOB-${importId}`,
          toolId: 'nmap-recon',
          sourceTool: 'Nmap JSON Parser',
          sourceFile,
          importId,
          title: `Discovered Service: ${service} on ${addr}:${portNum}`,
          description: `Discovered open port ${portNum}/${proto} running ${service}.`,
          severity: 'INFO',
          cvssScore: 0.0,
          cwe: 'CWE-200',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          host: addr,
          port: portNum,
          protocol: proto,
          evidenceSnippet: `Port: ${portNum}/${proto} | Service: ${service}`,
          remediation: 'Restrict access to necessary networks only.',
          confidence: 'CONFIRMED',
          validationStatus: 'UNVALIDATED',
          importedAt: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  /**
   * Burp Suite XML Parser: Parses `<issues><issue>` records with detailed CVE/CWE and HTTP payloads.
   */
  private parseBurpXml(
    content: string,
    importId: string,
    sourceFile: string,
    targetsSet: Set<string>,
    errors: string[]
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const parsed = this.xmlParser.parse(content);
    const root = parsed.issues || parsed;
    const issueList = root.issue ? (Array.isArray(root.issue) ? root.issue : [root.issue]) : [];

    for (const issue of issueList) {
      try {
        const title = issue.name || 'Burp Suite Finding';
        const hostObj = issue.host;
        const host = (typeof hostObj === 'object' ? hostObj['#text'] || hostObj['@_ip'] : hostObj) || '127.0.0.1';
        const path = issue.path || '/';
        const location = issue.location || `${host}${path}`;

        targetsSet.add(host);

        // Map Burp Severities
        let severity: Severity = 'LOW';
        let cvss = 3.5;
        const rawSev = String(issue.severity || '').toUpperCase();
        if (rawSev === 'HIGH') {
          severity = 'HIGH';
          cvss = 8.2;
        } else if (rawSev === 'MEDIUM') {
          severity = 'MEDIUM';
          cvss = 6.1;
        } else if (rawSev === 'INFORMATION' || rawSev === 'INFO') {
          severity = 'INFO';
          cvss = 0.0;
        } else if (rawSev === 'CRITICAL') {
          severity = 'CRITICAL';
          cvss = 9.8;
        }

        // Map Confidence
        let confidence: NormalizedFinding['confidence'] = 'MEDIUM';
        const rawConf = String(issue.confidence || '').toUpperCase();
        if (rawConf === 'CERTAIN') confidence = 'CONFIRMED';
        else if (rawConf === 'FIRM') confidence = 'HIGH';
        else if (rawConf === 'TENTATIVE') confidence = 'LOW';

        // Extract CWE
        let cwe = 'CWE-200';
        const vulnClass = String(issue.vulnerabilityClassifications || '');
        const cweMatch = vulnClass.match(/CWE-(\d+)/i) || String(issue.issueBackground || '').match(/CWE-(\d+)/i);
        if (cweMatch) {
          cwe = `CWE-${cweMatch[1]}`;
        }

        // Extract Evidence
        let snippet = '';
        if (issue.issueDetail) {
          snippet = String(issue.issueDetail).replace(/<[^>]+>/g, '').slice(0, 300);
        } else if (issue.requestresponse) {
          const req = Array.isArray(issue.requestresponse) ? issue.requestresponse[0] : issue.requestresponse;
          snippet = String(req.request?.['#text'] || req.response?.['#text'] || '').slice(0, 300);
        }

        findings.push({
          findingId: `FIND-BURP-${findings.length + 1}-${importId.slice(-4)}`,
          jobId: `JOB-${importId}`,
          toolId: 'burp-api',
          sourceTool: 'PortSwigger Burp Suite',
          sourceFile,
          importId,
          title,
          description: String(issue.issueDetail || issue.issueBackground || 'Burp vulnerability detection').replace(/<[^>]+>/g, '').slice(0, 500),
          severity,
          cvssScore: cvss,
          cwe,
          owaspCategory: 'A03:2021-Injection',
          host,
          path,
          protocol: location.startsWith('https') ? 'HTTPS' : 'HTTP',
          evidenceSnippet: snippet || `Location: ${location}`,
          remediation: String(issue.remediationBackground || issue.remediationDetail || 'Follow OWASP remediation recommendations.').replace(/<[^>]+>/g, '').slice(0, 400),
          confidence,
          validationStatus: 'UNVALIDATED',
          importedAt: new Date().toISOString()
        });
      } catch (err: unknown) {
        errors.push(`Error parsing Burp XML issue: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return findings;
  }

  /**
   * Burp Suite JSON Parser
   */
  private parseBurpJson(
    content: string,
    importId: string,
    sourceFile: string,
    targetsSet: Set<string>,
    errors: string[]
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const json = JSON.parse(content);
    const issues = Array.isArray(json) ? json : json.issues || [];

    for (const issue of issues) {
      const host = issue.host || issue.target || '127.0.0.1';
      targetsSet.add(host);

      findings.push({
        findingId: `FIND-BURPJSON-${findings.length + 1}-${importId.slice(-4)}`,
        jobId: `JOB-${importId}`,
        toolId: 'burp-api',
        sourceTool: 'PortSwigger Burp Suite JSON',
        sourceFile,
        importId,
        title: issue.name || issue.title || 'Burp Suite Finding',
        description: issue.issueDetail || issue.description || 'Vulnerability detected by Burp Scanner.',
        severity: (issue.severity?.toUpperCase() as Severity) || 'MEDIUM',
        cvssScore: issue.cvssScore || 5.0,
        cwe: issue.cwe || 'CWE-200',
        owaspCategory: 'A03:2021-Injection',
        host,
        path: issue.path || '/',
        evidenceSnippet: (issue.evidence || issue.request || '').slice(0, 300),
        remediation: issue.remediation || 'Remediate vulnerability according to standard guidelines.',
        confidence: 'HIGH',
        validationStatus: 'UNVALIDATED',
        importedAt: new Date().toISOString()
      });
    }

    return findings;
  }

  /**
   * Nessus XML (.nessus) Parser: Parses ReportHost and ReportItem tags with CVE, CVSS, and plugin outputs.
   */
  private parseNessusXml(
    content: string,
    importId: string,
    sourceFile: string,
    targetsSet: Set<string>,
    errors: string[]
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const parsed = this.xmlParser.parse(content);
    const report = parsed?.NessusClientData_v2?.Report || parsed?.Report;

    if (!report) {
      errors.push('Root <NessusClientData_v2> or <Report> element not found in Nessus file.');
      return findings;
    }

    const reportHosts = report.ReportHost ? (Array.isArray(report.ReportHost) ? report.ReportHost : [report.ReportHost]) : [];

    for (const host of reportHosts) {
      try {
        const hostName = host['@_name'] || '127.0.0.1';
        targetsSet.add(hostName);

        const items = host.ReportItem ? (Array.isArray(host.ReportItem) ? host.ReportItem : [host.ReportItem]) : [];

        for (const item of items) {
          const pluginName = item['@_pluginName'] || 'Nessus Finding';
          const pluginId = item['@_pluginID'] || '';
          const port = parseInt(item['@_port'], 10) || undefined;
          const proto = (item['@_protocol'] || 'tcp').toUpperCase();
          const rawSev = parseInt(item['@_severity'], 10);

          let severity: Severity = 'INFO';
          let cvss = 0.0;
          if (rawSev === 4) {
            severity = 'CRITICAL';
            cvss = 9.5;
          } else if (rawSev === 3) {
            severity = 'HIGH';
            cvss = 7.5;
          } else if (rawSev === 2) {
            severity = 'MEDIUM';
            cvss = 5.5;
          } else if (rawSev === 1) {
            severity = 'LOW';
            cvss = 3.0;
          }

          if (item.cvss_base_score || item.cvss3_base_score) {
            cvss = parseFloat(item.cvss3_base_score || item.cvss_base_score);
          }

          let cwe = 'CWE-200';
          if (item.cwe) {
            cwe = String(item.cwe).startsWith('CWE-') ? String(item.cwe) : `CWE-${item.cwe}`;
          }

          const cveList: string[] = [];
          if (item.cve) {
            const rawCves = Array.isArray(item.cve) ? item.cve : [item.cve];
            cveList.push(...rawCves.map(String));
          }

          const references: string[] = [];
          if (item.see_also) {
            references.push(...String(item.see_also).split('\n').map(s => s.trim()).filter(Boolean));
          }

          const description = String(item.description || item.synopsis || pluginName).slice(0, 500);
          const snippet = String(item.plugin_output || item.synopsis || '').slice(0, 300);
          const remediation = String(item.solution || 'Apply vendor patches and updates.').slice(0, 400);

          findings.push({
            findingId: `FIND-NESSUS-${findings.length + 1}-${importId.slice(-4)}`,
            jobId: `JOB-${importId}`,
            toolId: 'openvas-vuln',
            sourceTool: `Tenable Nessus (Plugin ${pluginId})`,
            sourceFile,
            importId,
            title: pluginName,
            description,
            severity,
            cvssScore: cvss,
            cwe,
            owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
            host: hostName,
            port: port && port > 0 ? port : undefined,
            protocol: proto,
            evidenceSnippet: snippet || `Plugin ID: ${pluginId}`,
            remediation,
            cveList,
            cve: cveList[0],
            references,
            confidence: 'CONFIRMED',
            validationStatus: 'UNVALIDATED',
            importedAt: new Date().toISOString()
          });
        }
      } catch (err: unknown) {
        errors.push(`Error parsing Nessus host: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    return findings;
  }

  /**
   * Nuclei JSONL Parser: Parses streaming/newline-delimited JSON output from ProjectDiscovery Nuclei.
   */
  private parseNucleiJsonl(
    content: string,
    importId: string,
    sourceFile: string,
    targetsSet: Set<string>,
    errors: string[]
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    const lines = content.split('\n').filter(l => l.trim().length > 0);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      try {
        const item = JSON.parse(line);
        const templateId = item['template-id'] || item['templateID'] || 'nuclei-template';
        const info = item.info || {};
        const title = info.name || templateId;
        const rawSev = String(info.severity || 'low').toUpperCase();
        const host = item.host || item['matched-at'] || '127.0.0.1';

        // Extract clean host/IP
        let cleanHost = host;
        try {
          if (host.includes('://')) {
            cleanHost = new URL(host).hostname;
          } else {
            cleanHost = host.split(':')[0];
          }
        } catch {}
        targetsSet.add(cleanHost);

        let severity: Severity = 'LOW';
        let cvss = 3.0;
        if (rawSev === 'CRITICAL') {
          severity = 'CRITICAL';
          cvss = 9.5;
        } else if (rawSev === 'HIGH') {
          severity = 'HIGH';
          cvss = 7.5;
        } else if (rawSev === 'MEDIUM') {
          severity = 'MEDIUM';
          cvss = 5.5;
        } else if (rawSev === 'INFO') {
          severity = 'INFO';
          cvss = 0.0;
        }

        if (info.classification?.['cvss-score']) {
          cvss = parseFloat(info.classification['cvss-score']);
        }

        let cwe = 'CWE-200';
        if (info.classification?.['cwe-id']) {
          const cweVal = info.classification['cwe-id'];
          cwe = Array.isArray(cweVal) ? cweVal[0] : String(cweVal);
          if (!cwe.startsWith('CWE-')) cwe = `CWE-${cwe}`;
        }

        const cveList: string[] = [];
        if (info.classification?.['cve-id']) {
          const cveVal = info.classification['cve-id'];
          if (Array.isArray(cveVal)) cveList.push(...cveVal);
          else cveList.push(String(cveVal));
        }

        const references: string[] = [];
        if (info.reference) {
          if (Array.isArray(info.reference)) references.push(...info.reference);
          else references.push(String(info.reference));
        }

        const snippet = item['extracted-results'] || item['curl-command'] || item['matcher-name'] || item['matched-at'] || '';

        findings.push({
          findingId: `FIND-NUCLEI-${findings.length + 1}-${importId.slice(-4)}`,
          jobId: `JOB-${importId}`,
          toolId: 'nuclei-vuln',
          sourceTool: `ProjectDiscovery Nuclei (${templateId})`,
          sourceFile,
          importId,
          title,
          description: info.description || `Nuclei template ${templateId} matched on target ${host}.`,
          severity,
          cvssScore: cvss,
          cwe,
          owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
          host: cleanHost,
          path: item.path || (host.includes('/') ? new URL(host.includes('://') ? host : `http://${host}`).pathname : '/'),
          evidenceSnippet: String(snippet).slice(0, 300),
          remediation: info.remediation || 'Upgrade software or apply recommended template remediations.',
          cveList,
          cve: cveList[0],
          references,
          confidence: 'CONFIRMED',
          validationStatus: 'UNVALIDATED',
          importedAt: new Date().toISOString()
        });
      } catch (lineErr: unknown) {
        errors.push(`Line ${i + 1} JSON parse error: ${lineErr instanceof Error ? lineErr.message : String(lineErr)}`);
      }
    }

    return findings;
  }

  // =========================================================================
  // ACCESSORS & STATUS UPDATES
  // =========================================================================

  public getAllImports(): ExternalToolImportRecord[] {
    return Array.from(this.importHistory.values()).sort(
      (a, b) => new Date(b.importedAt).getTime() - new Date(a.importedAt).getTime()
    );
  }

  public getImport(importId: string): ExternalToolImportRecord | undefined {
    return this.importHistory.get(importId);
  }

  public getAllImportedFindings(): NormalizedFinding[] {
    return Array.from(this.importedFindings.values());
  }

  public getFinding(findingId: string): NormalizedFinding | undefined {
    return this.importedFindings.get(findingId);
  }

  public updateFindingValidation(
    findingId: string,
    status: NormalizedFinding['validationStatus'],
    operatorId: string,
    notes?: string
  ): boolean {
    const finding = this.importedFindings.get(findingId);
    if (!finding) return false;

    finding.validationStatus = status;

    // Log validation action in audit ledger
    auditLedger.appendBlock(
      operatorId,
      'FINDING_VALIDATION_STATUS_UPDATED',
      'TENANT-AWM-01',
      'ENG-2026-ALPHA',
      finding.host,
      {
        findingId,
        newStatus: status,
        notes: notes || 'Operator manual review completed',
        toolId: finding.toolId,
        severity: finding.severity
      }
    );

    return true;
  }
}

export const externalToolImportEngine = ExternalToolImportEngine.getInstance();
