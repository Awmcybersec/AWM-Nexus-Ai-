/**
 * AWM Nexus — Finding Parser & Normalizer
 * Converts raw security tool stdout/stderr into normalized vulnerability findings with CVSS and CWE classification
 */

import { NormalizedFinding, SecurityTool, Severity } from '../types';

export class FindingParser {
  public parseOutput(
    tool: SecurityTool,
    jobId: string,
    target: string,
    stdout: string,
    stderr: string
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];

    switch (tool.binaryName) {
      case 'curl':
        this.parseCurlOutput(findings, jobId, tool.id, target, stdout);
        break;
      case 'openssl':
        this.parseOpensslOutput(findings, jobId, tool.id, target, stdout);
        break;
      case 'nmap':
        this.parseNmapOutput(findings, jobId, tool.id, target, stdout);
        break;
      case 'nuclei':
        this.parseNucleiOutput(findings, jobId, tool.id, target, stdout);
        break;
      case 'ffuf':
      case 'gobuster':
        this.parseDirectoryOutput(findings, jobId, tool.id, target, stdout);
        break;
      case 'dig':
      case 'dnsrecon':
        this.parseDnsOutput(findings, jobId, tool.id, target, stdout);
        break;
      default:
        this.parseGenericOutput(findings, jobId, tool.id, target, stdout);
        break;
    }

    return findings;
  }

  private parseCurlOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    const headers = stdout.toLowerCase();

    // Check for missing Content-Security-Policy
    if (!headers.includes('content-security-policy:')) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-01`,
        jobId,
        toolId,
        title: 'Missing Content-Security-Policy (CSP) Header',
        description: 'The target web server does not enforce a Content-Security-Policy header, increasing susceptibility to Cross-Site Scripting (XSS) and code injection.',
        severity: 'MEDIUM',
        cvssScore: 5.4,
        cwe: 'CWE-693',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        host: target,
        protocol: 'HTTP/HTTPS',
        evidenceSnippet: 'Response headers missing: Content-Security-Policy',
        remediation: 'Implement a strict Content-Security-Policy HTTP response header restricting script and object sources.',
        confidence: 'CONFIRMED',
        validationStatus: 'CONFIRMED'
      });
    }

    // Check for missing HSTS
    if (!headers.includes('strict-transport-security:')) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-02`,
        jobId,
        toolId,
        title: 'Missing Strict-Transport-Security (HSTS) Header',
        description: 'The web application fails to declare the HSTS header, allowing potential Man-in-the-Middle (MitM) downgrade attacks over plain HTTP.',
        severity: 'LOW',
        cvssScore: 3.7,
        cwe: 'CWE-319',
        owaspCategory: 'A02:2021-Cryptographic Failures',
        host: target,
        protocol: 'HTTP/HTTPS',
        evidenceSnippet: 'Response headers missing: Strict-Transport-Security',
        remediation: 'Enable HSTS header with max-age=31536000; includeSubDomains; preload.',
        confidence: 'CONFIRMED',
        validationStatus: 'CONFIRMED'
      });
    }

    // Check for verbose server header / banner leakage
    const serverMatch = stdout.match(/Server:\s*([^\r\n]+)/i);
    if (serverMatch && serverMatch[1]) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-03`,
        jobId,
        toolId,
        title: 'Web Server Version & Banner Disclosure',
        description: `The web server discloses detailed software version banner: '${serverMatch[1]}', aiding reconnaissance for version-specific exploits.`,
        severity: 'LOW',
        cvssScore: 3.1,
        cwe: 'CWE-200',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        host: target,
        protocol: 'HTTP',
        evidenceSnippet: serverMatch[0],
        remediation: 'Configure the web server to suppress or genericize the Server and X-Powered-By response headers.',
        confidence: 'CONFIRMED',
        validationStatus: 'CONFIRMED'
      });
    }
  }

  private parseOpensslOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    if (stdout.includes('Protocol  : TLSv1') || stdout.includes('Protocol  : TLSv1.0') || stdout.includes('Protocol  : TLSv1.1')) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-01`,
        jobId,
        toolId,
        title: 'Depreciated TLS 1.0/1.1 Protocol Enabled',
        description: 'The remote TLS endpoint negotiates legacy TLS 1.0/1.1 protocols which contain known cryptographic weaknesses.',
        severity: 'MEDIUM',
        cvssScore: 5.9,
        cwe: 'CWE-326',
        owaspCategory: 'A02:2021-Cryptographic Failures',
        host: target,
        port: 443,
        protocol: 'TLS',
        evidenceSnippet: stdout.split('\n').find(l => l.includes('Protocol')) || 'Protocol: TLSv1.0',
        remediation: 'Disable TLS 1.0 and TLS 1.1 across all web and load balancer configurations; enforce TLS 1.2 and TLS 1.3 only.',
        confidence: 'CONFIRMED',
        validationStatus: 'CONFIRMED'
      });
    }

    if (stdout.includes('Verify return code: 18') || stdout.includes('self-signed certificate')) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-02`,
        jobId,
        toolId,
        title: 'Untrusted Self-Signed TLS Certificate',
        description: 'The server is presenting a self-signed TLS certificate not signed by a recognized Certificate Authority.',
        severity: 'MEDIUM',
        cvssScore: 4.8,
        cwe: 'CWE-295',
        owaspCategory: 'A07:2021-Identification and Authentication Failures',
        host: target,
        port: 443,
        protocol: 'TLS',
        evidenceSnippet: 'Verify return code: 18 (self signed certificate)',
        remediation: 'Install a valid TLS certificate issued by a trusted public or internal enterprise Certificate Authority.',
        confidence: 'CONFIRMED',
        validationStatus: 'CONFIRMED'
      });
    }
  }

  private parseNmapOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    const lines = stdout.split('\n');
    for (const line of lines) {
      if (line.includes('/tcp') && line.includes('open')) {
        const parts = line.trim().split(/\s+/);
        const portProto = parts[0] || '';
        const [portStr] = portProto.split('/');
        const port = parseInt(portStr, 10);
        const service = parts[2] || 'unknown';

        if (port === 21) {
          findings.push({
            findingId: `FIND-${jobId.slice(-6)}-P21`,
            jobId,
            toolId,
            title: 'Unencrypted FTP Service Detected (Port 21)',
            description: 'Legacy FTP service exposes credentials and data in cleartext over the network.',
            severity: 'MEDIUM',
            cvssScore: 5.3,
            cwe: 'CWE-319',
            owaspCategory: 'A02:2021-Cryptographic Failures',
            host: target,
            port: 21,
            protocol: 'FTP',
            evidenceSnippet: line.trim(),
            remediation: 'Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS with enforced TLS.',
            confidence: 'CONFIRMED',
            validationStatus: 'CONFIRMED'
          });
        } else if (port === 23) {
          findings.push({
            findingId: `FIND-${jobId.slice(-6)}-P23`,
            jobId,
            toolId,
            title: 'Cleartext Telnet Service Exposed (Port 23)',
            description: 'Telnet transmits management credentials in plaintext without encryption.',
            severity: 'HIGH',
            cvssScore: 7.5,
            cwe: 'CWE-319',
            owaspCategory: 'A02:2021-Cryptographic Failures',
            host: target,
            port: 23,
            protocol: 'Telnet',
            evidenceSnippet: line.trim(),
            remediation: 'Disable Telnet daemon immediately and mandate SSHv2 with key-based authentication.',
            confidence: 'CONFIRMED',
            validationStatus: 'CONFIRMED'
          });
        } else if (port === 3389) {
          findings.push({
            findingId: `FIND-${jobId.slice(-6)}-P3389`,
            jobId,
            toolId,
            title: 'Exposed Microsoft Remote Desktop Protocol (RDP)',
            description: 'Port 3389 is exposed, presenting a target for brute-force credential stuffing and BlueKeep-style vulnerabilities.',
            severity: 'MEDIUM',
            cvssScore: 6.5,
            cwe: 'CWE-284',
            owaspCategory: 'A01:2021-Broken Access Control',
            host: target,
            port: 3389,
            protocol: 'RDP',
            evidenceSnippet: line.trim(),
            remediation: 'Place RDP behind a VPN/ZTNA gateway with MFA enforcement; restrict firewall access.',
            confidence: 'HIGH',
            validationStatus: 'CONFIRMED'
          });
        }
      }
    }
  }

  private parseNucleiOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    const lines = stdout.split('\n');
    let idx = 1;
    for (const line of lines) {
      if (line.includes('[critical]') || line.includes('[high]') || line.includes('[medium]')) {
        const severity: Severity = line.includes('[critical]') ? 'CRITICAL' : line.includes('[high]') ? 'HIGH' : 'MEDIUM';
        findings.push({
          findingId: `FIND-${jobId.slice(-6)}-${idx++}`,
          jobId,
          toolId,
          title: `Nuclei Detection: ${line.split(']')[0]?.replace('[', '') || 'Known CVE Issue'}`,
          description: line.trim(),
          severity,
          cvssScore: severity === 'CRITICAL' ? 9.8 : severity === 'HIGH' ? 8.2 : 5.5,
          cwe: 'CWE-937',
          owaspCategory: 'A06:2021-Vulnerable and Outdated Components',
          host: target,
          protocol: 'HTTP',
          evidenceSnippet: line.trim(),
          remediation: 'Upgrade vulnerable component to the latest vendor patched release.',
          confidence: 'CONFIRMED',
          validationStatus: 'CONFIRMED'
        });
      }
    }
  }

  private parseDirectoryOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    const sensitivePaths = ['.env', '.git', 'admin', 'swagger.json', 'phpinfo.php', 'config.json', 'actuator'];
    for (const path of sensitivePaths) {
      if (stdout.includes(path)) {
        findings.push({
          findingId: `FIND-${jobId.slice(-6)}-${path.replace(/[^a-z0-9]/gi, '')}`,
          jobId,
          toolId,
          title: `Sensitive Endpoint / File Exposed: /${path}`,
          description: `Discovered accessible sensitive administrative or configuration path: /${path}`,
          severity: path.includes('.env') || path.includes('.git') ? 'HIGH' : 'MEDIUM',
          cvssScore: path.includes('.env') ? 8.6 : 6.1,
          cwe: 'CWE-538',
          owaspCategory: 'A05:2021-Security Misconfiguration',
          host: target,
          path: `/${path}`,
          protocol: 'HTTP',
          evidenceSnippet: `Status 200 OK: /${path}`,
          remediation: `Restrict access to /${path} via web server configuration or remove sensitive files from docroot.`,
          confidence: 'CONFIRMED',
          validationStatus: 'CONFIRMED'
        });
      }
    }
  }

  private parseDnsOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    if (stdout.includes('AXFR') && stdout.includes('Transfer successful')) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-AXFR`,
        jobId,
        toolId,
        title: 'DNS Zone Transfer (AXFR) Information Leakage',
        description: 'The authoritative DNS server allows unrestricted zone transfers (AXFR), exposing internal DNS namespace.',
        severity: 'HIGH',
        cvssScore: 7.5,
        cwe: 'CWE-200',
        owaspCategory: 'A01:2021-Broken Access Control',
        host: target,
        protocol: 'DNS',
        evidenceSnippet: 'AXFR transfer successful',
        remediation: 'Restrict DNS zone transfers to authorized secondary nameserver IPs only.',
        confidence: 'CONFIRMED',
        validationStatus: 'CONFIRMED'
      });
    }
  }

  private parseGenericOutput(findings: NormalizedFinding[], jobId: string, toolId: string, target: string, stdout: string) {
    // Default pass-through if specific keywords found
    if (stdout.includes('VULNERABILITY') || stdout.includes('EXPLOITABLE')) {
      findings.push({
        findingId: `FIND-${jobId.slice(-6)}-GEN01`,
        jobId,
        toolId,
        title: 'Security Anomaly Flagged in Tool Telemetry',
        description: 'Automated parser identified positive security indicators in raw tool output.',
        severity: 'MEDIUM',
        cvssScore: 5.0,
        cwe: 'CWE-699',
        owaspCategory: 'A05:2021-Security Misconfiguration',
        host: target,
        evidenceSnippet: stdout.slice(0, 200),
        remediation: 'Review tool raw output and verify affected software component.',
        confidence: 'MEDIUM',
        validationStatus: 'UNVALIDATED'
      });
    }
  }
}

export const findingParser = new FindingParser();
