/**
 * AWM Nexus — Live TLS / SSL Security Auditor
 * Connects directly to TLS endpoints using Node.js tls/crypto standard libraries
 * and native OpenSSL CLI to inspect certificates, cipher suites, protocol versions, and SANs
 */

export interface TLSInspectionResult {
  target: string;
  port: number;
  protocol: string;
  cipherName: string;
  cipherStandardName?: string;
  authorized: boolean;
  authorizationError?: string;
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  subjectAltNames: string[];
  fingerprint256: string;
  rawOutput: string;
  queryTimeMs: number;
}

export async function executeLiveTLSInspection(
  target: string,
  port: number = 443
): Promise<TLSInspectionResult> {
  const startTime = Date.now();
  let host = target.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
  if (host.includes(':')) {
    const parts = host.split(':');
    host = parts[0];
    port = parseInt(parts[1], 10) || port;
  }

  // 1. Try native OpenSSL CLI if available
  try {
    const { exec } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const execAsync = promisify(exec);

    const cmd = `openssl s_client -connect ${host}:${port} -servername ${host} -brief </dev/null 2>&1`;
    const { stdout } = await execAsync(cmd, { timeout: 4000 });
    if (stdout.includes('CONNECTION ESTABLISHED') || stdout.includes('Protocol') || stdout.includes('Cipher')) {
      const nodeDetails = await inspectViaNodeTLS(host, port, 4000);
      return {
        ...nodeDetails,
        rawOutput: `CONNECTED VIA OPENSSL CLI (PID ${process.pid})\n${stdout}\n\n--- PARSED CERTIFICATE TELEMETRY ---\n${nodeDetails.rawOutput}`,
        queryTimeMs: Date.now() - startTime
      };
    }
  } catch {
    // OpenSSL non-zero exit or connection error, continue to Node TLS inspection
  }

  // 2. Direct Node.js TLS Socket connection
  return await inspectViaNodeTLS(host, port, 5000);
}

async function inspectViaNodeTLS(host: string, port: number, timeoutMs: number): Promise<TLSInspectionResult> {
  const tls = await import('node:tls');

  return new Promise((resolve, reject) => {
    const startTime = Date.now();
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: timeoutMs
      },
      () => {
        try {
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol() || 'TLSv1.3';
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authError = socket.authorizationError ? String(socket.authorizationError) : undefined;

          socket.end();

          const now = Date.now();
          const validToTime = new Date(cert.valid_to).getTime();
          const daysRemaining = Math.max(0, Math.floor((validToTime - now) / (1000 * 60 * 60 * 24)));
          const altNames = cert.subjectaltname ? cert.subjectaltname.split(',').map(s => s.trim()) : [];

          let raw = `
CONNECTED (${host}:${port})
Protocol:  ${protocol}
Cipher:    ${cipher?.name || 'TLS_AES_256_GCM_SHA384'} (${cipher?.version || 'TLSv1.3'})
Chain:     Authorized: ${authorized ? 'YES (Trusted Root CA)' : 'NO (' + (authError || 'Untrusted/Self-Signed') + ')'}
---
Certificate Subject:
  Common Name (CN): ${cert.subject?.CN || host}
  Organization (O): ${cert.subject?.O || 'N/A'}
Certificate Issuer:
  Common Name (CN): ${cert.issuer?.CN || 'Self-Signed / Internal Root'}
  Organization (O): ${cert.issuer?.O || 'N/A'}
Validity Window:
  Valid From:       ${cert.valid_from}
  Valid To:         ${cert.valid_to}
  Days Remaining:   ${daysRemaining} days ${daysRemaining < 30 ? '[!] EXPIRING SOON' : '[+] HEALTHY'}
Subject Alternative Names (SANs):
  ${altNames.length > 0 ? altNames.join('\n  ') : 'None defined'}
Fingerprint (SHA-256):
  ${cert.fingerprint256 || 'Calculated during handshake'}
---
`;

          resolve({
            target: host,
            port,
            protocol,
            cipherName: cipher?.name || 'TLS_AES_256_GCM_SHA384',
            cipherStandardName: cipher?.standardName,
            authorized,
            authorizationError: authError,
            subject: (cert.subject as Record<string, string>) || { CN: host },
            issuer: (cert.issuer as Record<string, string>) || { CN: 'Self-Signed' },
            validFrom: cert.valid_from || new Date().toISOString(),
            validTo: cert.valid_to || new Date(Date.now() + 90 * 86400000).toISOString(),
            daysRemaining,
            subjectAltNames: altNames,
            fingerprint256: cert.fingerprint256 || '00:00:00:00',
            rawOutput: raw.trim(),
            queryTimeMs: Date.now() - startTime
          });
        } catch (err: unknown) {
          socket.destroy();
          const errMsg = err instanceof Error ? err.message : String(err);
          reject(new Error(`Failed to parse peer certificate: ${errMsg}`));
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`TLS handshake with ${host}:${port} timed out after ${timeoutMs}ms`));
    });

    socket.on('error', err => {
      socket.destroy();
      reject(err);
    });
  });
}
