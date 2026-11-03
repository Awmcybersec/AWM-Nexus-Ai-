/**
 * AWM Nexus — Live HTTP / Web API Security Prober
 * Performs genuine HTTP/HTTPS requests using native cURL binary and Node.js fetch
 * Inspects security headers (CSP, HSTS, X-Frame-Options, CORS), server banners, and API endpoints
 */

export interface SecurityHeaderCheck {
  header: string;
  value?: string;
  present: boolean;
  compliant: boolean;
  recommendation: string;
}

export interface HTTPProbeResult {
  targetUrl: string;
  statusCode: number;
  statusText: string;
  httpVersion: string;
  headers: Record<string, string>;
  securityHeaders: SecurityHeaderCheck[];
  serverBanner?: string;
  poweredBy?: string;
  contentLength: number;
  contentType?: string;
  latencyMs: number;
  rawOutput: string;
}

export async function executeLiveHTTPProbe(
  target: string,
  method: string = 'GET',
  customHeaders: Record<string, string> = {}
): Promise<HTTPProbeResult> {
  const startTime = Date.now();
  let url = target.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `http://${url}`;
  }

  // 1. First attempt via native cURL binary
  try {
    const { exec } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const execAsync = promisify(exec);

    const cmd = `curl -i -s -S -k -X ${method} --max-time 6 "${url}" 2>&1`;
    const { stdout } = await execAsync(cmd, { timeout: 7000 });
    if (stdout.startsWith('HTTP/')) {
      const parsed = parseRawHttpResponse(stdout, url, Date.now() - startTime);
      return parsed;
    }
  } catch {
    // Fall back to Node fetch
  }

  // 2. Direct Node.js fetch probe
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);

    const resp = await fetch(url, {
      method,
      headers: {
        'User-Agent': 'AWM-Nexus-Security-Scanner/4.8 (Lead Operator Pentest Suite)',
        ...customHeaders
      },
      signal: controller.signal
    });
    clearTimeout(timeout);

    const latencyMs = Date.now() - startTime;
    const headers: Record<string, string> = {};
    resp.headers.forEach((val, key) => {
      headers[key.toLowerCase()] = val;
    });

    const bodyText = await resp.text();
    const securityHeaders = evaluateSecurityHeaders(headers);

    let raw = `HTTP/1.1 ${resp.status} ${resp.statusText}\r\n`;
    for (const [k, v] of Object.entries(headers)) {
      raw += `${k}: ${v}\r\n`;
    }
    raw += `\r\n`;
    raw += bodyText.slice(0, 500);
    if (bodyText.length > 500) {
      raw += `\n... [Truncated ${bodyText.length - 500} bytes]`;
    }

    return {
      targetUrl: url,
      statusCode: resp.status,
      statusText: resp.statusText || 'OK',
      httpVersion: '1.1',
      headers,
      securityHeaders,
      serverBanner: headers['server'],
      poweredBy: headers['x-powered-by'],
      contentLength: bodyText.length,
      contentType: headers['content-type'],
      latencyMs,
      rawOutput: raw
    };
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    const latencyMs = Date.now() - startTime;
    const raw = `[!] HTTP Probe Connection Error to ${url}\nError: ${errMsg}\nQuery Duration: ${latencyMs}ms`;

    return {
      targetUrl: url,
      statusCode: 0,
      statusText: 'CONNECTION_FAILED',
      httpVersion: 'N/A',
      headers: {},
      securityHeaders: [],
      contentLength: 0,
      latencyMs,
      rawOutput: raw
    };
  }
}

function parseRawHttpResponse(raw: string, targetUrl: string, latencyMs: number): HTTPProbeResult {
  const parts = raw.split(/\r?\n\r?\n/);
  const headerBlock = parts[0] || '';
  const bodyBlock = parts.slice(1).join('\n\n');

  const lines = headerBlock.split(/\r?\n/);
  const statusLine = lines[0] || 'HTTP/1.1 200 OK';
  const statusMatch = statusLine.match(/HTTP\/([\d.]+)\s+(\d+)\s*(.*)/i);

  const httpVersion = statusMatch ? statusMatch[1] : '1.1';
  const statusCode = statusMatch ? parseInt(statusMatch[2], 10) : 200;
  const statusText = statusMatch ? statusMatch[3] : 'OK';

  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx > 0) {
      const key = lines[i].slice(0, colonIdx).trim().toLowerCase();
      const val = lines[i].slice(colonIdx + 1).trim();
      headers[key] = val;
    }
  }

  const securityHeaders = evaluateSecurityHeaders(headers);

  return {
    targetUrl,
    statusCode,
    statusText,
    httpVersion,
    headers,
    securityHeaders,
    serverBanner: headers['server'],
    poweredBy: headers['x-powered-by'],
    contentLength: bodyBlock.length,
    contentType: headers['content-type'],
    latencyMs,
    rawOutput: raw
  };
}

function evaluateSecurityHeaders(headers: Record<string, string>): SecurityHeaderCheck[] {
  const checks: SecurityHeaderCheck[] = [
    {
      header: 'Strict-Transport-Security',
      value: headers['strict-transport-security'],
      present: !!headers['strict-transport-security'],
      compliant: !!headers['strict-transport-security'] && headers['strict-transport-security'].includes('max-age'),
      recommendation: 'Enforce HSTS with max-age >= 31536000 and includeSubDomains'
    },
    {
      header: 'Content-Security-Policy',
      value: headers['content-security-policy'],
      present: !!headers['content-security-policy'],
      compliant: !!headers['content-security-policy'] && !headers['content-security-policy'].includes("'unsafe-inline'"),
      recommendation: "Implement strict CSP avoiding 'unsafe-eval' and 'unsafe-inline'"
    },
    {
      header: 'X-Frame-Options',
      value: headers['x-frame-options'],
      present: !!headers['x-frame-options'],
      compliant: headers['x-frame-options'] === 'DENY' || headers['x-frame-options'] === 'SAMEORIGIN',
      recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking'
    },
    {
      header: 'X-Content-Type-Options',
      value: headers['x-content-type-options'],
      present: !!headers['x-content-type-options'],
      compliant: headers['x-content-type-options'] === 'nosniff',
      recommendation: 'Set X-Content-Type-Options: nosniff to stop MIME-sniffing exploits'
    },
    {
      header: 'Referrer-Policy',
      value: headers['referrer-policy'],
      present: !!headers['referrer-policy'],
      compliant: !!headers['referrer-policy'] && headers['referrer-policy'].includes('strict-origin'),
      recommendation: 'Set Referrer-Policy: strict-origin-when-cross-origin'
    },
    {
      header: 'Access-Control-Allow-Origin',
      value: headers['access-control-allow-origin'],
      present: !!headers['access-control-allow-origin'],
      compliant: headers['access-control-allow-origin'] !== '*',
      recommendation: 'Avoid wildcard CORS (*); explicitly whitelist trusted origin domains'
    }
  ];

  return checks;
}
