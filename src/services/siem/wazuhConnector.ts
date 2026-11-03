/**
 * AWM Nexus — Real Wazuh SIEM Connector
 * Genuine REST API integration with Wazuh Manager API.
 * Authenticates via POST /security/user/authenticate, queries /alerts and /agents,
 * normalizes rule levels, extracts MITRE ATT&CK IDs, and converts to AWM Nexus telemetry.
 */

import {
  SIEMConnector,
  SIEMProviderType,
  SIEMConfig,
  SIEMConnectionStatus,
  SIEMAlertFilter,
  NormalizedSIEMAlert
} from './types';
import { Severity, DefensiveTelemetryEvent } from '../../types';

export class WazuhConnector implements SIEMConnector {
  public readonly id = 'wazuh';
  public readonly name = 'Wazuh Enterprise SIEM (REST API v4)';
  public readonly providerType: SIEMProviderType = 'WAZUH';

  private config: SIEMConfig;
  private cachedToken: string | null = null;
  private tokenExpiresAt: number = 0;

  constructor(initialConfig?: Partial<SIEMConfig>) {
    this.config = {
      provider: 'WAZUH',
      baseUrl: initialConfig?.baseUrl || 'https://wazuh-manager.corp.internal',
      port: initialConfig?.port || 55000,
      username: initialConfig?.username || 'wazuh-api-admin',
      password: initialConfig?.password || '',
      verifySsl: initialConfig?.verifySsl ?? false,
      minAlertLevel: initialConfig?.minAlertLevel || 3,
      timeoutMs: initialConfig?.timeoutMs || 8000,
      syncIntervalSeconds: initialConfig?.syncIntervalSeconds || 60,
      enabled: initialConfig?.enabled ?? false,
      agentFilter: initialConfig?.agentFilter
    };
  }

  public updateConfig(newConfig: Partial<SIEMConfig>) {
    this.config = { ...this.config, ...newConfig };
    this.cachedToken = null; // Invalidate cached token on config changes
  }

  public getConfig(): SIEMConfig {
    return { ...this.config };
  }

  public isConfigured(): boolean {
    return Boolean(this.config.baseUrl && this.config.username);
  }

  private getFullUrl(path: string): string {
    const base = this.config.baseUrl.replace(/\/+$/, '');
    const portPart = this.config.port && !base.includes(`:${this.config.port}`) ? `:${this.config.port}` : '';
    return `${base}${portPart}${path.startsWith('/') ? path : '/' + path}`;
  }

  /**
   * Authenticates with Wazuh API: POST /security/user/authenticate with Basic Auth
   */
  public async authenticate(overridePassword?: string): Promise<{ token: string; expiresAt: number }> {
    const password = overridePassword || this.config.password;
    if (!password) {
      throw new Error('Wazuh API password or token is missing.');
    }

    // Check if current cached token is still valid (give 60s buffer)
    if (this.cachedToken && Date.now() < this.tokenExpiresAt - 60000) {
      return { token: this.cachedToken, expiresAt: this.tokenExpiresAt };
    }

    const authUrl = this.getFullUrl('/security/user/authenticate');
    const basicCredentials = Buffer.from(`${this.config.username}:${password}`).toString('base64');

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(authUrl, {
        method: 'POST',
        headers: {
          Authorization: `Basic ${basicCredentials}`,
          'Content-Type': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Wazuh API authentication failed: Invalid username or password (HTTP 401)');
        }
        throw new Error(`Wazuh API authentication responded with HTTP ${response.status}: ${response.statusText}`);
      }

      const body = await response.json() as { data?: { token?: string }; token?: string };
      const token = body?.data?.token || body?.token;

      if (!token) {
        throw new Error('Wazuh API responded with success, but no JWT token was found in the response body.');
      }

      this.cachedToken = token;
      this.tokenExpiresAt = Date.now() + 900000; // 15 minutes default validity
      return { token, expiresAt: this.tokenExpiresAt };
    } catch (err: unknown) {
      clearTimeout(timeout);
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('aborted')) {
        throw new Error(`Connection timed out after ${this.config.timeoutMs}ms while contacting Wazuh at ${authUrl}`);
      }
      throw err;
    }
  }

  /**
   * Tests connection to the configured Wazuh host.
   * If live host is unreachable, cleanly returns UNVERIFIED status with honest diagnosis.
   */
  public async testConnection(overrideConfig?: Partial<SIEMConfig>): Promise<SIEMConnectionStatus> {
    const testConfig = overrideConfig ? { ...this.config, ...overrideConfig } : this.config;
    const startTime = Date.now();
    const targetUrl = this.getFullUrl('/manager/info');

    try {
      // 1. Authenticate
      const { token } = await this.authenticate(testConfig.password);

      // 2. Query Manager Info
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), testConfig.timeoutMs);

      const response = await fetch(targetUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timeout);
      const latencyMs = Date.now() - startTime;

      if (response.ok) {
        const info = await response.json() as { data?: { version?: string; name?: string } };
        const version = info?.data?.version || 'Wazuh v4.x';
        return {
          status: 'CONNECTED',
          provider: 'WAZUH',
          baseUrl: testConfig.baseUrl,
          lastTested: new Date().toISOString(),
          latencyMs,
          authenticated: true,
          version,
          details: `Connected & authenticated successfully to ${version} at ${testConfig.baseUrl}`
        };
      }

      return {
        status: 'ERROR',
        provider: 'WAZUH',
        baseUrl: testConfig.baseUrl,
        lastTested: new Date().toISOString(),
        latencyMs,
        authenticated: true,
        details: `Authenticated, but manager info endpoint returned HTTP ${response.status}`,
        error: `HTTP ${response.status}: ${response.statusText}`
      };
    } catch (err: unknown) {
      const latencyMs = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);

      // Distinguish unreachable host from invalid credentials
      const isNetworkUnreachable =
        errorMsg.includes('ECONNREFUSED') ||
        errorMsg.includes('ENOTFOUND') ||
        errorMsg.includes('timed out') ||
        errorMsg.includes('fetch failed');

      return {
        status: isNetworkUnreachable ? 'UNVERIFIED' : 'ERROR',
        provider: 'WAZUH',
        baseUrl: testConfig.baseUrl,
        lastTested: new Date().toISOString(),
        latencyMs,
        authenticated: false,
        details: isNetworkUnreachable
          ? `Host unreachable: Unable to establish TCP/TLS handshake with ${testConfig.baseUrl}:${testConfig.port}. (Diagnostic: ${errorMsg}). SIEM connector is configured and ready for live endpoint.`
          : `Wazuh API connection failed: ${errorMsg}`,
        error: errorMsg
      };
    }
  }

  /**
   * Queries Wazuh alerts endpoint: GET /alerts with filter params
   */
  public async fetchAlerts(filter?: SIEMAlertFilter): Promise<NormalizedSIEMAlert[]> {
    const minLevel = filter?.minLevel ?? this.config.minAlertLevel;
    const limit = filter?.limit ?? 25;
    const alertsUrl = this.getFullUrl(`/alerts?limit=${limit}&level>=${minLevel}&sort=-timestamp`);

    try {
      const { token } = await this.authenticate();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

      const response = await fetch(alertsUrl, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`Failed to fetch alerts from Wazuh: HTTP ${response.status} ${response.statusText}`);
      }

      const body = await response.json() as { data?: { items?: unknown[] }; items?: unknown[] };
      const rawAlerts = body?.data?.items || body?.items || [];

      return rawAlerts.map(r => this.normalizeAlert(r));
    } catch (err: unknown) {
      console.warn('[!] Wazuh fetchAlerts live query encountered:', err instanceof Error ? err.message : String(err));
      throw err;
    }
  }

  /**
   * Normalizes raw Wazuh JSON alert into standard NormalizedSIEMAlert schema
   */
  public normalizeAlert(rawAlert: unknown): NormalizedSIEMAlert {
    const raw = (rawAlert || {}) as Record<string, any>;
    const rule = raw.rule || {};
    const agent = raw.agent || {};
    const data = raw.data || {};

    const rawLevel = typeof rule.level === 'number' ? rule.level : parseInt(rule.level || '3', 10);
    const normalizedSeverity: Severity =
      rawLevel >= 12 ? 'CRITICAL' :
      rawLevel >= 8 ? 'HIGH' :
      rawLevel >= 5 ? 'MEDIUM' : 'LOW';

    // Extract MITRE ATT&CK techniques from rule.mitre
    const mitreTechniques: string[] = [];
    const mitreTactics: string[] = [];

    if (rule.mitre) {
      if (Array.isArray(rule.mitre.id)) {
        mitreTechniques.push(...rule.mitre.id);
      } else if (typeof rule.mitre.id === 'string') {
        mitreTechniques.push(rule.mitre.id);
      }

      if (Array.isArray(rule.mitre.tactic)) {
        mitreTactics.push(...rule.mitre.tactic);
      } else if (typeof rule.mitre.tactic === 'string') {
        mitreTactics.push(rule.mitre.tactic);
      }
    }

    // Fallback heuristic for common rule descriptions if mitre object was omitted in raw log
    const desc = rule.description || raw.full_log || 'Unknown Wazuh Security Event';
    if (mitreTechniques.length === 0) {
      if (/scan|nmap|nuclei|sweep|probe/i.test(desc)) mitreTechniques.push('T1595');
      if (/brute|login fail|ssh auth fail/i.test(desc)) mitreTechniques.push('T1110');
      if (/sql|injection|sqli/i.test(desc)) mitreTechniques.push('T1190');
      if (/command injection|shell execution/i.test(desc)) mitreTechniques.push('T1059');
      if (/privilege|sudo|root/i.test(desc)) mitreTechniques.push('T1078');
    }

    return {
      alertId: String(raw.id || `wazuh-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`),
      sourceSIEM: 'WAZUH',
      timestamp: raw.timestamp || new Date().toISOString(),
      agentId: String(agent.id || '000'),
      agentName: String(agent.name || 'wazuh-agent-perimeter'),
      agentIp: agent.ip || data.srcip || undefined,
      ruleId: String(rule.id || '100001'),
      ruleDescription: desc,
      rawLevel,
      normalizedSeverity,
      mitreTechniques,
      mitreTactics,
      sourceIp: data.srcip || raw.srcip,
      destinationIp: data.dstip || raw.dstip,
      rawLog: raw.full_log || JSON.stringify(raw),
      fullLogExcerpt: (raw.full_log || desc).slice(0, 300),
      epistemicStatus: 'OBSERVED',
      isSimulated: Boolean(raw._simulated)
    };
  }

  /**
   * Converts a NormalizedSIEMAlert into AWM Nexus DefensiveTelemetryEvent
   */
  public toDefensiveTelemetryEvent(alert: NormalizedSIEMAlert): DefensiveTelemetryEvent {
    return {
      eventId: `DEF-WAZUH-${alert.alertId.replace(/[^a-zA-Z0-9-]/g, '')}`,
      timestamp: alert.timestamp,
      sourceControl: `Wazuh SIEM [Agent ${alert.agentId}: ${alert.agentName}]`,
      eventName: alert.ruleDescription,
      matchedTechnique: alert.mitreTactics[0] || 'Reconnaissance / Discovery',
      mitreId: alert.mitreTechniques[0] || 'T1595',
      target: alert.destinationIp || '127.0.0.1',
      severity: alert.normalizedSeverity,
      detected: true,
      detectionStatus: alert.isSimulated ? 'SIMULATED' : 'LIVE',
      controlEffectiveness: Math.min(100, Math.max(50, alert.rawLevel * 7))
    };
  }
}
