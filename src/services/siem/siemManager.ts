/**
 * AWM Nexus — SIEM Integration Manager
 * Coordinates SIEM connectors, manages sync triggers, and streams
 * normalized telemetry into the authoritative DefensiveTelemetryEngine.
 */

import {
  SIEMConnector,
  SIEMConfig,
  SIEMConnectionStatus,
  NormalizedSIEMAlert,
  SIEMAlertFilter
} from './types';
import { WazuhConnector } from './wazuhConnector';
import { defensiveTelemetryEngine } from '../../engine/offensiveDefensiveEngines';
import { auditLedger } from '../../engine/auditLedger';

export class SIEMManager {
  private static instance: SIEMManager;
  private wazuhConnector: WazuhConnector;
  private lastSyncTime: string | null = null;
  private lastConnectionStatus: SIEMConnectionStatus | null = null;
  private syncedAlertsCount: number = 0;

  private constructor() {
    this.wazuhConnector = new WazuhConnector({
      baseUrl: 'https://wazuh-manager.corp.internal',
      port: 55000,
      username: 'wazuh-api-admin',
      minAlertLevel: 3,
      enabled: true
    });
  }

  public static getInstance(): SIEMManager {
    if (!SIEMManager.instance) {
      SIEMManager.instance = new SIEMManager();
    }
    return SIEMManager.instance;
  }

  public getWazuhConnector(): WazuhConnector {
    return this.wazuhConnector;
  }

  public getConfig(): SIEMConfig {
    const raw = this.wazuhConnector.getConfig();
    // Return sanitized config (never expose cleartext password in responses)
    return {
      ...raw,
      password: raw.password ? '********' : undefined,
      apiToken: raw.apiToken ? '********' : undefined
    };
  }

  public updateConfig(newConfig: Partial<SIEMConfig>) {
    this.wazuhConnector.updateConfig(newConfig);
  }

  public getLastStatus(): SIEMConnectionStatus {
    if (!this.lastConnectionStatus) {
      return {
        status: 'DISCONNECTED',
        provider: 'WAZUH',
        baseUrl: this.wazuhConnector.getConfig().baseUrl,
        lastTested: 'Never',
        authenticated: false,
        details: 'SIEM connector initialized; pending initial connection test.'
      };
    }
    return this.lastConnectionStatus;
  }

  public getStats() {
    return {
      lastSyncTime: this.lastSyncTime,
      syncedAlertsCount: this.syncedAlertsCount,
      activeProvider: 'WAZUH',
      status: this.lastConnectionStatus?.status || 'DISCONNECTED'
    };
  }

  /**
   * Tests connection to Wazuh endpoint and logs result to cryptographic audit ledger.
   */
  public async testConnection(overrideConfig?: Partial<SIEMConfig>): Promise<SIEMConnectionStatus> {
    const status = await this.wazuhConnector.testConnection(overrideConfig);
    this.lastConnectionStatus = status;

    auditLedger.appendBlock(
      'system-siem-manager',
      `SIEM Connection Test [${status.provider}] — ${status.status}`,
      'TENANT-AWM-01',
      'eng-2026-001',
      undefined,
      {
        baseUrl: status.baseUrl,
        status: status.status,
        authenticated: status.authenticated,
        details: status.details,
        error: status.error
      }
    );

    return status;
  }

  /**
   * Syncs alerts from Wazuh into AWM Nexus Defensive Telemetry Engine.
   */
  public async syncAlerts(filter?: SIEMAlertFilter): Promise<{
    success: boolean;
    syncedCount: number;
    error?: string;
  }> {
    try {
      const alerts = await this.wazuhConnector.fetchAlerts(filter);
      let newCount = 0;

      for (const alert of alerts) {
        const telemetryEvent = this.wazuhConnector.toDefensiveTelemetryEvent(alert);
        defensiveTelemetryEngine.recordEvent(telemetryEvent);
        newCount++;
      }

      this.syncedAlertsCount += newCount;
      this.lastSyncTime = new Date().toISOString();

      auditLedger.appendBlock(
        'system-siem-manager',
        `SIEM Telemetry Ingestion [Wazuh] — Synced ${newCount} events`,
        'TENANT-AWM-01',
        'eng-2026-001',
        undefined,
        {
          syncedCount: newCount,
          minLevel: filter?.minLevel ?? this.wazuhConnector.getConfig().minAlertLevel
        }
      );

      return { success: true, syncedCount: newCount };
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      return { success: false, syncedCount: 0, error: errorMsg };
    }
  }

  /**
   * Ingests verified sample Wazuh payloads for sandbox verification or demonstration
   * when no live remote Wazuh host is configured.
   * Every injected event is honestly tagged with isSimulated: true.
   */
  public ingestVerifiedSampleAlerts(): { count: number; alerts: NormalizedSIEMAlert[] } {
    const samples: unknown[] = [
      {
        id: `wazuh-${Date.now()}-01`,
        timestamp: new Date().toISOString(),
        rule: {
          id: '5710',
          level: 10,
          description: 'sshd: Multiple failed login attempts (Brute force attempt detected)',
          groups: ['syslog', 'sshd', 'authentication_failures'],
          mitre: {
            id: ['T1110.001'],
            tactic: ['Credential Access'],
            technique: ['Password Guessing']
          }
        },
        agent: {
          id: '002',
          name: 'wazuh-agent-bastion',
          ip: '10.0.0.15'
        },
        data: {
          srcip: '198.51.100.42',
          dstuser: 'root'
        },
        full_log: 'May 14 03:12:01 bastion sshd[18492]: Failed password for root from 198.51.100.42 port 49202 ssh2',
        _simulated: true
      },
      {
        id: `wazuh-${Date.now()}-02`,
        timestamp: new Date().toISOString(),
        rule: {
          id: '31101',
          level: 8,
          description: 'Web server 400 error code: Web directory and file scan detected (ffuf/gobuster probe)',
          groups: ['web', 'accesslog'],
          mitre: {
            id: ['T1083', 'T1595.002'],
            tactic: ['Discovery', 'Reconnaissance'],
            technique: ['File and Directory Discovery', 'Vulnerability Scanning']
          }
        },
        agent: {
          id: '001',
          name: 'wazuh-agent-web-dmz',
          ip: '127.0.0.1'
        },
        data: {
          srcip: '127.0.0.1',
          url: '/api/v1/.env'
        },
        full_log: '127.0.0.1 - - [14/May/2026:03:12:15 +0000] "GET /api/v1/.env HTTP/1.1" 404 153 "-" "ffuf/2.1.0"',
        _simulated: true
      },
      {
        id: `wazuh-${Date.now()}-03`,
        timestamp: new Date().toISOString(),
        rule: {
          id: '31106',
          level: 13,
          description: 'SQL Injection attempt detected in HTTP parameter id',
          groups: ['web', 'appsec', 'attack'],
          mitre: {
            id: ['T1190'],
            tactic: ['Initial Access'],
            technique: ['Exploit Public-Facing Application']
          }
        },
        agent: {
          id: '001',
          name: 'wazuh-agent-web-dmz',
          ip: '127.0.0.1'
        },
        data: {
          srcip: '127.0.0.1',
          url: '/api/users?id=1%27%20OR%201=1--'
        },
        full_log: '127.0.0.1 - - [14/May/2026:03:12:30 +0000] "GET /api/users?id=1\' OR 1=1-- HTTP/1.1" 403 219',
        _simulated: true
      }
    ];

    const normalized = samples.map(s => this.wazuhConnector.normalizeAlert(s));
    for (const alert of normalized) {
      defensiveTelemetryEngine.recordEvent(this.wazuhConnector.toDefensiveTelemetryEvent(alert));
    }

    this.syncedAlertsCount += normalized.length;
    this.lastSyncTime = new Date().toISOString();

    auditLedger.appendBlock(
      'system-siem-manager',
      `SIEM Demo Ingestion [Wazuh Schema] — Ingested ${normalized.length} sample events`,
      'TENANT-AWM-01',
      'eng-2026-001',
      undefined,
      {
        count: normalized.length,
        isSimulated: true
      }
    );

    return { count: normalized.length, alerts: normalized };
  }
}

export const siemManager = SIEMManager.getInstance();
