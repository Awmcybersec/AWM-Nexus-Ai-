/**
 * AWM Nexus — SIEM Integration Architecture
 * Types and interfaces for modular SIEM connectivity (Wazuh, Splunk, Elastic, Webhooks).
 */

import { Severity, DetectionStatus, EpistemicStatus, DefensiveTelemetryEvent } from '../../types';

export type SIEMProviderType = 'WAZUH' | 'SPLUNK' | 'ELASTIC' | 'DEMO_SIMULATOR';

export interface SIEMConfig {
  provider: SIEMProviderType;
  baseUrl: string;
  port: number;
  username: string;
  password?: string;
  apiToken?: string;
  verifySsl: boolean;
  minAlertLevel: number; // e.g. Wazuh rule level (3-15)
  timeoutMs: number;
  syncIntervalSeconds: number;
  enabled: boolean;
  agentFilter?: string; // Optional agent ID filter
}

export interface SIEMConnectionStatus {
  status: 'CONNECTED' | 'UNVERIFIED' | 'DISCONNECTED' | 'ERROR';
  provider: SIEMProviderType;
  baseUrl: string;
  lastTested: string;
  latencyMs?: number;
  details: string;
  version?: string;
  authenticated: boolean;
  error?: string;
}

export interface SIEMAlertFilter {
  minLevel?: number;
  agentId?: string;
  ruleId?: string;
  search?: string;
  limit?: number;
  timeWindowMinutes?: number;
}

export interface NormalizedSIEMAlert {
  alertId: string;
  sourceSIEM: SIEMProviderType;
  timestamp: string;
  agentId: string;
  agentName: string;
  agentIp?: string;
  ruleId: string;
  ruleDescription: string;
  rawLevel: number;
  normalizedSeverity: Severity;
  mitreTechniques: string[];
  mitreTactics: string[];
  sourceIp?: string;
  destinationIp?: string;
  rawLog?: string;
  fullLogExcerpt: string;
  epistemicStatus: EpistemicStatus;
  isSimulated: boolean;
}

export interface SIEMConnector {
  readonly id: string;
  readonly name: string;
  readonly providerType: SIEMProviderType;
  isConfigured(): boolean;
  testConnection(overrideConfig?: Partial<SIEMConfig>): Promise<SIEMConnectionStatus>;
  fetchAlerts(filter?: SIEMAlertFilter): Promise<NormalizedSIEMAlert[]>;
  normalizeAlert(rawAlert: unknown): NormalizedSIEMAlert;
  toDefensiveTelemetryEvent(alert: NormalizedSIEMAlert): DefensiveTelemetryEvent;
}
