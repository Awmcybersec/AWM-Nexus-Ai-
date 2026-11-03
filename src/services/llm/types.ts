/**
 * AWM Nexus — Real LLM Provider Architecture
 * Types and interfaces for modular Large Language Model integration.
 * Supports Google Gemini, future providers (OpenAI, Anthropic), and deterministic rule fallbacks.
 */

import { EpistemicStatus, Severity } from '../../types';

export type LLMProviderType = 'gemini' | 'openai' | 'anthropic' | 'deterministic-fallback';

export interface LLMConfig {
  provider: LLMProviderType;
  model: string;
  apiKeyConfigured: boolean;
  temperature: number;
  maxOutputTokens: number;
  timeoutMs: number;
  enableSafetyFilters: boolean;
}

export interface MitreTechniqueExplanation {
  id: string;
  name: string;
  tactic: string;
  description: string;
  relevanceToEngagement: string;
  detectionSignatures: string[];
  recommendedMitigations: string[];
}

export interface RecommendedAction {
  action: string;
  priority: Severity;
  target?: string;
  toolId?: string;
  requiresHitl: boolean;
  rationale: string;
}

export interface LLMAnalysisResult {
  title: string;
  summary: string;
  keyFindings: string[];
  mitreTechniques: MitreTechniqueExplanation[];
  defensiveGaps: string[];
  recommendedActions: RecommendedAction[];
  epistemicStatus: EpistemicStatus;
  confidence: number; // 0.0 - 1.0
  isLLMGenerated: boolean;
  provider: string;
  model: string;
  latencyMs: number;
  timestamp: string;
  rawTokens?: {
    promptTokens: number;
    completionTokens: number;
  };
  errorNotice?: string;
}

export interface LLMIncidentAnalysisParams {
  incidentTitle: string;
  target: string;
  findings: Array<{
    title: string;
    severity: string;
    description: string;
    cve?: string;
    cwe?: string;
    evidenceData?: string;
  }>;
  telemetryEvents?: Array<{
    eventId: string;
    controlSource: string;
    detectedEvent: string;
    mitreTechnique?: string;
    detectionStatus: string;
  }>;
  engagementContext?: {
    code: string;
    tenantId: string;
    scopeTargets: string[];
  };
}

export interface LLMAlertSummarizationParams {
  alerts: Array<{
    id: string;
    source: string;
    ruleTitle: string;
    level: number | string;
    timestamp: string;
    rawLog?: string;
    mitreId?: string;
  }>;
  timeWindow?: string;
}

export interface LLMReportParams {
  engagementCode: string;
  clientName: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  executiveFocus: 'RISK_REDUCTION' | 'COMPLIANCE' | 'DEFENSIVE_RESILIENCE';
  topFindings: Array<{
    title: string;
    severity: string;
    affectedAsset: string;
    summary: string;
  }>;
}

export interface LLMConnectionTestResult {
  success: boolean;
  provider: string;
  model: string;
  latencyMs: number;
  message: string;
  sampleResponse?: string;
  error?: string;
}

export interface LLMProvider {
  readonly id: string;
  readonly name: string;
  readonly defaultModel: string;
  isConfigured(): boolean;
  testConnection(ephemeralApiKey?: string): Promise<LLMConnectionTestResult>;
  analyzeIncident(params: LLMIncidentAnalysisParams, ephemeralApiKey?: string): Promise<LLMAnalysisResult>;
  summarizeAlerts(params: LLMAlertSummarizationParams, ephemeralApiKey?: string): Promise<LLMAnalysisResult>;
  explainMitreTechnique(techniqueId: string, context?: string, ephemeralApiKey?: string): Promise<LLMAnalysisResult>;
  generateExecutiveNarrative(params: LLMReportParams, ephemeralApiKey?: string): Promise<LLMAnalysisResult>;
}
