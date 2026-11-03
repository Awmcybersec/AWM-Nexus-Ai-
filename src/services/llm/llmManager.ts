/**
 * AWM Nexus — LLM Integration Manager
 * Manages the active provider (Google Gemini vs Deterministic Fallback),
 * coordinates API key storage (server-side, never exposed to client),
 * dispatches analysis requests, and logs all events to the cryptographic audit ledger.
 */

import {
  LLMProvider,
  LLMProviderType,
  LLMConfig,
  LLMAnalysisResult,
  LLMConnectionTestResult,
  LLMIncidentAnalysisParams,
  LLMAlertSummarizationParams,
  LLMReportParams
} from './types';
import { GeminiProvider } from './geminiProvider';
import { DeterministicFallbackProvider } from './deterministicFallbackProvider';
import { auditLedger } from '../../engine/auditLedger';

export class LLMManager {
  private static instance: LLMManager;
  private providers: Map<string, LLMProvider> = new Map();
  private activeProviderId: string = 'gemini';
  private sessionApiKey: string | null = null;
  private lastTestResult: LLMConnectionTestResult | null = null;

  private constructor() {
    this.registerProvider(new GeminiProvider());
    this.registerProvider(new DeterministicFallbackProvider());

    // If Gemini key is missing, default to deterministic fallback
    const gemini = this.providers.get('gemini');
    if (gemini && !gemini.isConfigured()) {
      this.activeProviderId = 'deterministic-fallback';
    }
  }

  public static getInstance(): LLMManager {
    if (!LLMManager.instance) {
      LLMManager.instance = new LLMManager();
    }
    return LLMManager.instance;
  }

  public registerProvider(provider: LLMProvider) {
    this.providers.set(provider.id, provider);
  }

  public setActiveProvider(providerId: string): boolean {
    if (this.providers.has(providerId)) {
      this.activeProviderId = providerId;
      return true;
    }
    return false;
  }

  public getActiveProvider(): LLMProvider {
    return this.providers.get(this.activeProviderId) || this.providers.get('deterministic-fallback')!;
  }

  /**
   * Sets the API key in server memory for the current session.
   * Strips whitespace and never stores in client bundle.
   */
  public setSessionApiKey(key: string | null) {
    this.sessionApiKey = key && key.trim().length > 0 ? key.trim() : null;
    if (this.sessionApiKey) {
      this.activeProviderId = 'gemini';
    }
  }

  public getConfig(): LLMConfig {
    const active = this.getActiveProvider();
    const hasKey = Boolean(
      (this.sessionApiKey && this.sessionApiKey.length > 0) ||
      (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.length > 0) ||
      (process.env.VITE_GEMINI_API_KEY && process.env.VITE_GEMINI_API_KEY.length > 0)
    );

    return {
      provider: active.id as LLMProviderType,
      model: active.defaultModel,
      apiKeyConfigured: hasKey,
      temperature: 0.2,
      maxOutputTokens: 2048,
      timeoutMs: 15000,
      enableSafetyFilters: true
    };
  }

  public getLastTestResult(): LLMConnectionTestResult | null {
    return this.lastTestResult;
  }

  /**
   * Tests connection with active provider or specific ephemeral key.
   */
  public async testConnection(ephemeralKey?: string): Promise<LLMConnectionTestResult> {
    const provider = this.getActiveProvider();
    const keyToUse = ephemeralKey || this.sessionApiKey || undefined;

    const result = await provider.testConnection(keyToUse);
    this.lastTestResult = result;

    // Log connection test to immutable audit ledger
    auditLedger.appendBlock(
      'system-llm-manager',
      `LLM Connection Test [${provider.name}] — ${result.success ? 'SUCCESS' : 'FAILED'}`,
      'TENANT-AWM-01',
      'eng-2026-001',
      undefined,
      {
        provider: provider.name,
        model: result.model,
        latencyMs: result.latencyMs,
        success: result.success,
        error: result.error
      }
    );

    return result;
  }

  public async analyzeIncident(params: LLMIncidentAnalysisParams): Promise<LLMAnalysisResult> {
    const provider = this.getActiveProvider();
    const keyToUse = this.sessionApiKey || undefined;

    try {
      const result = await provider.analyzeIncident(params, keyToUse);
      this.recordAudit('INCIDENT_ANALYSIS', result);
      return result;
    } catch (err: unknown) {
      // Automatic graceful fallback to deterministic engine
      if (provider.id !== 'deterministic-fallback') {
        console.warn(`[!] Primary LLM provider '${provider.id}' failed, falling back to deterministic:`, err);
        const fallback = this.providers.get('deterministic-fallback')!;
        const fallbackResult = await fallback.analyzeIncident(params);
        fallbackResult.errorNotice = `Primary LLM unavailable (${err instanceof Error ? err.message : String(err)}). Serving deterministic rules.`;
        this.recordAudit('INCIDENT_ANALYSIS_FALLBACK', fallbackResult);
        return fallbackResult;
      }
      throw err;
    }
  }

  public async summarizeAlerts(params: LLMAlertSummarizationParams): Promise<LLMAnalysisResult> {
    const provider = this.getActiveProvider();
    const keyToUse = this.sessionApiKey || undefined;

    try {
      const result = await provider.summarizeAlerts(params, keyToUse);
      this.recordAudit('ALERT_SUMMARIZATION', result);
      return result;
    } catch (err: unknown) {
      if (provider.id !== 'deterministic-fallback') {
        const fallback = this.providers.get('deterministic-fallback')!;
        const fallbackResult = await fallback.summarizeAlerts(params);
        fallbackResult.errorNotice = `Primary LLM unavailable (${err instanceof Error ? err.message : String(err)}). Serving deterministic rules.`;
        this.recordAudit('ALERT_SUMMARIZATION_FALLBACK', fallbackResult);
        return fallbackResult;
      }
      throw err;
    }
  }

  public async explainMitreTechnique(techniqueId: string, context?: string): Promise<LLMAnalysisResult> {
    const provider = this.getActiveProvider();
    const keyToUse = this.sessionApiKey || undefined;

    try {
      const result = await provider.explainMitreTechnique(techniqueId, context, keyToUse);
      this.recordAudit('MITRE_EXPLANATION', result);
      return result;
    } catch (err: unknown) {
      if (provider.id !== 'deterministic-fallback') {
        const fallback = this.providers.get('deterministic-fallback')!;
        const fallbackResult = await fallback.explainMitreTechnique(techniqueId, context);
        fallbackResult.errorNotice = `Primary LLM unavailable (${err instanceof Error ? err.message : String(err)}). Serving deterministic rules.`;
        this.recordAudit('MITRE_EXPLANATION_FALLBACK', fallbackResult);
        return fallbackResult;
      }
      throw err;
    }
  }

  public async generateExecutiveNarrative(params: LLMReportParams): Promise<LLMAnalysisResult> {
    const provider = this.getActiveProvider();
    const keyToUse = this.sessionApiKey || undefined;

    try {
      const result = await provider.generateExecutiveNarrative(params, keyToUse);
      this.recordAudit('EXECUTIVE_NARRATIVE', result);
      return result;
    } catch (err: unknown) {
      if (provider.id !== 'deterministic-fallback') {
        const fallback = this.providers.get('deterministic-fallback')!;
        const fallbackResult = await fallback.generateExecutiveNarrative(params);
        fallbackResult.errorNotice = `Primary LLM unavailable (${err instanceof Error ? err.message : String(err)}). Serving deterministic rules.`;
        this.recordAudit('EXECUTIVE_NARRATIVE_FALLBACK', fallbackResult);
        return fallbackResult;
      }
      throw err;
    }
  }

  private recordAudit(category: string, result: LLMAnalysisResult) {
    auditLedger.appendBlock(
      'system-llm-orchestrator',
      `AI Reasoning [${category}] via ${result.provider} (${result.model})`,
      'TENANT-AWM-01',
      'eng-2026-001',
      undefined,
      {
        title: result.title,
        epistemicStatus: result.epistemicStatus,
        confidence: result.confidence,
        isLLMGenerated: result.isLLMGenerated,
        latencyMs: result.latencyMs,
        findingsCount: result.keyFindings.length,
        actionsCount: result.recommendedActions.length
      }
    );
  }
}

export const llmManager = LLMManager.getInstance();
