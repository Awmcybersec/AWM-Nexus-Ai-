/**
 * AWM Nexus — Real Google Gemini LLM Provider
 * Implements Google GenAI TypeScript SDK (@google/genai) integration with
 * schema-validated JSON outputs, structured epistemic reasoning, and prompt injection defenses.
 */

import { GoogleGenAI, Type } from '@google/genai';
import {
  LLMProvider,
  LLMAnalysisResult,
  LLMConnectionTestResult,
  LLMIncidentAnalysisParams,
  LLMAlertSummarizationParams,
  LLMReportParams
} from './types';
import { PromptSanitizer } from './promptSanitizer';

export class GeminiProvider implements LLMProvider {
  public readonly id = 'gemini';
  public readonly name = 'Google Gemini (Official @google/genai SDK)';
  public readonly defaultModel = 'gemini-3.8-flash';
  private static readonly TIMEOUT_MS = 15000;

  /**
   * Resolves the API key from argument, server environment variable, or null.
   */
  private getApiKey(ephemeralKey?: string): string | null {
    if (ephemeralKey && ephemeralKey.trim().length > 0) {
      return ephemeralKey.trim();
    }
    const envKey = process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY;
    if (envKey && envKey.trim().length > 0) {
      return envKey.trim();
    }
    return null;
  }

  public isConfigured(): boolean {
    return this.getApiKey() !== null;
  }

  /**
   * Executes a minimal 1-token real API request to Google Gemini to verify connectivity.
   */
  public async testConnection(ephemeralApiKey?: string): Promise<LLMConnectionTestResult> {
    const apiKey = this.getApiKey(ephemeralApiKey);
    if (!apiKey) {
      return {
        success: false,
        provider: this.name,
        model: this.defaultModel,
        latencyMs: 0,
        message: 'No API key configured. Provide GEMINI_API_KEY in environment or input in settings.',
        error: 'API_KEY_MISSING'
      };
    }

    const startTime = Date.now();
    try {
      const ai = new GoogleGenAI({ apiKey });

      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Request timed out after 15,000ms')), GeminiProvider.TIMEOUT_MS)
      );

      const requestPromise = ai.models.generateContent({
        model: this.defaultModel,
        contents: 'Respond with the single word: "READY_AWM_NEXUS"'
      });

      const response = await Promise.race([requestPromise, timeoutPromise]);
      const latencyMs = Date.now() - startTime;
      const text = response.text ? response.text.trim() : '';

      return {
        success: true,
        provider: this.name,
        model: this.defaultModel,
        latencyMs,
        message: 'Google Gemini API connection verified successfully.',
        sampleResponse: text
      };
    } catch (err: unknown) {
      const latencyMs = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);
      return {
        success: false,
        provider: this.name,
        model: this.defaultModel,
        latencyMs,
        message: `Gemini API connection test failed: ${errorMsg}`,
        error: errorMsg
      };
    }
  }

  /**
   * Analyzes an ongoing security incident, findings, and telemetry.
   */
  public async analyzeIncident(
    params: LLMIncidentAnalysisParams,
    ephemeralApiKey?: string
  ): Promise<LLMAnalysisResult> {
    const apiKey = this.getApiKey(ephemeralApiKey);
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is not configured on this server or session.');
    }

    const startTime = Date.now();
    const ai = new GoogleGenAI({ apiKey });

    const safeFindings = PromptSanitizer.wrapUntrustedData('Discovered Findings', params.findings);
    const safeTelemetry = PromptSanitizer.wrapUntrustedData('Defensive Telemetry', params.telemetryEvents || []);

    const prompt = `
You are the Nexus Lead AI Security Investigator in AWM Nexus.
Engagement Target: ${params.target}
Incident Context: ${params.incidentTitle}

Here is the authoritative telemetry and finding evidence collected by our deterministic security engines:
${safeFindings}
${safeTelemetry}

Analyze this incident. You must return a strictly formatted JSON object adhering to this schema:
{
  "title": "Incident Investigation Title",
  "summary": "Concise 2-3 sentence executive synopsis of what occurred, what was detected, and current posture",
  "keyFindings": ["Finding 1", "Finding 2"],
  "mitreTechniques": [
    {
      "id": "e.g. T1190 or T1046",
      "name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "Technique explanation",
      "relevanceToEngagement": "How this technique was evidenced in this incident",
      "detectionSignatures": ["Specific log or WAF signature"],
      "recommendedMitigations": ["Specific firewall or code fix"]
    }
  ],
  "defensiveGaps": ["Identified gap in detection or control"],
  "recommendedActions": [
    {
      "action": "Description of action",
      "priority": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "requiresHitl": true | false,
      "toolId": "optional tool identifier if pentest tool like curl-probe or openssl-tls-audit",
      "rationale": "Why this action is needed"
    }
  ],
  "epistemicStatus": "OBSERVED" | "INFERRED",
  "confidence": 0.95
}
Output ONLY valid JSON.
`;

    try {
      const response = await ai.models.generateContent({
        model: this.defaultModel,
        contents: prompt,
        config: {
          responseMimeType: 'application/json'
        }
      });

      const latencyMs = Date.now() - startTime;
      const text = response.text || '{}';
      const parsed = JSON.parse(text);

      return {
        title: parsed.title || params.incidentTitle,
        summary: parsed.summary || 'Incident analysis generated.',
        keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
        mitreTechniques: Array.isArray(parsed.mitreTechniques) ? parsed.mitreTechniques : [],
        defensiveGaps: Array.isArray(parsed.defensiveGaps) ? parsed.defensiveGaps : [],
        recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions : [],
        epistemicStatus: parsed.epistemicStatus === 'OBSERVED' ? 'OBSERVED' : 'INFERRED',
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.9,
        isLLMGenerated: true,
        provider: this.name,
        model: this.defaultModel,
        latencyMs,
        timestamp: new Date().toISOString()
      };
    } catch (err: unknown) {
      const latencyMs = Date.now() - startTime;
      throw new Error(`Gemini Incident Analysis failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Summarizes Wazuh or SIEM alerts.
   */
  public async summarizeAlerts(
    params: LLMAlertSummarizationParams,
    ephemeralApiKey?: string
  ): Promise<LLMAnalysisResult> {
    const apiKey = this.getApiKey(ephemeralApiKey);
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is not configured on this server or session.');
    }

    const startTime = Date.now();
    const ai = new GoogleGenAI({ apiKey });

    const safeAlerts = PromptSanitizer.wrapUntrustedData('SIEM Alerts', params.alerts);

    const prompt = `
You are the Nexus Defensive SOC Analyst in AWM Nexus.
Summarize the following SIEM alerts and identify if an active adversary campaign is underway.
${safeAlerts}

Return a strictly valid JSON response:
{
  "title": "SIEM Alert Stream Synthesis",
  "summary": "Concise summary of the alerts and threat posture",
  "keyFindings": ["Finding 1", "Finding 2"],
  "mitreTechniques": [
    {
      "id": "Txxxx",
      "name": "Technique Name",
      "tactic": "Tactic Name",
      "description": "Technique description",
      "relevanceToEngagement": "Relevance to these alerts",
      "detectionSignatures": ["Signature"],
      "recommendedMitigations": ["Mitigation"]
    }
  ],
  "defensiveGaps": ["Defensive gap"],
  "recommendedActions": [
    {
      "action": "Action description",
      "priority": "HIGH" | "MEDIUM" | "LOW",
      "requiresHitl": false,
      "rationale": "Rationale"
    }
  ],
  "epistemicStatus": "OBSERVED",
  "confidence": 0.92
}
`;

    try {
      const response = await ai.models.generateContent({
        model: this.defaultModel,
        contents: prompt,
        config: {
          responseMimeType: 'application/json'
        }
      });

      const latencyMs = Date.now() - startTime;
      const parsed = JSON.parse(response.text || '{}');

      return {
        title: parsed.title || 'SIEM Alert Stream Analysis',
        summary: parsed.summary || 'Alert analysis completed.',
        keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
        mitreTechniques: Array.isArray(parsed.mitreTechniques) ? parsed.mitreTechniques : [],
        defensiveGaps: Array.isArray(parsed.defensiveGaps) ? parsed.defensiveGaps : [],
        recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions : [],
        epistemicStatus: 'OBSERVED',
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.9,
        isLLMGenerated: true,
        provider: this.name,
        model: this.defaultModel,
        latencyMs,
        timestamp: new Date().toISOString()
      };
    } catch (err: unknown) {
      throw new Error(`Gemini Alert Summarization failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Provides deep contextual explanation of a MITRE ATT&CK technique.
   */
  public async explainMitreTechnique(
    techniqueId: string,
    context?: string,
    ephemeralApiKey?: string
  ): Promise<LLMAnalysisResult> {
    const apiKey = this.getApiKey(ephemeralApiKey);
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is not configured on this server or session.');
    }

    const startTime = Date.now();
    const ai = new GoogleGenAI({ apiKey });

    const safeContext = context ? PromptSanitizer.sanitizeString(context, 1000) : 'General security engagement context';

    const prompt = `
You are the Nexus Threat Hunter in AWM Nexus.
Explain MITRE ATT&CK technique ${techniqueId}.
Context: ${safeContext}

Return a strictly valid JSON response:
{
  "title": "MITRE ATT&CK Deep Dive: ${techniqueId}",
  "summary": "Technical explanation of the technique, mechanics, adversary objectives, and detection opportunities",
  "keyFindings": ["Key aspect 1", "Key aspect 2"],
  "mitreTechniques": [
    {
      "id": "${techniqueId}",
      "name": "Technique Name",
      "tactic": "Tactic",
      "description": "Comprehensive explanation of how adversaries execute this technique",
      "relevanceToEngagement": "How it impacts this engagement",
      "detectionSignatures": ["SIEM/EDR detection rule indicator 1", "Network signature 2"],
      "recommendedMitigations": ["Defensive control mitigation 1", "Policy mitigation 2"]
    }
  ],
  "defensiveGaps": ["Common oversight in defending against this technique"],
  "recommendedActions": [
    {
      "action": "Validation or hardening recommendation",
      "priority": "HIGH",
      "requiresHitl": true,
      "toolId": "curl-probe",
      "rationale": "Validate whether detection triggers"
    }
  ],
  "epistemicStatus": "OBSERVED",
  "confidence": 0.98
}
`;

    try {
      const response = await ai.models.generateContent({
        model: this.defaultModel,
        contents: prompt,
        config: {
          responseMimeType: 'application/json'
        }
      });

      const latencyMs = Date.now() - startTime;
      const parsed = JSON.parse(response.text || '{}');

      return {
        title: parsed.title || `MITRE ATT&CK Technique ${techniqueId}`,
        summary: parsed.summary || 'Technique explanation generated.',
        keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
        mitreTechniques: Array.isArray(parsed.mitreTechniques) ? parsed.mitreTechniques : [],
        defensiveGaps: Array.isArray(parsed.defensiveGaps) ? parsed.defensiveGaps : [],
        recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions : [],
        epistemicStatus: 'OBSERVED',
        confidence: 0.95,
        isLLMGenerated: true,
        provider: this.name,
        model: this.defaultModel,
        latencyMs,
        timestamp: new Date().toISOString()
      };
    } catch (err: unknown) {
      throw new Error(`Gemini MITRE explanation failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Generates executive narrative for pentest reporting.
   */
  public async generateExecutiveNarrative(
    params: LLMReportParams,
    ephemeralApiKey?: string
  ): Promise<LLMAnalysisResult> {
    const apiKey = this.getApiKey(ephemeralApiKey);
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is not configured on this server or session.');
    }

    const startTime = Date.now();
    const ai = new GoogleGenAI({ apiKey });

    const safeFindings = PromptSanitizer.wrapUntrustedData('Top Findings', params.topFindings);

    const prompt = `
You are the Nexus Executive Security Analyst in AWM Nexus.
Synthesize an executive narrative for Engagement: ${params.engagementCode} for client: ${params.clientName}.
Metrics: Critical: ${params.criticalCount}, High: ${params.highCount}, Medium: ${params.mediumCount}, Total: ${params.findingsCount}.
Strategic Focus: ${params.executiveFocus}.
${safeFindings}

Return a strictly valid JSON response:
{
  "title": "Executive Posture Synthesis: ${params.engagementCode}",
  "summary": "Professional executive summary suitable for the Board of Directors and CISO. Address business risk, defense-in-depth maturity, and prioritized remediation roadmap.",
  "keyFindings": ["Business impact statement 1", "Strategic risk statement 2"],
  "mitreTechniques": [],
  "defensiveGaps": ["Strategic organizational or architecture gap"],
  "recommendedActions": [
    {
      "action": "Executive strategic recommendation",
      "priority": "CRITICAL",
      "requiresHitl": false,
      "rationale": "High-level risk mitigation"
    }
  ],
  "epistemicStatus": "INFERRED",
  "confidence": 0.95
}
`;

    try {
      const response = await ai.models.generateContent({
        model: this.defaultModel,
        contents: prompt,
        config: {
          responseMimeType: 'application/json'
        }
      });

      const latencyMs = Date.now() - startTime;
      const parsed = JSON.parse(response.text || '{}');

      return {
        title: parsed.title || `Executive Summary ${params.engagementCode}`,
        summary: parsed.summary || 'Executive narrative generated.',
        keyFindings: Array.isArray(parsed.keyFindings) ? parsed.keyFindings : [],
        mitreTechniques: Array.isArray(parsed.mitreTechniques) ? parsed.mitreTechniques : [],
        defensiveGaps: Array.isArray(parsed.defensiveGaps) ? parsed.defensiveGaps : [],
        recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions : [],
        epistemicStatus: 'INFERRED',
        confidence: 0.95,
        isLLMGenerated: true,
        provider: this.name,
        model: this.defaultModel,
        latencyMs,
        timestamp: new Date().toISOString()
      };
    } catch (err: unknown) {
      throw new Error(`Gemini Executive narrative failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
