/**
 * AWM Nexus — AI Agent Fleet Governance & Live Reasoning Workspace
 * Coordinates all 12 specialized autonomous and semi-autonomous security agents.
 * Supports dual reasoning paths: Google Gemini (@google/genai) and Deterministic Authoritative Rules.
 */

import React, { useState } from 'react';
import {
  Bot,
  Shield,
  Zap,
  Lock,
  CheckCircle2,
  AlertCircle,
  Radio,
  Cpu,
  Layers,
  Sparkles,
  Send,
  Activity,
  FileCheck2,
  ChevronRight
} from 'lucide-react';
import { aiOrchestrator } from '../engine/aiOrchestrator';
import { llmManager } from '../services/llm/llmManager';
import { AIAgentProfile, EpistemicStatus } from '../types';

export const AgentFleetView: React.FC = () => {
  const agents = aiOrchestrator.getAllAgents();
  const [selectedAgentId, setSelectedAgentId] = useState<string>(agents[0]?.id || 'agent-attack-surface');
  const [useLLM, setUseLLM] = useState<boolean>(true);
  const [queryInput, setQueryInput] = useState<string>('Assess in-scope perimeter assets and formulate non-destructive validation plan.');
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [consultationResult, setConsultationResult] = useState<{
    agentName: string;
    role: string;
    summary: string;
    epistemicStatus: EpistemicStatus;
    confidence: number;
    evidenceReferences: string[];
    recommendations: string[];
    isLLMGenerated: boolean;
    provider: string;
    model: string;
    latencyMs: number;
  } | null>(null);

  const selectedAgent = agents.find(a => a.id === selectedAgentId) || agents[0];

  const handleConsult = async () => {
    if (!selectedAgent) return;
    setAnalyzing(true);
    setConsultationResult(null);

    try {
      if (useLLM) {
        const res = await aiOrchestrator.askAgentWithLLM(selectedAgent.id, queryInput);
        setConsultationResult({
          agentName: res.agentName,
          role: res.role,
          summary: res.responseSummary,
          epistemicStatus: res.epistemicStatus,
          confidence: res.confidence,
          evidenceReferences: res.evidenceReferences,
          recommendations: res.recommendations,
          isLLMGenerated: res.isLLMGenerated,
          provider: res.provider,
          model: res.model,
          latencyMs: res.latencyMs
        });
      } else {
        const start = Date.now();
        const res = aiOrchestrator.askAgent(selectedAgent.id, queryInput);
        setConsultationResult({
          agentName: res.agentName,
          role: res.role,
          summary: res.responseSummary,
          epistemicStatus: res.epistemicStatus,
          confidence: res.confidence,
          evidenceReferences: res.evidenceReferences,
          recommendations: res.recommendations,
          isLLMGenerated: false,
          provider: 'Deterministic Fallback Engine',
          model: 'nexus-rules',
          latencyMs: Date.now() - start
        });
      }
    } finally {
      setAnalyzing(false);
    }
  };

  const presetQueries = [
    'Assess in-scope perimeter assets and formulate non-destructive validation plan.',
    'Correlate active findings against MITRE ATT&CK techniques T1190 and T1595.',
    'Investigate SOC telemetry for lateral movement indicators or brute force probes.',
    'Synthesize executive risk narrative and prioritized remediation actions.'
  ];

  return (
    <div className="space-y-3.5 font-mono text-xs">
      {/* Top Banner */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/70 border border-cyan-500/40 rounded-lg text-cyan-400">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              AI Agent Fleet Governance & Live Reasoning Workspace
            </h2>
            <p className="text-[11px] text-slate-400 font-sans">
              12 specialized security agents operating above deterministic security engines with real Google Gemini integration.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <div className="bg-[#080c14] border border-slate-800 px-2.5 py-1 rounded flex items-center space-x-1.5">
            <Lock className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-[10.5px] text-slate-300">HITL MANDATORY: DUAL-OPERATOR TOKEN GATE</span>
          </div>
        </div>
      </div>

      {/* Interactive Agent Consultation Console */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
          <div className="flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-slate-100 uppercase tracking-wider">
              Specialized Agent Consultation Console
            </span>
          </div>

          {/* Reasoning Mode Toggle */}
          <div className="flex items-center space-x-2 bg-[#080c14] border border-slate-800 p-1 rounded-lg">
            <button
              onClick={() => setUseLLM(true)}
              className={`px-2.5 py-1 rounded text-[10.5px] font-bold flex items-center space-x-1 transition-colors ${
                useLLM ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Sparkles className="w-3 h-3" />
              <span>Google Gemini AI (Real)</span>
            </button>
            <button
              onClick={() => setUseLLM(false)}
              className={`px-2.5 py-1 rounded text-[10.5px] font-bold flex items-center space-x-1 transition-colors ${
                !useLLM ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-3 h-3" />
              <span>Deterministic Expert Engine</span>
            </button>
          </div>
        </div>

        {/* Query Builder */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="space-y-1">
            <label className="text-[10px] uppercase text-slate-400">Target Specialist Agent</label>
            <select
              value={selectedAgentId}
              onChange={e => setSelectedAgentId(e.target.value)}
              className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
            >
              {agents.map(a => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.category})
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-1 md:col-span-2">
            <label className="text-[10px] uppercase text-slate-400">Inquiry Prompt</label>
            <div className="flex items-center space-x-2">
              <input
                type="text"
                value={queryInput}
                onChange={e => setQueryInput(e.target.value)}
                placeholder="Ask agent for analysis, remediation, or MITRE mapping..."
                className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-cyan-300 font-sans"
              />
              <button
                onClick={handleConsult}
                disabled={analyzing || !queryInput.trim()}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-bold flex items-center space-x-1.5 shrink-0 transition-colors"
              >
                <Send className={`w-3.5 h-3.5 ${analyzing ? 'animate-spin' : ''}`} />
                <span>{analyzing ? 'Reasoning...' : 'Consult'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 text-[10px] text-slate-400">
          <span className="shrink-0 text-slate-500">Presets:</span>
          {presetQueries.map((q, idx) => (
            <button
              key={idx}
              onClick={() => setQueryInput(q)}
              className="bg-[#080c14] hover:bg-slate-800 border border-slate-800 text-slate-300 px-2 py-0.5 rounded truncate max-w-[280px]"
            >
              {q}
            </button>
          ))}
        </div>

        {/* Consultation Result Display */}
        {consultationResult && (
          <div className="bg-[#080c14] border border-cyan-800/60 rounded-lg p-3 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
              <div className="flex items-center space-x-2">
                <Bot className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-100">{consultationResult.agentName}</span>
                <span className="text-[10px] text-slate-400">({consultationResult.role})</span>
              </div>

              <div className="flex items-center space-x-2">
                <span
                  className={`text-[9.5px] px-2 py-0.5 rounded font-bold border ${
                    consultationResult.isLLMGenerated
                      ? 'bg-purple-950/60 border-purple-700/60 text-purple-300'
                      : 'bg-emerald-950/60 border-emerald-700/60 text-emerald-300'
                  }`}
                >
                  {consultationResult.isLLMGenerated ? 'REAL LLM GENERATED' : 'DETERMINISTIC FALLBACK'}
                </span>

                <span className="bg-[#0f172a] border border-slate-700 text-cyan-300 text-[9.5px] px-2 py-0.5 rounded font-bold">
                  {consultationResult.model} • {consultationResult.latencyMs}ms
                </span>

                <span className="bg-amber-950/60 border border-amber-800/60 text-amber-300 text-[9.5px] px-2 py-0.5 rounded font-bold">
                  [{consultationResult.epistemicStatus}] {(consultationResult.confidence * 100).toFixed(0)}%
                </span>
              </div>
            </div>

            <div className="space-y-1.5 font-sans">
              <div className="text-[10px] font-mono text-slate-500 uppercase">Analysis Synopsis</div>
              <p className="text-xs text-slate-200 leading-relaxed bg-[#0b0f19] p-2.5 rounded border border-slate-800">
                {consultationResult.summary}
              </p>
            </div>

            {consultationResult.recommendations.length > 0 && (
              <div className="space-y-1 font-sans">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Actionable Recommendations</div>
                <div className="space-y-1">
                  {consultationResult.recommendations.map((rec, i) => (
                    <div
                      key={i}
                      className="bg-[#0b0f19] border border-slate-800/70 p-2 rounded flex items-center justify-between text-xs text-slate-300"
                    >
                      <div className="flex items-center space-x-2">
                        <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span>{rec}</span>
                      </div>
                      <span className="text-[9.5px] font-mono bg-slate-900 text-amber-400 px-1.5 py-0.5 rounded">
                        HITL GATED
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 12 Specialized Agents Fleet Matrix */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-bold text-slate-200 uppercase tracking-wider">
          <div className="flex items-center space-x-1.5">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Registered Specialized Security Agents ({agents.length})</span>
          </div>
          <span className="text-[10px] text-slate-500 font-normal">All agents bound by immutable policy</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {agents.map(ag => (
            <div
              key={ag.id}
              className={`bg-[#0e1422] border rounded-lg p-3 space-y-2 transition-all cursor-pointer ${
                selectedAgentId === ag.id
                  ? 'border-cyan-500/70 shadow-lg shadow-cyan-950/20'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
              onClick={() => setSelectedAgentId(ag.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-1.5">
                  <Bot className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="font-bold text-slate-200 text-xs truncate max-w-[170px]">{ag.name}</span>
                </div>
                <span
                  className={`text-[9px] px-1.5 py-0.2 rounded font-bold border ${
                    ag.category === 'OFFENSIVE'
                      ? 'bg-red-950/60 text-red-300 border-red-800/60'
                      : ag.category === 'DEFENSIVE'
                      ? 'bg-blue-950/60 text-blue-300 border-blue-800/60'
                      : ag.category === 'EXECUTIVE'
                      ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60'
                      : 'bg-purple-950/60 text-purple-300 border-purple-800/60'
                  }`}
                >
                  {ag.category}
                </span>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed font-sans line-clamp-2">{ag.description}</p>

              <div className="pt-1.5 border-t border-slate-800/60 grid grid-cols-2 gap-2 text-[9px] text-slate-400">
                <div>
                  <span className="text-slate-500 block">ROLE:</span>
                  <span className="text-cyan-400 font-bold truncate block">{ag.role}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">EPISTEMIC:</span>
                  <span className="text-amber-400 font-bold">
                    [{ag.epistemicStatus}] {(ag.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>

              <div className="pt-0.5 flex flex-wrap gap-1">
                {ag.allowedToolIds.slice(0, 3).map(t => (
                  <span
                    key={t}
                    className="bg-[#080c14] border border-slate-800 text-slate-300 text-[9px] px-1.5 py-0.2 rounded"
                  >
                    {t}
                  </span>
                ))}
                {ag.allowedToolIds.length > 3 && (
                  <span className="text-[9px] text-slate-500">+{ag.allowedToolIds.length - 3}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
