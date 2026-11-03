import React, { useState } from 'react';
import {
  FileText,
  Download,
  Copy,
  Check,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Lock,
  Printer,
  Sparkles,
  Activity
} from 'lucide-react';
import { pentestReportEngine } from '../engine/offensiveDefensiveEngines';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { llmManager } from '../services/llm/llmManager';
import { PentestReport } from '../types';
import { LLMAnalysisResult } from '../services/llm/types';

export const ReportGeneratorView: React.FC = () => {
  const [reportType, setReportType] = useState<'TECHNICAL' | 'EXECUTIVE'>('TECHNICAL');
  const [copied, setCopied] = useState(false);
  const [generatingAi, setGeneratingAi] = useState(false);
  const [aiNarrative, setAiNarrative] = useState<LLMAnalysisResult | null>(null);

  const jobs = sandboxExecutionManager.getAllJobs();
  const findings = jobs.flatMap(j => j.findings);
  const baseReport: PentestReport = pentestReportEngine.generateReport('eng-2026-001', reportType, findings);

  const activeExecutiveSummary = aiNarrative?.summary || baseReport.executiveSummary;

  const handleGenerateAiNarrative = async () => {
    setGeneratingAi(true);
    try {
      const res = await llmManager.generateExecutiveNarrative({
        engagementCode: baseReport.engagementCode,
        clientName: 'AWM Nexus Enterprise Security',
        findingsCount: baseReport.findingsSummary.total,
        criticalCount: baseReport.findingsSummary.critical,
        highCount: baseReport.findingsSummary.high,
        mediumCount: baseReport.findingsSummary.medium,
        executiveFocus: 'DEFENSIVE_RESILIENCE',
        topFindings: findings.slice(0, 5).map(f => ({
          title: f.title,
          severity: f.severity,
          affectedAsset: `${f.host}${f.path || ''}`,
          summary: f.description
        }))
      });
      setAiNarrative(res);
    } finally {
      setGeneratingAi(false);
    }
  };

  const handleCopyMarkdown = () => {
    const md = `
# ${baseReport.title}
**Report ID:** ${baseReport.reportId}
**Engagement:** ${baseReport.engagementCode}
**Date:** ${baseReport.generatedAt}
**Risk Rating:** ${baseReport.riskRating} (Score: ${baseReport.overallRiskScore}/100)

## Executive Summary
${activeExecutiveSummary}

## Scope & Target Coverage
- Total Targets: ${baseReport.scopeSummary.totalTargets}
- In-Scope Assets Evaluated: ${baseReport.scopeSummary.inScopeTargets}
- Excluded Assets: ${baseReport.scopeSummary.excludedTargets}

## Findings Breakdown
- Critical: ${baseReport.findingsSummary.critical}
- High: ${baseReport.findingsSummary.high}
- Medium: ${baseReport.findingsSummary.medium}
- Low: ${baseReport.findingsSummary.low}
- Total Discovered: ${baseReport.findingsSummary.total}

## Prioritized Remediation Actions
${baseReport.recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n')}

## Cryptographic Provenance & Audit Integrity
- Audit Blocks Checked: ${baseReport.auditChainVerification.blocksChecked}
- Blockchain Integrity: ${baseReport.auditChainVerification.isValid ? 'VALID' : 'CORRUPTED'}
- Sealed Evidence Records: ${baseReport.evidenceList.length}
`;
    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const exportedData = {
      ...baseReport,
      executiveSummary: activeExecutiveSummary,
      aiNarrativeMetadata: aiNarrative
        ? {
            provider: aiNarrative.provider,
            model: aiNarrative.model,
            isLLMGenerated: aiNarrative.isLLMGenerated,
            latencyMs: aiNarrative.latencyMs
          }
        : undefined
    };
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(exportedData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `${baseReport.reportId}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-3.5 font-mono text-xs">
      {/* Controls Bar */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/60 border border-cyan-600/40 rounded-lg text-cyan-300">
            <FileText className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">Penetration Testing Report Generator</h2>
            <p className="text-[11px] text-slate-400 font-sans">
              Production-ready technical assessments backed by cryptographically sealed evidence and AI executive synthesis.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <div className="flex items-center bg-[#080c14] border border-slate-800 p-0.5 rounded-md">
            <button
              onClick={() => setReportType('TECHNICAL')}
              className={`px-2.5 py-1 text-xs font-semibold rounded transition-all ${
                reportType === 'TECHNICAL' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Technical
            </button>
            <button
              onClick={() => setReportType('EXECUTIVE')}
              className={`px-2.5 py-1 text-xs font-semibold rounded transition-all ${
                reportType === 'EXECUTIVE' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Executive
            </button>
          </div>

          <button
            onClick={handleGenerateAiNarrative}
            disabled={generatingAi}
            className="flex items-center space-x-1.5 px-3 py-1 bg-purple-950/70 hover:bg-purple-900 border border-purple-600/60 text-purple-200 rounded text-xs font-bold transition-colors"
          >
            <Sparkles className={`w-3.5 h-3.5 text-purple-300 ${generatingAi ? 'animate-spin' : ''}`} />
            <span>{generatingAi ? 'Synthesizing...' : 'Generate AI Executive Narrative'}</span>
          </button>

          <button
            onClick={handleCopyMarkdown}
            className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs rounded transition-colors"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy MD'}</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="flex items-center space-x-1 px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded transition-colors"
          >
            <Download className="w-3 h-3" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Rendered Document View */}
      <div className="bg-[#0a0e17] border border-slate-800 rounded-lg p-4 space-y-4 max-w-5xl mx-auto shadow-2xl">
        {/* Document Header */}
        <div className="border-b border-slate-800 pb-3 space-y-1">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-1.5">
            <div>
              <span className="text-[10px] font-mono text-cyan-400 uppercase font-bold tracking-wider">
                AWM NEXUS OPERATIONS ASSESSMENT
              </span>
              <h1 className="text-base font-bold text-slate-100 mt-0.5">{baseReport.title}</h1>
            </div>

            <div className="text-right font-mono text-[11px] text-slate-400">
              <div>REPORT ID: <strong className="text-slate-200">{baseReport.reportId}</strong></div>
              <div>GENERATED: {new Date(baseReport.generatedAt).toLocaleString()}</div>
            </div>
          </div>
        </div>

        {/* Risk & Posture Highlight Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5 font-mono">
          <div className="bg-[#0e1422] border border-slate-800 p-2.5 rounded-lg">
            <span className="text-[10px] text-slate-500 block">OVERALL RISK RATING</span>
            <div className="text-base font-bold text-red-400 mt-0.5">{baseReport.riskRating}</div>
            <span className="text-[9.5px] text-slate-400 block mt-0.5">Score: {baseReport.overallRiskScore}/100</span>
          </div>

          <div className="bg-[#0e1422] border border-slate-800 p-2.5 rounded-lg">
            <span className="text-[10px] text-slate-500 block">SCOPE COVERAGE</span>
            <div className="text-base font-bold text-cyan-300 mt-0.5">{baseReport.scopeSummary.inScopeTargets} Targets</div>
            <span className="text-[9.5px] text-slate-400 block mt-0.5">{baseReport.scopeSummary.excludedTargets} Excluded Assets</span>
          </div>

          <div className="bg-[#0e1422] border border-slate-800 p-2.5 rounded-lg">
            <span className="text-[10px] text-slate-500 block">CRITICAL & HIGH FINDINGS</span>
            <div className="text-base font-bold text-amber-400 mt-0.5">
              {baseReport.findingsSummary.critical + baseReport.findingsSummary.high} / {baseReport.findingsSummary.total}
            </div>
            <span className="text-[9.5px] text-slate-400 block mt-0.5">
              {baseReport.findingsSummary.critical} Crit, {baseReport.findingsSummary.high} High
            </span>
          </div>

          <div className="bg-[#0e1422] border border-slate-800 p-2.5 rounded-lg">
            <span className="text-[10px] text-slate-500 block">AUDIT PROVENANCE</span>
            <div className="text-base font-bold text-emerald-400 mt-0.5">VERIFIED</div>
            <span className="text-[9.5px] text-slate-400 block mt-0.5">{baseReport.auditChainVerification.blocksChecked} Blocks Sealed</span>
          </div>
        </div>

        {/* Executive Summary Narrative */}
        <div className="bg-[#0e1422] border border-slate-800/80 rounded-lg p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono flex items-center space-x-1.5">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
              <span>Executive Risk Narrative</span>
            </h3>
            {aiNarrative && (
              <span className="text-[9.5px] bg-purple-950/70 border border-purple-700/60 text-purple-300 px-2 py-0.5 rounded font-bold">
                {aiNarrative.provider} ({aiNarrative.model}) • {aiNarrative.latencyMs}ms
              </span>
            )}
          </div>
          <p className="text-xs text-slate-200 leading-relaxed font-sans bg-[#080c14] p-3 rounded border border-slate-800/80">
            {activeExecutiveSummary}
          </p>
        </div>

        {/* Technical Findings Section (if Technical Report) */}
        {reportType === 'TECHNICAL' && (
          <div className="space-y-2">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
              Normalized Vulnerability Findings ({baseReport.findings.length})
            </h3>

            {baseReport.findings.length === 0 ? (
              <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-5 text-center text-xs text-slate-500 font-mono">
                No active vulnerability findings discovered in this assessment window.
              </div>
            ) : (
              <div className="space-y-2">
                {baseReport.findings.map(f => (
                  <div key={f.findingId} className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-bold text-slate-100 font-mono">{f.title}</span>
                        <span className="text-xs font-mono text-cyan-400">({f.findingId})</span>
                      </div>
                      <span
                        className={`text-[9.5px] font-mono font-bold px-1.5 py-0.2 rounded ${
                          f.severity === 'CRITICAL'
                            ? 'bg-red-950 text-red-300 border border-red-700'
                            : f.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-300 border border-amber-700'
                            : 'bg-slate-900 text-slate-300 border border-slate-700'
                        }`}
                      >
                        {f.severity} (CVSS: {f.cvssScore})
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 font-sans">{f.description}</p>
                    <div className="text-[10.5px] text-slate-400 font-mono">
                      Target: {f.host}{f.path || ''} | CWE: {f.cwe}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Prioritized Recommendations */}
        <div className="bg-[#0e1422] border border-slate-800/80 rounded-lg p-3.5 space-y-2">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider font-mono">
            Remediation & Hardening Roadmap
          </h3>
          <div className="space-y-1">
            {baseReport.recommendations.map((rec, i) => (
              <div key={i} className="flex items-start space-x-2 text-xs font-sans text-slate-300">
                <span className="font-mono text-cyan-400 font-bold shrink-0">{i + 1}.</span>
                <span>{rec}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
