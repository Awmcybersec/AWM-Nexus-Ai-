import React, { useState } from 'react';
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Activity,
  RefreshCw,
  Cpu,
  Layers,
  Radio,
  Sparkles,
  X,
  Play
} from 'lucide-react';
import { defensiveTelemetryEngine } from '../engine/offensiveDefensiveEngines';
import { siemManager } from '../services/siem/siemManager';
import { llmManager } from '../services/llm/llmManager';
import { DefensiveTelemetryEvent } from '../types';
import { LLMAnalysisResult } from '../services/llm/types';

export const DefensiveTelemetryView: React.FC = () => {
  const [events, setEvents] = useState<DefensiveTelemetryEvent[]>(defensiveTelemetryEngine.getAllEvents());
  const [syncing, setSyncing] = useState<boolean>(false);
  const [activeAnalysisModal, setActiveAnalysisModal] = useState<DefensiveTelemetryEvent | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [aiResult, setAiResult] = useState<LLMAnalysisResult | null>(null);

  const siemStatus = siemManager.getLastStatus();

  const handleRefresh = () => {
    setEvents([...defensiveTelemetryEngine.getAllEvents()]);
  };

  const handleSyncSiem = async () => {
    setSyncing(true);
    try {
      const res = await siemManager.syncAlerts();
      handleRefresh();
      alert(res.success ? `Successfully synced ${res.syncedCount} alerts from Wazuh.` : `Sync error: ${res.error}`);
    } finally {
      setSyncing(false);
    }
  };

  const handleDemoIngest = () => {
    const res = siemManager.ingestVerifiedSampleAlerts();
    handleRefresh();
    alert(`Ingested ${res.count} verified Wazuh schema alerts [SIMULATED] into Defensive Telemetry Engine.`);
  };

  const handleAnalyzeWithGemini = async (evt: DefensiveTelemetryEvent) => {
    setActiveAnalysisModal(evt);
    setAiLoading(true);
    setAiResult(null);

    try {
      const result = await llmManager.analyzeIncident({
        incidentTitle: `Telemetry Alert Investigation: ${evt.eventName}`,
        target: evt.target || '127.0.0.1',
        telemetryEvents: [
          {
            eventId: evt.eventId,
            controlSource: evt.sourceControl,
            detectedEvent: evt.eventName,
            mitreTechnique: evt.mitreId,
            detectionStatus: evt.detectionStatus
          }
        ],
        findings: []
      });
      setAiResult(result);
    } finally {
      setAiLoading(false);
    }
  };

  const getStatusBadge = (status: DefensiveTelemetryEvent['detectionStatus']) => {
    switch (status) {
      case 'LIVE':
        return (
          <span className="bg-emerald-950/70 border border-emerald-700/50 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>LIVE SIEM</span>
          </span>
        );
      case 'SIMULATED':
        return (
          <span className="bg-purple-950/70 border border-purple-700/50 text-purple-300 text-[10px] font-mono px-2 py-0.5 rounded">
            SIMULATED FEED
          </span>
        );
      case 'OFFLINE':
        return (
          <span className="bg-slate-900 border border-slate-700 text-slate-400 text-[10px] font-mono px-2 py-0.5 rounded">
            OFFLINE
          </span>
        );
      default:
        return (
          <span className="bg-red-950/70 border border-red-700/50 text-red-400 text-[10px] font-mono px-2 py-0.5 rounded">
            UNAVAILABLE
          </span>
        );
    }
  };

  return (
    <div className="space-y-3.5 font-mono text-xs">
      {/* Top Banner */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/60 border border-cyan-600/40 rounded-lg text-cyan-300">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">Defensive Telemetry & Wazuh SIEM Stream</h2>
            <p className="text-[11px] text-slate-400 font-sans">
              Live correlation of offensive pentesting actions with SIEM, WAF, and EDR detections.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleDemoIngest}
            className="px-2.5 py-1 bg-purple-950/70 hover:bg-purple-900 border border-purple-700/60 text-purple-200 rounded text-xs font-semibold"
          >
            + Ingest Wazuh Sample Alerts
          </button>
          <button
            onClick={handleSyncSiem}
            disabled={syncing}
            className="flex items-center space-x-1.5 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-semibold"
          >
            <RefreshCw className={`w-3 h-3 ${syncing ? 'animate-spin' : ''}`} />
            <span>{syncing ? 'Syncing...' : 'Sync Wazuh SIEM'}</span>
          </button>
        </div>
      </div>

      {/* Control Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>WAF DEFENSE LAYER</span>
            <span className="text-emerald-400 font-bold">92% EFF</span>
          </div>
          <div className="text-sm font-bold text-slate-100 font-mono">ModSecurity / WAF</div>
          <p className="text-[11px] text-slate-400 font-sans">Captured active fuzzing & directory traversal sweeps on staging API gateway.</p>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>WAZUH REST SIEM</span>
            <span className={siemStatus.status === 'CONNECTED' ? 'text-emerald-400 font-bold' : 'text-purple-400 font-bold'}>
              {siemStatus.status === 'CONNECTED' ? 'LIVE (88% EFF)' : 'CONNECTOR READY'}
            </span>
          </div>
          <div className="text-sm font-bold text-slate-100 font-mono">Wazuh Manager v4.x</div>
          <p className="text-[11px] text-slate-400 font-sans">
            {siemStatus.status === 'CONNECTED' ? 'Connected to live endpoint' : siemStatus.details}
          </p>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-1.5">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>HOST EDR AGENT</span>
            <span className="text-amber-400 font-bold">65% EFF</span>
          </div>
          <div className="text-sm font-bold text-slate-100 font-mono">CrowdStrike Falcon</div>
          <p className="text-[11px] text-slate-400 font-sans">Missed non-standard TLS handshake probe; simulated alert triggered.</p>
        </div>
      </div>

      {/* Defensive Events Correlation Table */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-1.5">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Offensive-Defensive Telemetry Ingestion Stream ({events.length})</span>
          </h3>
          <span className="text-[10.5px] text-slate-400 font-sans">Click "Analyze with Gemini" for instant AI alert triage</span>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg overflow-hidden font-mono text-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-[#090d16] text-slate-400 border-b border-slate-800 text-[10.5px]">
                <tr>
                  <th className="py-2 px-3">EVENT ID</th>
                  <th className="py-2 px-3">CONTROL / SENSOR</th>
                  <th className="py-2 px-3">DETECTED EVENT</th>
                  <th className="py-2 px-3">MITRE ID</th>
                  <th className="py-2 px-3">FEED STATUS</th>
                  <th className="py-2 px-3">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {events.map(evt => (
                  <tr key={evt.eventId} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2 px-3 font-bold text-slate-200">{evt.eventId}</td>
                    <td className="py-2 px-3 text-cyan-300 truncate max-w-[180px]">{evt.controlSource}</td>
                    <td className="py-2 px-3 text-slate-100 font-sans">{evt.detectedEvent}</td>
                    <td className="py-2 px-3 text-amber-300 font-bold">{evt.mitreTechnique || 'T1595'}</td>
                    <td className="py-2 px-3">{getStatusBadge(evt.detectionStatus)}</td>
                    <td className="py-2 px-3">
                      <button
                        onClick={() => handleAnalyzeWithGemini(evt)}
                        className="px-2 py-0.5 bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 rounded text-[9.5px] font-bold flex items-center space-x-1"
                      >
                        <Sparkles className="w-2.5 h-2.5 text-cyan-400" />
                        <span>Analyze with Gemini</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* AI Alert Triage Modal */}
      {activeAnalysisModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0e1422] border border-cyan-800/80 rounded-xl max-w-2xl w-full p-4 space-y-3 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-slate-100">
                  AI Alert Triage: {activeAnalysisModal.eventId}
                </span>
              </div>
              <button
                onClick={() => setActiveAnalysisModal(null)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {aiLoading ? (
              <div className="py-12 flex flex-col items-center justify-center space-y-2 text-slate-400">
                <Activity className="w-6 h-6 text-cyan-400 animate-spin" />
                <span className="text-xs">Triaging alert telemetry with Gemini model...</span>
              </div>
            ) : aiResult ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between bg-[#080c14] p-2 rounded border border-slate-800">
                  <span className="text-cyan-400 font-bold">{aiResult.title}</span>
                  <span className="text-[9.5px] bg-purple-950 border border-purple-800 px-2 py-0.5 rounded text-purple-300">
                    {aiResult.provider} ({aiResult.model})
                  </span>
                </div>

                <div className="space-y-1 font-sans">
                  <span className="text-[10px] font-mono text-slate-500 uppercase">Executive Synopsis</span>
                  <p className="text-xs text-slate-200 leading-relaxed bg-[#080c14] p-2.5 rounded border border-slate-800">
                    {aiResult.summary}
                  </p>
                </div>

                {aiResult.keyFindings.length > 0 && (
                  <div className="space-y-1 font-sans">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Key Triage Findings</span>
                    <ul className="list-disc list-inside bg-[#080c14] p-2.5 rounded border border-slate-800 text-xs text-slate-300 space-y-1">
                      {aiResult.keyFindings.map((f, idx) => (
                        <li key={idx}>{f}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {aiResult.recommendedActions.length > 0 && (
                  <div className="space-y-1 font-sans">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Defensive Hardening Recommendations</span>
                    <div className="space-y-1">
                      {aiResult.recommendedActions.map((act, idx) => (
                        <div key={idx} className="bg-[#080c14] p-2 rounded border border-slate-800 flex justify-between items-center text-xs">
                          <span className="text-slate-200">{act.action}</span>
                          <span className="text-[9.5px] font-mono bg-slate-900 text-amber-400 px-1.5 py-0.5 rounded">
                            {act.priority}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-end pt-2 border-t border-slate-800">
                  <button
                    onClick={() => setActiveAnalysisModal(null)}
                    className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-semibold"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
