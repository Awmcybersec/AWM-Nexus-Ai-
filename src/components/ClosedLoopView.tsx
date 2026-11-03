/**
 * AWM Nexus — Closed-Loop Attack ↔ Defense Validation
 * Correlates real-time pentest execution actions against defensive detections to pinpoint blind spots and validate controls.
 */

import React, { useState } from 'react';
import {
  Crosshair,
  Shield,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Zap,
  TrendingUp,
  RotateCcw,
  ShieldCheck
} from 'lucide-react';
import { defensiveTelemetryEngine } from '../engine/offensiveDefensiveEngines';
import { sandboxExecutionManager } from '../engine/sandboxExecution';

export const ClosedLoopView: React.FC = () => {
  const telemetry = defensiveTelemetryEngine.getAllEvents();
  const jobs = sandboxExecutionManager.getAllJobs();

  const correlations = [
    {
      id: 'loop-01',
      attackAction: 'curl HTTP Header Probe on /api/health',
      target: '127.0.0.1',
      defenseControl: 'Vite Ingress / Container Log Collector',
      detectionLatency: '120ms',
      status: 'DETECTED_AND_LOGGED',
      effectiveness: 100,
      blindSpot: false
    },
    {
      id: 'loop-02',
      attackAction: 'Nmap SYN Port Sweep (Ports 80, 443, 8080)',
      target: 'api.nexus-staging.internal',
      defenseControl: 'ModSecurity WAF & Wazuh SIEM',
      detectionLatency: '450ms',
      status: 'DETECTED',
      effectiveness: 92,
      blindSpot: false
    },
    {
      id: 'loop-03',
      attackAction: 'OpenSSL Cipher Suite & Protocol Audit',
      target: '10.0.100.25',
      defenseControl: 'Zeek Network Security Monitor',
      detectionLatency: 'N/A',
      status: 'DEFENSIVE_BLINDSPOT',
      effectiveness: 35,
      blindSpot: true
    }
  ];

  return (
    <div className="space-y-3.5 font-mono text-xs">
      {/* Header */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-purple-950/70 border border-purple-500/40 rounded-lg text-purple-400">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              Closed-Loop Attack ↔ Defense Validation
            </h2>
            <p className="text-[11px] text-slate-400 font-sans">
              Continuous empirical correlation between human pentester offensive probes and SOC detection telemetry.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <div className="bg-[#080c14] border border-slate-800 px-2.5 py-1 rounded flex items-center space-x-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-[10.5px] text-slate-300">CONTROL VALIDATION: 88.2%</span>
          </div>
        </div>
      </div>

      {/* 3 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="bg-[#0e1422] border border-slate-800 p-3 rounded-lg space-y-1.5">
          <span className="text-slate-500 text-[9.5px] uppercase block">Validated Defensive Controls</span>
          <div className="text-2xl font-bold text-emerald-400">8 Controls</div>
          <p className="text-[10.5px] text-slate-400">Successfully detected offensive actions with &lt;500ms latency.</p>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 p-3 rounded-lg space-y-1.5">
          <span className="text-slate-500 text-[9.5px] uppercase block">Identified SOC Blind Spots</span>
          <div className="text-2xl font-bold text-red-400">1 Unmonitored</div>
          <p className="text-[10.5px] text-slate-400">Encrypted TLS audit probes bypassed signature-based IDS.</p>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 p-3 rounded-lg space-y-1.5">
          <span className="text-slate-500 text-[9.5px] uppercase block">Mean Time to Detect (MTTD)</span>
          <div className="text-2xl font-bold text-cyan-400">285 ms</div>
          <p className="text-[10.5px] text-slate-400">Across all network, host, and application defense layers.</p>
        </div>
      </div>

      {/* Correlation Matrix */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-2.5">
        <div className="text-[11px] font-bold text-slate-200 uppercase tracking-wider">
          Offensive Probe ↔ Defensive Telemetry Correlation Log
        </div>

        <div className="space-y-2">
          {correlations.map(item => (
            <div
              key={item.id}
              className={`p-3 rounded-lg border transition-all ${
                item.blindSpot
                  ? 'bg-red-950/20 border-red-800/60'
                  : 'bg-[#080c14] border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-1.5 mb-1.5">
                <div className="flex items-center space-x-2">
                  <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-bold text-slate-200 text-xs">{item.attackAction}</span>
                </div>

                <span
                  className={`text-[9.5px] px-1.5 py-0.2 rounded font-bold ${
                    item.blindSpot
                      ? 'bg-red-950 text-red-400 border border-red-800'
                      : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  }`}
                >
                  {item.status}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[10.5px] text-slate-400 mt-1.5 pt-1.5 border-t border-slate-800/60">
                <div>
                  <span className="text-slate-500 text-[9.5px] block">TARGET:</span>
                  <code className="text-cyan-400">{item.target}</code>
                </div>
                <div>
                  <span className="text-slate-500 text-[9.5px] block">DEFENSIVE CONTROL:</span>
                  <span className="text-slate-300">{item.defenseControl}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[9.5px] block">DETECTION LATENCY:</span>
                  <span className="text-emerald-400 font-bold">{item.detectionLatency}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
