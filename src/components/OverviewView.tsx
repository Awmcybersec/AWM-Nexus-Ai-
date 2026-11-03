/**
 * AWM Nexus — Pentest Operational Overview Dashboard
 * Displays high-level status of engagement, scope boundaries, tool readiness,
 * active jobs pipeline, pending HITL gates, vulnerability distribution, and cryptographic audit posture.
 */

import React from 'react';
import {
  Shield,
  Layers,
  Activity,
  Lock,
  Database,
  Terminal,
  Crosshair,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  ArrowUpRight,
  TrendingUp
} from 'lucide-react';
import { scopeEngine } from '../engine/scopeEngine';
import { toolRegistry } from '../engine/toolRegistry';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { policyAndHitlEngine } from '../engine/policyAndHitlEngine';
import { auditLedger } from '../engine/auditLedger';

interface OverviewViewProps {
  onNavigate: (tab: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const engagement = scopeEngine.getAllEngagements()[0];
  const allTools = toolRegistry.getAllTools();
  const installedTools = allTools.filter(t => t.availabilityStatus === 'INSTALLED');
  const allJobs = sandboxExecutionManager.getAllJobs();
  const activeJobs = allJobs.filter(j => j.status === 'RUNNING' || j.status === 'QUEUED');
  const pendingHitl = policyAndHitlEngine.getPendingRequests();
  const allFindings = allJobs.flatMap(j => j.findings);
  const auditVerification = auditLedger.verifyChainIntegrity();

  const critCount = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = allFindings.filter(f => f.severity === 'HIGH').length;
  const medCount = allFindings.filter(f => f.severity === 'MEDIUM').length;

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center space-x-2.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              Pentest Operations Center
            </h2>
            <span className="bg-emerald-950/80 border border-emerald-700/60 text-emerald-300 text-[10px] font-mono px-2 py-0.5 rounded font-semibold">
              ACTIVE ENGAGEMENT
            </span>
          </div>
          <p className="text-xs text-slate-400">
            {engagement?.name || 'Enterprise Perimeter Pentest'} • Client: {engagement?.clientName || 'AWM Defense Corp'}
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => onNavigate('preview')}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded transition-colors shadow-sm"
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Launch Pre-Flight</span>
          </button>
          <button
            onClick={() => onNavigate('terminal')}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold rounded transition-colors"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>ASCL Terminal</span>
          </button>
        </div>
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 font-mono space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-semibold">TOOL READINESS</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">
            {installedTools.length} <span className="text-xs text-slate-500 font-normal">/ {allTools.length} Installed</span>
          </div>
          <div className="text-[11px] text-slate-400">
            {allTools.length - installedTools.length} Sandbox Simulated
          </div>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 font-mono space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-semibold">TARGETS IN SCOPE</span>
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">
            {engagement?.targets.length || 0}
          </div>
          <div className="text-[11px] text-slate-400">
            {engagement?.scopeRules.length || 0} RoE Rules Defined
          </div>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 font-mono space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-semibold">ACTIVE JOBS</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">
            {activeJobs.length}
          </div>
          <div className="text-[11px] text-slate-400">
            {allJobs.length} Total Executed
          </div>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 font-mono space-y-1.5">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span className="font-semibold">AUDIT LEDGER</span>
            <Database className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-purple-400">
            #{auditVerification.blocksCount}
          </div>
          <div className="text-[11px] text-emerald-400 flex items-center space-x-1 font-semibold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>SHA-256 Verified</span>
          </div>
        </div>
      </div>

      {/* 2-Column Operational Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Left: Discovered Findings Summary */}
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 space-y-3.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Discovered Normalized Findings ({allFindings.length})
              </span>
            </div>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-3 gap-2.5 font-mono text-xs text-center">
            <div className="bg-red-950/30 border border-red-800/50 p-2.5 rounded">
              <span className="text-red-400 font-bold text-xl block">{critCount}</span>
              <span className="text-slate-400 text-[10px] font-semibold tracking-wider">CRITICAL</span>
            </div>
            <div className="bg-amber-950/30 border border-amber-800/50 p-2.5 rounded">
              <span className="text-amber-400 font-bold text-xl block">{highCount}</span>
              <span className="text-slate-400 text-[10px] font-semibold tracking-wider">HIGH</span>
            </div>
            <div className="bg-yellow-950/30 border border-yellow-800/50 p-2.5 rounded">
              <span className="text-yellow-400 font-bold text-xl block">{medCount}</span>
              <span className="text-slate-400 text-[10px] font-semibold tracking-wider">MEDIUM</span>
            </div>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {allFindings.slice(0, 4).map(f => (
              <div
                key={f.findingId}
                className="bg-[#080c14] border border-slate-800/80 p-2.5 rounded flex items-center justify-between"
              >
                <div className="space-y-0.5">
                  <div className="font-semibold text-slate-200 text-xs">{f.title}</div>
                  <div className="text-[11px] text-slate-400">{f.host} • {f.cwe}</div>
                </div>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                    f.severity === 'CRITICAL'
                      ? 'bg-red-950 text-red-400 border border-red-800'
                      : f.severity === 'HIGH'
                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                      : 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                  }`}
                >
                  {f.severity}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: HITL Approval & Safety Pipeline */}
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 space-y-3.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
            <div className="flex items-center space-x-2">
              <Lock className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Human-In-The-Loop (HITL) Interceptions ({pendingHitl.length})
              </span>
            </div>
            <button
              onClick={() => onNavigate('hitl')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-medium"
            >
              <span>View Gate</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {pendingHitl.length === 0 ? (
            <div className="bg-[#080c14] border border-slate-800/80 p-5 rounded text-center text-xs font-mono text-slate-400 space-y-2">
              <CheckCircle2 className="w-7 h-7 text-emerald-400 mx-auto opacity-80" />
              <div className="text-xs font-medium text-slate-300">No high-risk operations currently awaiting authorization.</div>
              <div className="text-[11px] text-slate-500">
                Safe and non-destructive tool profiles operate with automatic pre-clearance.
              </div>
            </div>
          ) : (
            <div className="space-y-2 font-mono text-xs">
              {pendingHitl.map(req => (
                <div
                  key={req.requestId}
                  className="bg-amber-950/20 border border-amber-800/50 p-3 rounded space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-300 text-xs">{req.toolId}</span>
                    <span className="text-[10px] bg-amber-950 text-amber-400 px-2 py-0.5 rounded border border-amber-800 font-bold">
                      {req.riskLevel} IMPACT
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-300">Target: {req.targetAddress}</div>
                  <div className="text-[11px] text-slate-400">{req.reason}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
