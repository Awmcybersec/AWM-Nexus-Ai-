/**
 * AWM Nexus — Top Bar & Contextual Actions Header
 * Houses global tenant context, live operational status indicators, quick action triggers,
 * operator session details, and ledger health indicators.
 */

import React from 'react';
import {
  Terminal,
  Shield,
  Lock,
  Database,
  CheckCircle2,
  AlertTriangle,
  Play,
  Bell,
  Search,
  Zap,
  Activity,
  Layers,
  Radio
} from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  installedToolsCount: number;
  totalToolsCount: number;
  auditValid: boolean;
  pendingHitlCount: number;
  activeJobsCount: number;
  onQuickExecute?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  installedToolsCount,
  totalToolsCount,
  auditValid,
  pendingHitlCount,
  activeJobsCount,
  onQuickExecute
}) => {
  return (
    <header className="bg-[#0b0f17] border-b border-slate-800/80 sticky top-0 z-40 select-none">
      {/* Top Banner: Global Identity, Tenant, Engagement & Operator Context */}
      <div className="max-w-[1600px] mx-auto px-4 py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
        {/* Left: Branding & Tenant */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-mono font-bold tracking-wider text-slate-100 text-sm">AWM NEXUS</span>
            <span className="text-slate-600 font-mono">|</span>
            <span className="text-cyan-400 font-mono text-xs bg-cyan-950/70 border border-cyan-800/50 px-2 py-0.5 rounded font-semibold">
              PENTEST OPS
            </span>
          </div>

          <div className="hidden lg:flex items-center space-x-2 text-slate-400 font-mono text-xs">
            <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded text-slate-300">
              TENANT: <span className="text-cyan-400 font-semibold">TENANT-AWM-01</span>
            </span>
            <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded text-slate-300">
              ENGAGEMENT: <span className="text-emerald-400 font-semibold">ENG-2026-ALPHA</span>
            </span>
          </div>
        </div>

        {/* Right: Quick Action Indicators & Operator Session Controls */}
        <div className="flex items-center space-x-2.5 font-mono text-xs">
          {/* Quick Context Action: ASCL Terminal Quick Launch */}
          <button
            onClick={() => setActiveTab('terminal')}
            className={`flex items-center space-x-1.5 px-2.5 py-1 rounded transition-all ${
              activeTab === 'terminal'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/50'
                : 'bg-slate-900/90 text-slate-300 border border-slate-800 hover:border-slate-700 hover:text-white'
            }`}
            title="Open ASCL Command Terminal"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">CLI PROMPT</span>
          </button>

          {/* Quick Context Action: HITL Alert Badge */}
          {pendingHitlCount > 0 && (
            <button
              onClick={() => setActiveTab('hitl')}
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse hover:bg-amber-500/30 transition-all font-semibold"
              title="Pending Human-in-the-Loop Approval Required"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{pendingHitlCount} HITL PENDING</span>
            </button>
          )}

          {/* Quick Context Action: Active Jobs Monitor */}
          {activeJobsCount > 0 && (
            <button
              onClick={() => setActiveTab('jobs')}
              className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 animate-pulse hover:bg-emerald-500/30 transition-all font-semibold"
              title="Running Pentest Jobs"
            >
              <Activity className="w-3.5 h-3.5" />
              <span>{activeJobsCount} ACTIVE JOBS</span>
            </button>
          )}

          {/* Audit Ledger Status Indicator */}
          <div
            onClick={() => setActiveTab('evidence')}
            className="hidden md:flex items-center space-x-1.5 bg-slate-900/90 border border-slate-800 px-2.5 py-1 rounded cursor-pointer hover:border-slate-700 transition-colors"
            title="Cryptographic Hash-Chain Ledger Status"
          >
            <Database className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-500">LEDGER:</span>
            {auditValid ? (
              <span className="text-emerald-400 flex items-center space-x-1 font-bold">
                <CheckCircle2 className="w-3 h-3" />
                <span>SEALED</span>
              </span>
            ) : (
              <span className="text-red-400 flex items-center space-x-1 font-bold">
                <AlertTriangle className="w-3 h-3" />
                <span>ALERT</span>
              </span>
            )}
          </div>

          {/* Operator RBAC Badge */}
          <div className="flex items-center space-x-1.5 bg-slate-900/90 border border-slate-800 px-2.5 py-1 rounded text-slate-300">
            <span className="text-slate-500 hidden sm:inline">OP:</span>
            <span className="text-slate-200 font-semibold truncate max-w-[110px]">lead-pentester</span>
            <span className="text-amber-400 bg-amber-950/70 border border-amber-800/60 text-[10px] px-1.5 py-0.5 rounded font-bold">
              T4
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
