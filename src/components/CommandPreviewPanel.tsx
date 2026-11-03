/**
 * AWM Nexus — Dedicated Command Preview & Pre-Flight Execution Panel
 * Displays real-time generated command, arguments, safety classification,
 * capability tier, scope validation result, HITL requirements, and execution buttons.
 */

import React, { useState, useEffect } from 'react';
import { Terminal, Shield, CheckCircle2, AlertTriangle, Play, Lock, FileCode, Check, Copy, ArrowRight, Eye, RefreshCw, Cpu, Crosshair } from 'lucide-react';
import { toolRegistry } from '../engine/toolRegistry';
import { scopeEngine } from '../engine/scopeEngine';
import { policyAndHitlEngine } from '../engine/policyAndHitlEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { SecurityTool, ToolProfile, TargetAsset, ScopeValidationResult, CapabilityTier } from '../types';

interface CommandPreviewPanelProps {
  initialToolId?: string;
  initialTarget?: string;
  initialProfileId?: string;
  onJobCreated?: (jobId: string) => void;
}

export const CommandPreviewPanel: React.FC<CommandPreviewPanelProps> = ({
  initialToolId,
  initialTarget,
  initialProfileId,
  onJobCreated
}) => {
  const tools = toolRegistry.getAllTools();
  const engagement = scopeEngine.getAllEngagements()[0];
  const targets = engagement?.targets || [];

  const [selectedToolId, setSelectedToolId] = useState<string>(initialToolId || tools[0]?.id || 'curl-probe');
  const [selectedTarget, setSelectedTarget] = useState<string>(initialTarget || targets[0]?.address || '127.0.0.1');
  const [selectedProfileId, setSelectedProfileId] = useState<string>(initialProfileId || '');
  const [customFlags, setCustomFlags] = useState<string>('');
  const [executionFeedback, setExecutionFeedback] = useState<{ type: 'SUCCESS' | 'ERROR' | 'WARNING'; message: string; jobId?: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const selectedTool = tools.find(t => t.id === selectedToolId) || tools[0];
  const activeProfile: ToolProfile = selectedTool.profiles.find(p => p.id === selectedProfileId) || selectedTool.profiles[0];

  // Pre-flight argument construction & shell sanitization
  const customParamsList = customFlags.trim() ? customFlags.trim().split(/\s+/) : [];
  const argBuildResult = toolRegistry.buildInvocationArguments(selectedTool, activeProfile, selectedTarget, customParamsList);

  // Pre-flight scope check
  const scopeValidation = scopeEngine.validateExecution(
    engagement?.id || 'eng-2026-001',
    engagement?.tenantId || 'TENANT-AWM-01',
    'operator-human-01',
    'LEAD_SECURITY_ENGINEER',
    selectedTarget,
    activeProfile.capabilityTier
  );

  // Pre-flight policy & HITL evaluation
  const targetAsset = targets.find(t => t.address === selectedTarget);
  const policyResult = policyAndHitlEngine.evaluatePolicy(
    selectedTool,
    activeProfile,
    targetAsset,
    selectedTarget,
    customParamsList
  );

  // Generated CLI command string
  const generatedCommand = argBuildResult.isSafe
    ? `${selectedTool.binaryName} ${argBuildResult.safeArgs.join(' ')}`
    : `[BLOCKED] Invalid / Unsafe arguments: ${argBuildResult.rejectionReason}`;

  const handleCopyCommand = () => {
    navigator.clipboard.writeText(generatedCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExecute = async (mode: 'LIVE' | 'SIMULATED' | 'DRY_RUN') => {
    setExecutionFeedback(null);

    const res = sandboxExecutionManager.createJob(
      engagement.tenantId,
      engagement.id,
      'operator-human-01',
      selectedTool.id,
      selectedTarget,
      activeProfile.id,
      customParamsList,
      mode
    );

    if (res.error) {
      setExecutionFeedback({
        type: 'ERROR',
        message: `Execution Rejected by Security Pipeline: ${res.error}`
      });
      return;
    }

    if (res.requiresHITL) {
      setExecutionFeedback({
        type: 'WARNING',
        message: `High-Impact Action Intercepted. Operator Approval Request Created (#${res.hitlRequestId}). Proceed to HITL Gate to authorize.`,
        jobId: res.job?.jobId
      });
      if (onJobCreated && res.job) onJobCreated(res.job.jobId);
      return;
    }

    if (res.job) {
      setExecutionFeedback({
        type: 'SUCCESS',
        message: `Job ${res.job.jobId} created in [${res.job.mode}] mode. Execution dispatched to sandbox.`,
        jobId: res.job.jobId
      });

      if (onJobCreated) onJobCreated(res.job.jobId);
      sandboxExecutionManager.executeJob(res.job.jobId);
    }
  };

  const handleRequestApproval = () => {
    handleExecute('LIVE');
  };

  return (
    <div className="space-y-3.5">
      {/* Top Banner */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/60 border border-cyan-600/40 rounded-lg text-cyan-300">
            <Crosshair className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">Command Preview & Safety Enforcement Matrix</h2>
            <p className="text-[11px] text-slate-400">
              Live syntax preview, argument sanitization, scope boundary validation, and capability tier enforcement.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[10px] font-mono bg-slate-900 border border-slate-800 text-slate-400 px-2 py-0.5 rounded">
            OPERATOR: <strong className="text-slate-200">LEAD PENTESTER (TIER 4)</strong>
          </span>
        </div>
      </div>

      {/* Execution Feedback Notification */}
      {executionFeedback && (
        <div
          className={`p-2.5 rounded-lg border text-xs font-mono flex items-center justify-between ${
            executionFeedback.type === 'SUCCESS'
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
              : executionFeedback.type === 'WARNING'
              ? 'bg-amber-950/40 border-amber-800/60 text-amber-300'
              : 'bg-red-950/40 border-red-800/60 text-red-300'
          }`}
        >
          <div className="flex items-center space-x-2">
            {executionFeedback.type === 'SUCCESS' ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            )}
            <span className="text-xs">{executionFeedback.message}</span>
          </div>
          <button
            onClick={() => setExecutionFeedback(null)}
            className="text-slate-400 hover:text-slate-200 text-[11px] underline ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 3-Column Configuration Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
        {/* 1. Tool Selection */}
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between text-slate-300 font-bold uppercase tracking-wider text-[11px]">
            <span>1. Select Security Tool</span>
            <span className="text-cyan-400 text-[9.5px]">({tools.length} Registered)</span>
          </div>

          <select
            value={selectedToolId}
            onChange={e => {
              setSelectedToolId(e.target.value);
              const t = tools.find(x => x.id === e.target.value);
              if (t && t.profiles[0]) setSelectedProfileId(t.profiles[0].id);
            }}
            className="w-full bg-[#080c14] border border-slate-800 rounded py-1.5 px-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {tools.map(t => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.binaryName}) [{t.availabilityStatus}]
              </option>
            ))}
          </select>

          <div className="bg-[#080c14] border border-slate-800/80 p-2 rounded text-[10.5px] space-y-1 text-slate-400">
            <div className="flex justify-between">
              <span>Category:</span>
              <span className="text-slate-200 font-semibold">{selectedTool.category}</span>
            </div>
            <div className="flex justify-between">
              <span>Binary Status:</span>
              <span
                className={`font-semibold ${
                  selectedTool.availabilityStatus === 'INSTALLED' ? 'text-emerald-400' : 'text-purple-400'
                }`}
              >
                {selectedTool.availabilityStatus}
              </span>
            </div>
            <div className="flex justify-between">
              <span>Capability Tier:</span>
              <span className="text-amber-400">{selectedTool.capabilityTier}</span>
            </div>
          </div>
        </div>

        {/* 2. Target Selection */}
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between text-slate-300 font-bold uppercase tracking-wider text-[11px]">
            <span>2. Candidate Target</span>
            <span className="text-cyan-400 text-[9.5px]">RoE Bound</span>
          </div>

          <select
            value={selectedTarget}
            onChange={e => setSelectedTarget(e.target.value)}
            className="w-full bg-[#080c14] border border-slate-800 rounded py-1.5 px-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {targets.map(tgt => (
              <option key={tgt.id} value={tgt.address}>
                {tgt.name} ({tgt.address}) - {tgt.environment}
              </option>
            ))}
          </select>

          <div className="space-y-0.5">
            <span className="text-[9.5px] text-slate-500 block">OR ENTER CUSTOM IP / HOSTNAME:</span>
            <input
              type="text"
              value={selectedTarget}
              onChange={e => setSelectedTarget(e.target.value)}
              placeholder="e.g. 10.0.100.25 or staging.corp.internal"
              className="w-full bg-[#080c14] border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="bg-[#080c14] border border-slate-800/80 p-1.5 rounded text-[10px]">
            <span className="text-slate-500 block">SCOPE ROE VERIFICATION:</span>
            {scopeValidation.inScope ? (
              <span className="text-emerald-400 font-semibold flex items-center space-x-1 mt-0.5">
                <CheckCircle2 className="w-2.5 h-2.5" />
                <span>IN SCOPE (Rule: {scopeValidation.matchedRule || 'Authorized'})</span>
              </span>
            ) : (
              <span className="text-red-400 font-semibold flex items-center space-x-1 mt-0.5">
                <AlertTriangle className="w-2.5 h-2.5" />
                <span>{scopeValidation.reason}</span>
              </span>
            )}
          </div>
        </div>

        {/* 3. Profile & Flags Selection */}
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between text-slate-300 font-bold uppercase tracking-wider text-[11px]">
            <span>3. Execution Profile</span>
            <span className="text-cyan-400 text-[9.5px]">({selectedTool.profiles.length} Profiles)</span>
          </div>

          <select
            value={selectedProfileId || activeProfile.id}
            onChange={e => setSelectedProfileId(e.target.value)}
            className="w-full bg-[#080c14] border border-slate-800 rounded py-1.5 px-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {selectedTool.profiles.map(p => (
              <option key={p.id} value={p.id}>
                {p.name} {p.requiresHITL ? '⚠️ (HITL Required)' : ''}
              </option>
            ))}
          </select>

          <div className="space-y-0.5">
            <span className="text-[9.5px] text-slate-500 block">CUSTOM ARGS (WHITELISTED ONLY):</span>
            <input
              type="text"
              value={customFlags}
              onChange={e => setCustomFlags(e.target.value)}
              placeholder="e.g. -p 80,443 -Pn"
              className="w-full bg-[#080c14] border border-slate-800 rounded px-2 py-1 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="bg-[#080c14] border border-slate-800/80 p-1.5 rounded text-[10px]">
            <span className="text-slate-500 block">HITL INTERCEPTION:</span>
            {policyResult.requiresHITL ? (
              <span className="text-amber-400 font-semibold flex items-center space-x-1 mt-0.5">
                <Lock className="w-2.5 h-2.5" />
                <span>APPROVAL REQUIRED ({policyResult.hitlReason || 'High-Impact'})</span>
              </span>
            ) : (
              <span className="text-emerald-400 font-semibold flex items-center space-x-1 mt-0.5">
                <CheckCircle2 className="w-2.5 h-2.5" />
                <span>AUTOMATIC PRE-CLEARANCE</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Command Syntax Preview Box */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3 font-mono">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
          <div className="flex items-center space-x-2">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Pre-Flight Command Syntax & Parameter Preview
            </span>
          </div>

          <button
            onClick={handleCopyCommand}
            className="flex items-center space-x-1 text-[11px] text-slate-400 hover:text-slate-200 bg-slate-900 border border-slate-800 px-2 py-0.5 rounded transition-colors"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        {/* Shell Code Display */}
        <div className="bg-[#050811] border border-slate-800/90 rounded-lg p-3 text-xs font-mono relative overflow-x-auto">
          <div className="text-slate-500 text-[9.5px] uppercase block mb-0.5">
            CLI INVOCATION ARGS [{argBuildResult.isSafe ? 'VERIFIED SAFE' : 'SECURITY REJECTED'}]:
          </div>
          <code className={argBuildResult.isSafe ? 'text-emerald-300 text-xs font-bold' : 'text-red-400 font-bold text-xs'}>
            $ {generatedCommand}
          </code>
        </div>

        {/* Pre-Flight Inspection Indicators */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
          <div className="bg-[#080c14] border border-slate-800 p-2 rounded">
            <span className="text-slate-500 block text-[9.5px]">CAPABILITY TIER:</span>
            <span className="text-amber-400 font-semibold text-xs">{activeProfile.capabilityTier}</span>
          </div>

          <div className="bg-[#080c14] border border-slate-800 p-2 rounded">
            <span className="text-slate-500 block text-[9.5px]">SAFETY CLASSIFICATION:</span>
            <span className={argBuildResult.isSafe ? 'text-emerald-400 font-semibold text-xs' : 'text-red-400 font-semibold text-xs'}>
              {argBuildResult.isSafe ? 'SANITIZED & ALLOWED' : 'ILLEGAL ARGS DETECTED'}
            </span>
          </div>

          <div className="bg-[#080c14] border border-slate-800 p-2 rounded">
            <span className="text-slate-500 block text-[9.5px]">EXECUTION MODE:</span>
            <span className={selectedTool.availabilityStatus === 'INSTALLED' ? 'text-emerald-400 font-semibold text-xs' : 'text-purple-400 font-semibold text-xs'}>
              {selectedTool.availabilityStatus === 'INSTALLED' ? 'LIVE SUBPROCESS' : 'DETERMINISTIC SANDBOX'}
            </span>
          </div>

          <div className="bg-[#080c14] border border-slate-800 p-2 rounded">
            <span className="text-slate-500 block text-[9.5px]">SANDBOX TIMEOUT:</span>
            <span className="text-slate-300 font-semibold text-xs">{activeProfile.timeoutSeconds}s Max</span>
          </div>
        </div>

        {/* Action Controls Bar */}
        <div className="border-t border-slate-800/80 pt-2.5 flex flex-wrap items-center justify-between gap-2">
          <div className="text-[11px] text-slate-400">
            Pipeline Policy Status:{' '}
            {scopeValidation.valid && argBuildResult.isSafe ? (
              <strong className="text-emerald-400">READY FOR EXECUTION</strong>
            ) : (
              <strong className="text-red-400">EXECUTION BLOCKED BY POLICY</strong>
            )}
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleExecute('DRY_RUN')}
              className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-semibold rounded transition-colors"
            >
              <Eye className="w-3 h-3 text-cyan-400" />
              <span>DRY RUN</span>
            </button>

            {policyResult.requiresHITL ? (
              <button
                onClick={handleRequestApproval}
                disabled={!scopeValidation.valid || !argBuildResult.isSafe}
                className="flex items-center space-x-1.5 px-3 py-1 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white text-xs font-semibold rounded transition-colors shadow-sm"
              >
                <Lock className="w-3 h-3" />
                <span>REQUEST HITL APPROVAL</span>
              </button>
            ) : (
              <button
                onClick={() => handleExecute(selectedTool.availabilityStatus === 'INSTALLED' ? 'LIVE' : 'SIMULATED')}
                disabled={!scopeValidation.valid || !argBuildResult.isSafe}
                className="flex items-center space-x-1.5 px-4 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold rounded transition-colors shadow-sm"
              >
                <Play className="w-3 h-3 fill-current" />
                <span>EXECUTE TOOL</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
