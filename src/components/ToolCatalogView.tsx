import React, { useState } from 'react';
import {
  Layers,
  Search,
  CheckCircle,
  AlertCircle,
  Play,
  Shield,
  ExternalLink,
  Terminal,
  RefreshCw,
  Sliders,
  X,
  AlertTriangle,
  Info,
  Check
} from 'lucide-react';
import { SecurityTool, ToolCategory, ToolProfile, TargetAsset, ToolExecutionMode } from '../types';
import { toolRegistry } from '../engine/toolRegistry';
import { scopeEngine } from '../engine/scopeEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { detectRealBinaries } from '../engine/binaryDetector';

interface ToolCatalogViewProps {
  onJobStarted?: (jobId: string) => void;
  onSelectTool?: (toolId: string) => void;
}

export const ToolCatalogView: React.FC<ToolCatalogViewProps> = ({ onJobStarted, onSelectTool }) => {
  const [tools, setTools] = useState<SecurityTool[]>(toolRegistry.getAllTools());
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedTool, setSelectedTool] = useState<SecurityTool | null>(null);
  const [selectedProfile, setSelectedProfile] = useState<ToolProfile | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<string>('127.0.0.1');
  const [selectedMode, setSelectedMode] = useState<ToolExecutionMode>('LIVE');
  const [customFlags, setCustomFlags] = useState<string>('');
  const [detecting, setDetecting] = useState<boolean>(false);
  const [executionResult, setExecutionResult] = useState<{ success: boolean; message: string; jobId?: string } | null>(null);

  const engagement = scopeEngine.getAllEngagements()[0];
  const targets: TargetAsset[] = engagement ? engagement.targets : [];

  const categories: { id: string; label: string }[] = [
    { id: 'ALL', label: 'All Tools' },
    { id: 'RECON', label: 'Reconnaissance' },
    { id: 'WEB_ENUM', label: 'Web Enumeration' },
    { id: 'WEB_API', label: 'Web & API' },
    { id: 'VULNERABILITY', label: 'Vulnerability' },
    { id: 'NETWORK', label: 'Network' },
    { id: 'DNS_TLS', label: 'DNS & TLS' },
    { id: 'CLOUD', label: 'Cloud' },
    { id: 'KUBERNETES', label: 'Kubernetes' },
    { id: 'PASSWORD_HASH', label: 'Password & Hash' },
    { id: 'CONTROLLED_VAL', label: 'Controlled Validation' }
  ];

  const handleScanBinaries = async () => {
    setDetecting(true);
    await detectRealBinaries();
    setTools([...toolRegistry.getAllTools()]);
    setDetecting(false);
  };

  const openToolModal = (tool: SecurityTool) => {
    setSelectedTool(tool);
    setSelectedProfile(tool.profiles[0] || null);
    setCustomFlags('');
    setExecutionResult(null);
  };

  const filteredTools = tools.filter(t => {
    const matchesCat = selectedCategory === 'ALL' || t.category === selectedCategory;
    const matchesSearch =
      !searchQuery ||
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.binaryName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesSearch;
  });

  // Pre-flight scope check for modal
  const scopeValidation = selectedTool && selectedProfile ? scopeEngine.validateTargetScope(engagement, selectedTarget) : null;

  // Command preview string
  const commandPreview = selectedTool && selectedProfile ?
    `${selectedTool.binaryName} ${selectedProfile.defaultFlags.join(' ')} ${customFlags ? customFlags + ' ' : ''}${selectedTarget}` : '';

  const handleExecute = async () => {
    if (!selectedTool || !selectedProfile) return;

    const customParams = customFlags.split(/\s+/).filter(f => f.trim().length > 0);

    const res = sandboxExecutionManager.createJob(
      engagement.tenantId,
      engagement.id,
      'operator-human-01',
      selectedTool.id,
      selectedTarget,
      selectedProfile.id,
      customParams,
      selectedMode
    );

    if (res.error) {
      setExecutionResult({ success: false, message: res.error });
      return;
    }

    if (res.requiresHITL) {
      setExecutionResult({
        success: true,
        message: `High-Risk Action Intercepted: HITL Approval Request #${res.hitlRequestId} has been created. Please authorize in the HITL Gate.`,
        jobId: res.job?.jobId
      });
      return;
    }

    if (res.job) {
      setExecutionResult({
        success: true,
        message: `Job ${res.job.jobId} created in sandbox. Executing in background...`,
        jobId: res.job.jobId
      });
      if (onJobStarted) onJobStarted(res.job.jobId);
      // Trigger execution in background
      sandboxExecutionManager.executeJob(res.job.jobId);
    }
  };

  const getStatusBadge = (tool: SecurityTool) => {
    if (tool.availabilityStatus === 'INSTALLED') {
      return (
        <span className="bg-emerald-950/70 border border-emerald-600/40 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          <span>INSTALLED (LIVE)</span>
        </span>
      );
    }
    if (tool.availabilityStatus === 'AVAILABLE') {
      const isAgent = tool.version?.includes('Kali Agent');
      return (
        <span className={`bg-cyan-950/70 border border-cyan-600/40 ${isAgent ? 'text-cyan-300' : 'text-emerald-300'} text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1`}>
          <span className={`w-1.5 h-1.5 rounded-full ${isAgent ? 'bg-cyan-400' : 'bg-emerald-400'}`}></span>
          <span>{isAgent ? 'LIVE (Kali Agent)' : 'LIVE (Container Engine)'}</span>
        </span>
      );
    }
    if (tool.availabilityStatus === 'SIMULATED') {
      return (
        <span className="bg-purple-950/70 border border-purple-600/40 text-purple-300 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1">
          <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
          <span>SIMULATED</span>
        </span>
      );
    }
    if (tool.availabilityStatus === 'NOT_CONFIGURED') {
      return (
        <span className="bg-amber-950/70 border border-amber-600/40 text-amber-400 text-[10px] font-mono px-2 py-0.5 rounded">
          NOT CONFIGURED
        </span>
      );
    }
    return (
      <span className="bg-slate-900 border border-slate-700/60 text-slate-400 text-[10px] font-mono px-2 py-0.5 rounded">
        REQUIRES KALI AGENT
      </span>
    );
  };

  return (
    <div className="space-y-3">
      {/* Top Controls Bar */}
      <div className="bg-[#0e1422] p-3 rounded-lg border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
        <div className="flex-1 relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search security tools by name, binary (nmap, curl, nuclei, amass), or capability..."
            className="w-full bg-[#080c14] border border-slate-800 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>

        <button
          onClick={handleScanBinaries}
          disabled={detecting}
          className="flex items-center justify-center space-x-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs px-3 py-1.5 rounded-md transition-colors"
        >
          <RefreshCw className={`w-3 h-3 text-cyan-400 ${detecting ? 'animate-spin' : ''}`} />
          <span>{detecting ? 'Probing Operating System...' : 'Re-verify Native Binaries'}</span>
        </button>
      </div>

      {/* Category Pills */}
      <div className="flex items-center space-x-1 overflow-x-auto pb-0.5 scrollbar-none">
        {categories.map(cat => (
          <button
            key={cat.id}
            onClick={() => setSelectedCategory(cat.id)}
            className={`px-2.5 py-0.5 rounded-full text-[11px] font-medium whitespace-nowrap transition-colors ${
              selectedCategory === cat.id
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800/80'
            }`}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Tools Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filteredTools.map(tool => (
          <div
            key={tool.id}
            className="bg-[#0d121f] border border-slate-800/90 hover:border-slate-700/80 rounded-lg p-3 flex flex-col justify-between transition-all group space-y-2"
          >
            <div>
              <div className="flex items-start justify-between gap-1.5 mb-1.5">
                <div>
                  <h3 className="text-xs font-semibold text-slate-100 group-hover:text-cyan-400 transition-colors">
                    {tool.name}
                  </h3>
                  <span className="text-[10px] font-mono text-slate-400">bin: {tool.binaryName}</span>
                </div>
                {getStatusBadge(tool)}
              </div>

              <p className="text-[11px] text-slate-400 line-clamp-2 mb-2 leading-relaxed">
                {tool.description}
              </p>

              {tool.version && (
                <div className="text-[9.5px] font-mono text-slate-400 bg-slate-950/60 border border-slate-800 px-1.5 py-0.5 rounded mb-2 truncate">
                  <span className="text-slate-500">DETECTED: </span>
                  <span className="text-emerald-400">{tool.version}</span>
                </div>
              )}

              <div className="flex flex-wrap gap-1 mb-2">
                <span className="text-[9.5px] bg-slate-900 border border-slate-800 text-slate-300 px-1.5 py-0.2 rounded font-mono">
                  {tool.category}
                </span>
                <span className="text-[9.5px] bg-slate-900 border border-slate-800 text-slate-400 px-1.5 py-0.2 rounded font-mono">
                  TIER: {tool.capabilityTier}
                </span>
                <span className="text-[9.5px] bg-slate-900 border border-slate-800 text-slate-400 px-1.5 py-0.2 rounded font-mono">
                  {tool.profiles.length} profile(s)
                </span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <a
                href={tool.documentationUrl}
                target="_blank"
                rel="noreferrer"
                className="text-[10.5px] text-slate-500 hover:text-slate-300 flex items-center space-x-1"
              >
                <span>Docs</span>
                <ExternalLink className="w-2.5 h-2.5" />
              </a>

              <button
                onClick={() => openToolModal(tool)}
                className="flex items-center space-x-1 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-[11px] px-2.5 py-1 rounded transition-colors"
              >
                <Sliders className="w-3 h-3" />
                <span>Configure & Run</span>
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Execution Modal */}
      {selectedTool && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-3">
          <div className="bg-[#0b0f17] border border-slate-800 rounded-lg max-w-xl w-full p-4 space-y-3 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <div>
                  <h2 className="text-sm font-bold text-slate-100">{selectedTool.name}</h2>
                  <span className="text-[10px] font-mono text-slate-400">Binary: {selectedTool.binaryName} | Category: {selectedTool.category}</span>
                </div>
              </div>
              <button
                onClick={() => setSelectedTool(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Profile Selection */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-slate-300">Execution Profile:</label>
              <div className="grid grid-cols-1 gap-1.5">
                {selectedTool.profiles.map(prof => (
                  <button
                    key={prof.id}
                    onClick={() => setSelectedProfile(prof)}
                    className={`p-2 rounded border text-left transition-all ${
                      selectedProfile?.id === prof.id
                        ? 'bg-slate-800/90 border-cyan-500/60 text-slate-100'
                        : 'bg-slate-900/50 border-slate-800 text-slate-400 hover:bg-slate-900'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-200">{prof.name}</span>
                      {prof.requiresHITL && (
                        <span className="text-[9px] font-mono bg-amber-950/70 border border-amber-600/50 text-amber-300 px-1 py-0.2 rounded flex items-center space-x-1">
                          <AlertTriangle className="w-2.5 h-2.5 inline" />
                          <span>REQUIRES HITL</span>
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">{prof.description}</p>
                    <div className="text-[9.5px] font-mono text-slate-500 mt-0.5">
                      Flags: {prof.defaultFlags.join(' ') || 'none'} | Timeout: {prof.timeoutSeconds}s
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Target Selection */}
            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-300">Target Asset (In Scope):</label>
              <select
                value={selectedTarget}
                onChange={e => setSelectedTarget(e.target.value)}
                className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
              >
                {targets.map(t => (
                  <option key={t.id} value={t.address}>
                    {t.name} — {t.address} {t.inScope ? '(IN SCOPE)' : '[EXCLUDED - OUT OF SCOPE]'}
                  </option>
                ))}
              </select>
            </div>

            {/* Mode Selection */}
            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-300">Execution Mode:</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedMode('LIVE')}
                  className={`p-2 rounded border text-left text-xs transition-colors ${
                    selectedMode === 'LIVE'
                      ? 'bg-cyan-950/80 border-cyan-500/80 text-cyan-200'
                      : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="font-bold flex items-center space-x-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                    <span>LIVE EXECUTION</span>
                  </div>
                  <p className="text-[10px] text-slate-400 mt-0.5 font-sans">
                    Local container or connected Kali Execution Agent
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setSelectedMode('SIMULATED')}
                  className={`p-2 rounded border text-left text-xs transition-colors ${
                    selectedMode === 'SIMULATED'
                      ? 'bg-amber-950/80 border-amber-500/80 text-amber-200'
                      : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="font-bold flex items-center space-x-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                    <span>SIMULATED / LAB</span>
                  </div>
                  <p className="text-[10px] text-slate-400 mt-0.5 font-sans">
                    Offline safe training simulation (no raw network packets)
                  </p>
                </button>
              </div>
            </div>

            {/* Scope Pre-flight Check Feedback */}
            {scopeValidation && (
              <div
                className={`p-2 rounded border text-xs flex items-start space-x-2 ${
                  scopeValidation.inScope
                    ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                    : 'bg-red-950/20 border-red-800/40 text-red-300'
                }`}
              >
                {scopeValidation.inScope ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                ) : (
                  <AlertCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 flex-shrink-0" />
                )}
                <div>
                  <span className="font-semibold text-[11px]">
                    {scopeValidation.inScope ? 'RoE Scope Verified:' : 'Scope Boundary Rejection:'}
                  </span>
                  <p className="text-[11px] text-slate-300">{scopeValidation.reason}</p>
                </div>
              </div>
            )}

            {/* Command Preview */}
            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-slate-300">Command Invocation Preview (Sandbox Encapsulated):</label>
              <div className="bg-[#080c14] border border-slate-800/90 rounded p-2 font-mono text-xs text-cyan-300">
                {commandPreview}
              </div>
            </div>

            {/* Execution Result Feedback */}
            {executionResult && (
              <div
                className={`p-2.5 rounded border text-xs ${
                  executionResult.success
                    ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
                    : 'bg-red-950/30 border-red-800/60 text-red-300'
                }`}
              >
                {executionResult.message}
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedTool(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded transition-colors"
              >
                Close
              </button>
              <button
                onClick={handleExecute}
                disabled={!scopeValidation?.inScope}
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-semibold rounded flex items-center space-x-1.5 transition-colors"
              >
                <Play className="w-3 h-3" />
                <span>Launch in Sandbox</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
