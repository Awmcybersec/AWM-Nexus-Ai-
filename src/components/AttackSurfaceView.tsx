import React, { useState } from 'react';
import { Radio, ShieldAlert, ArrowRight, Server, Globe, CheckCircle2, ChevronRight, Activity, Terminal } from 'lucide-react';
import { attackSurfaceEngine, attackPathEngine } from '../engine/offensiveDefensiveEngines';
import { AttackSurfaceAsset, AttackPath } from '../types';

export const AttackSurfaceView: React.FC = () => {
  const [assets, setAssets] = useState<AttackSurfaceAsset[]>(attackSurfaceEngine.getAllAssets());
  const [paths, setPaths] = useState<AttackPath[]>(attackPathEngine.getAllPaths());
  const [selectedAsset, setSelectedAsset] = useState<AttackSurfaceAsset | null>(assets[0] || null);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(paths[0] || null);

  return (
    <div className="space-y-3.5">
      {/* Top Banner */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/60 border border-cyan-600/40 rounded-lg text-cyan-300">
            <Radio className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">Attack Surface Inventory & Multi-Hop Exploit Chains</h2>
            <p className="text-[11px] text-slate-400">
              Correlating port discovery, technology fingerprinting, and MITRE ATT&CK attack paths across in-scope infrastructure.
            </p>
          </div>
        </div>
      </div>

      {/* Attack Surface Assets Grid */}
      <div className="space-y-2.5">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-1.5">
          <Server className="w-3.5 h-3.5 text-cyan-400" />
          <span>Discovered Attack Surface Assets ({assets.length})</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {assets.map(asset => (
            <div
              key={asset.id}
              onClick={() => setSelectedAsset(asset)}
              className={`bg-[#0e1422] border rounded-lg p-3 cursor-pointer transition-all space-y-2 ${
                selectedAsset?.id === asset.id
                  ? 'border-cyan-500/60 shadow-md shadow-cyan-950/20 bg-slate-850'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-cyan-300 truncate">{asset.target}</span>
                <span
                  className={`text-[9px] font-mono font-semibold px-1.5 py-0.2 rounded ${
                    asset.riskCategory === 'HIGH'
                      ? 'bg-red-950/80 text-red-300 border border-red-700/50'
                      : asset.riskCategory === 'MEDIUM'
                      ? 'bg-amber-950/80 text-amber-300 border border-amber-700/50'
                      : 'bg-emerald-950/80 text-emerald-300 border border-emerald-700/50'
                  }`}
                >
                  EXPOSURE: {asset.exposureScore}/100
                </span>
              </div>

              <div className="text-[11px] text-slate-400 font-sans truncate">{asset.host}</div>

              <div className="space-y-0.5">
                <span className="text-[9px] font-mono text-slate-500 block uppercase">Open Ports ({asset.openPorts.length}):</span>
                <div className="flex flex-wrap gap-1">
                  {asset.openPorts.map(p => (
                    <span key={p.port} className="text-[9.5px] font-mono bg-slate-900 border border-slate-800 px-1 py-0.2 rounded text-slate-300">
                      {p.port}/{p.service}
                    </span>
                  ))}
                </div>
              </div>

              <div className="text-[9.5px] font-mono text-slate-500 border-t border-slate-800/80 pt-1.5 flex items-center justify-between">
                <span>Tech: {asset.technologies.slice(0, 2).join(', ')}</span>
                <span>Scanned: {new Date(asset.lastScanned).toLocaleDateString()}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Multi-Hop Attack Path Modeling */}
      <div className="space-y-2.5">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          <span>Multi-Hop Attack Paths ({paths.length})</span>
        </h3>

        {paths.map(path => (
          <div key={path.id} className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800 pb-2">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-[10px] font-mono bg-slate-900 border border-slate-800 text-slate-400 px-1.5 py-0.2 rounded">
                    {path.id}
                  </span>
                  <h4 className="text-xs font-bold text-slate-100">{path.name}</h4>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 font-sans">{path.description}</p>
              </div>

              <div className="flex items-center space-x-1.5">
                <span className="text-[9px] font-mono bg-red-950/80 border border-red-700/50 text-red-300 px-1.5 py-0.2 rounded">
                  SEVERITY: {path.severity}
                </span>
                <span className="text-[9px] font-mono bg-emerald-950/80 border border-emerald-700/50 text-emerald-300 px-1.5 py-0.2 rounded">
                  VERIFIED CHAIN
                </span>
              </div>
            </div>

            {/* Stepped Timeline */}
            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-slate-300 block">Exploit Sequence:</span>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
                {path.steps.map((step, idx) => (
                  <div key={step.stepId} className="bg-[#080c14] border border-slate-800/90 rounded-lg p-2.5 space-y-1.5 relative">
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <span className="text-cyan-400 font-bold">Step {idx + 1}</span>
                      <span className="bg-slate-900 border border-slate-800 text-slate-400 text-[9px] px-1 rounded">
                        {step.mitreTechniqueId}
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-slate-200">{step.name}</div>
                    <div className="text-[10.5px] text-slate-400">{step.technique}</div>

                    <div className="text-[9px] font-mono text-slate-500 pt-1.5 border-t border-slate-800/80 flex items-center justify-between">
                      <span>Tool: {step.toolUsed}</span>
                      <span className="text-amber-400">{step.mitreTactic}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
