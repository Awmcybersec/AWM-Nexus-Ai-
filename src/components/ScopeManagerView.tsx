import React, { useState } from 'react';
import { Shield, CheckCircle, XCircle, AlertTriangle, Plus, Search, Lock, Calendar, Globe, Server } from 'lucide-react';
import { scopeEngine } from '../engine/scopeEngine';
import { auditLedger } from '../engine/auditLedger';
import { TargetAsset } from '../types';

interface ScopeManagerViewProps {
  onSelectTarget?: (target: string) => void;
}

export const ScopeManagerView: React.FC<ScopeManagerViewProps> = ({ onSelectTarget }) => {
  const [engagement, setEngagement] = useState(scopeEngine.getAllEngagements()[0]);
  const [testTarget, setTestTarget] = useState('10.0.100.25');
  const [testResult, setTestResult] = useState<ReturnType<typeof scopeEngine.validateTargetScope> | null>(null);

  // New target modal state
  const [showAddModal, setShowAddModal] = useState(false);
  const [newName, setNewName] = useState('');
  const [newAddress, setNewAddress] = useState('');
  const [newType, setNewType] = useState<TargetAsset['type']>('HOST');
  const [newEnv, setNewEnv] = useState<TargetAsset['environment']>('STAGING');

  const handleTestScope = () => {
    if (!testTarget.trim()) return;
    const res = scopeEngine.validateTargetScope(engagement, testTarget);
    setTestResult(res);
  };

  const handleAddTarget = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim() || !newAddress.trim()) return;

    const target = scopeEngine.addTarget(engagement.id, {
      name: newName,
      address: newAddress,
      type: newType,
      ports: [80, 443],
      environment: newEnv,
      criticality: 'MEDIUM',
      inScope: true,
      active: true,
      authorizedUntil: engagement.endDate
    });

    auditLedger.appendBlock('operator-human-01', 'TARGET_ADDED', engagement.tenantId, engagement.id, newAddress, {
      targetId: target.id,
      name: newName,
      address: newAddress
    });

    setEngagement({ ...scopeEngine.getEngagement(engagement.id)! });
    setShowAddModal(false);
    setNewName('');
    setNewAddress('');
  };

  return (
    <div className="space-y-3.5">
      {/* Engagement Overview Card */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2.5 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-[10.5px] font-mono bg-cyan-950/70 border border-cyan-700/50 text-cyan-300 px-1.5 py-0.2 rounded">
                {engagement.code}
              </span>
              <h2 className="text-sm font-bold text-slate-100">{engagement.name}</h2>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">Client: {engagement.clientName} | Tenant: {engagement.tenantId}</p>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <div className="bg-slate-900 border border-slate-800 px-2.5 py-1 rounded text-slate-300">
              <span className="text-slate-500">MAX TIER: </span>
              <span className="text-emerald-400 font-semibold">{engagement.allowedCapabilityTier}</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 px-2.5 py-1 rounded text-slate-300">
              <span className="text-slate-500">WINDOW: </span>
              <span className="text-slate-200">{engagement.startDate.slice(0, 10)} → {engagement.endDate.slice(0, 10)}</span>
            </div>
          </div>
        </div>

        {/* Scope Tester Bar */}
        <div className="mt-3 pt-1">
          <label className="text-[11px] font-semibold text-slate-300 block mb-1">
            Interactive RoE Scope & Boundary Pre-flight Validator:
          </label>
          <div className="flex items-center space-x-2">
            <input
              type="text"
              value={testTarget}
              onChange={e => setTestTarget(e.target.value)}
              placeholder="Enter IP, CIDR, or Domain to test (e.g. 10.0.100.25, 10.0.0.1, api.nexus-staging.internal)..."
              className="flex-1 bg-[#080c14] border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
            />
            <button
              onClick={handleTestScope}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium rounded transition-colors whitespace-nowrap"
            >
              Verify Target Scope
            </button>
          </div>

          {testResult && (
            <div
              className={`mt-2 p-2.5 rounded border text-xs flex items-start space-x-2 ${
                testResult.inScope
                  ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-300'
                  : 'bg-red-950/20 border-red-800/40 text-red-300'
              }`}
            >
              {testResult.inScope ? (
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
              ) : (
                <XCircle className="w-3.5 h-3.5 text-red-400 mt-0.5 flex-shrink-0" />
              )}
              <div>
                <span className="font-bold font-mono text-xs">
                  {testResult.inScope ? '[+] TARGET AUTHORIZED IN SCOPE' : '[-] TARGET REJECTED OUT OF SCOPE / EXCLUDED'}
                </span>
                <p className="mt-0.5 text-slate-300 text-[11px]">{testResult.reason}</p>
                {testResult.matchedRule && (
                  <span className="text-[9.5px] font-mono text-slate-400 mt-0.5 block">
                    Matched Rule ID: {testResult.matchedRule}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Target Assets Inventory */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <h3 className="text-xs font-bold text-slate-200">Authorized Target Assets</h3>
            <span className="text-[11px] text-slate-500 font-mono">({engagement.targets.length} defined)</span>
          </div>

          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center space-x-1 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs px-2.5 py-1 rounded transition-colors"
          >
            <Plus className="w-3 h-3 text-cyan-400" />
            <span>Add Target</span>
          </button>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#090d16] text-slate-400 border-b border-slate-800 text-[10.5px]">
                <tr>
                  <th className="py-2 px-3">ASSET NAME</th>
                  <th className="py-2 px-3">TYPE</th>
                  <th className="py-2 px-3">ADDRESS</th>
                  <th className="py-2 px-3">ENVIRONMENT</th>
                  <th className="py-2 px-3">CRITICALITY</th>
                  <th className="py-2 px-3">AUTHORIZED PORTS</th>
                  <th className="py-2 px-3">SCOPE STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {engagement.targets.map(t => (
                  <tr key={t.id} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2 px-3 font-semibold text-slate-100">{t.name}</td>
                    <td className="py-2 px-3 text-slate-400">{t.type}</td>
                    <td className="py-2 px-3 text-cyan-300 font-mono">{t.address}</td>
                    <td className="py-2 px-3">
                      <span className="bg-slate-900 border border-slate-800 px-1.5 py-0.2 rounded text-[10px] text-slate-300">
                        {t.environment}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`text-[9px] font-semibold px-1.5 py-0.2 rounded ${
                          t.criticality === 'CRITICAL'
                            ? 'bg-red-950/60 text-red-300 border border-red-800/40'
                            : t.criticality === 'HIGH'
                            ? 'bg-amber-950/60 text-amber-300 border border-amber-800/40'
                            : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                      >
                        {t.criticality}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400">{t.ports.join(', ')}</td>
                    <td className="py-2 px-3">
                      {t.inScope ? (
                        <span className="bg-emerald-950/70 border border-emerald-800/50 text-emerald-400 px-1.5 py-0.2 rounded text-[9.5px] flex items-center space-x-1 w-max">
                          <CheckCircle className="w-2.5 h-2.5" />
                          <span>IN SCOPE</span>
                        </span>
                      ) : (
                        <span className="bg-red-950/70 border border-red-800/50 text-red-400 px-1.5 py-0.2 rounded text-[9.5px] flex items-center space-x-1 w-max">
                          <XCircle className="w-2.5 h-2.5" />
                          <span>EXCLUDED</span>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Scope Rules & Exclusions Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center space-x-1.5 text-xs font-bold text-emerald-400">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>Authorized Scope Inclusions</span>
          </div>
          <div className="space-y-1.5">
            {engagement.scopeRules.filter(r => r.type === 'INCLUDE').map(r => (
              <div key={r.ruleId} className="bg-[#080c14] border border-slate-800/80 p-2 rounded text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-cyan-300 font-semibold">{r.pattern}</span>
                  <span className="text-[9.5px] text-slate-500">{r.ruleId}</span>
                </div>
                <p className="text-slate-400 text-[10.5px] mt-0.5 font-sans">{r.description}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex items-center space-x-1.5 text-xs font-bold text-red-400">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Strict Exclusions & Out-of-Scope Rules</span>
          </div>
          <div className="space-y-1.5">
            {engagement.scopeRules.filter(r => r.type === 'EXCLUDE').map(r => (
              <div key={r.ruleId} className="bg-[#080c14] border border-red-900/30 p-2 rounded text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-red-300 font-semibold">{r.pattern}</span>
                  <span className="text-[9px] text-red-400 font-bold bg-red-950/60 px-1 rounded">EXCLUDE</span>
                </div>
                <p className="text-slate-400 text-[10.5px] mt-0.5 font-sans">{r.description}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Add Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-3">
          <form onSubmit={handleAddTarget} className="bg-[#0b0f17] border border-slate-800 rounded-lg max-w-sm w-full p-4 space-y-3">
            <h3 className="text-xs font-bold text-slate-100">Register In-Scope Target Asset</h3>

            <div className="space-y-0.5">
              <label className="text-[11px] text-slate-300">Asset Name:</label>
              <input
                type="text"
                required
                value={newName}
                onChange={e => setNewName(e.target.value)}
                placeholder="e.g. Staging Auth Node 02"
                className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200"
              />
            </div>

            <div className="space-y-0.5">
              <label className="text-[11px] text-slate-300">Target Address (IP / Domain / CIDR):</label>
              <input
                type="text"
                required
                value={newAddress}
                onChange={e => setNewAddress(e.target.value)}
                placeholder="e.g. 10.0.100.50 or auth.nexus-staging.internal"
                className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-0.5">
                <label className="text-[11px] text-slate-300">Type:</label>
                <select
                  value={newType}
                  onChange={e => setNewType(e.target.value as TargetAsset['type'])}
                  className="w-full bg-[#080c14] border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-200"
                >
                  <option value="HOST">HOST</option>
                  <option value="IP">IP</option>
                  <option value="CIDR">CIDR</option>
                  <option value="DOMAIN">DOMAIN</option>
                  <option value="API_ENDPOINT">API_ENDPOINT</option>
                </select>
              </div>

              <div className="space-y-0.5">
                <label className="text-[11px] text-slate-300">Environment:</label>
                <select
                  value={newEnv}
                  onChange={e => setNewEnv(e.target.value as TargetAsset['environment'])}
                  className="w-full bg-[#080c14] border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-200"
                >
                  <option value="SANDBOX_LAB">SANDBOX_LAB</option>
                  <option value="DEVELOPMENT">DEVELOPMENT</option>
                  <option value="STAGING">STAGING</option>
                  <option value="PRODUCTION">PRODUCTION</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded"
              >
                Save Target
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
