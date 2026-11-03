import React, { useState } from 'react';
import { Lock, CheckCircle, XCircle, AlertTriangle, Shield, User, Clock, Terminal } from 'lucide-react';
import { HITLApprovalRequest } from '../types';
import { policyAndHitlEngine } from '../engine/policyAndHitlEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';

export const HitlGateView: React.FC = () => {
  const [requests, setRequests] = useState<HITLApprovalRequest[]>(policyAndHitlEngine.getAllRequests());
  const [rejectReason, setRejectReason] = useState<string>('');
  const [activeRejectId, setActiveRejectId] = useState<string | null>(null);

  const handleApprove = async (requestId: string) => {
    const res = policyAndHitlEngine.approveRequest(requestId, 'lead-operator-01');
    if (res.success) {
      setRequests([...policyAndHitlEngine.getAllRequests()]);
      // If there's an associated job, trigger execution
      const req = policyAndHitlEngine.getRequest(requestId);
      if (req?.jobId) {
        sandboxExecutionManager.executeJob(req.jobId);
      }
    }
  };

  const handleReject = (requestId: string) => {
    const res = policyAndHitlEngine.rejectRequest(requestId, 'lead-operator-01', rejectReason || 'Declined by security lead');
    if (res.success) {
      setRequests([...policyAndHitlEngine.getAllRequests()]);
      setActiveRejectId(null);
      setRejectReason('');
    }
  };

  const pending = requests.filter(r => r.status === 'PENDING');
  const history = requests.filter(r => r.status !== 'PENDING');

  return (
    <div className="space-y-3.5">
      {/* Header Info */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-amber-950/60 border border-amber-600/40 rounded-lg text-amber-300">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">Human-In-The-Loop (HITL) Safety Gate</h2>
            <p className="text-[11px] text-slate-400">
              High-impact pentesting commands and capability tier elevations require manual authorization by a Lead Security Operator.
            </p>
          </div>
        </div>
      </div>

      {/* Pending Approvals */}
      <div className="space-y-2.5">
        <div className="flex items-center space-x-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            Pending Authorization Queue ({pending.length})
          </h3>
        </div>

        {pending.length === 0 ? (
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-5 text-center text-xs text-slate-500 font-mono">
            No pending HITL authorization requests. All operations conform to pre-approved automated tiers.
          </div>
        ) : (
          <div className="space-y-2.5">
            {pending.map(req => (
              <div
                key={req.requestId}
                className="bg-[#0e1422] border border-amber-600/40 rounded-lg p-3.5 space-y-2.5 shadow-lg shadow-amber-950/10"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-1.5 border-b border-slate-800 pb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-mono font-bold text-amber-300 bg-amber-950/70 border border-amber-600/40 px-1.5 py-0.2 rounded">
                      {req.requestId}
                    </span>
                    <span className="text-xs font-semibold text-slate-100">Tool: {req.toolId}</span>
                    <span className="text-[11px] font-mono text-cyan-400">Target: {req.targetAddress}</span>
                  </div>

                  <span
                    className={`text-[9.5px] font-mono font-bold px-1.5 py-0.2 rounded ${
                      req.riskLevel === 'CRITICAL'
                        ? 'bg-red-950 text-red-300 border border-red-700'
                        : 'bg-amber-950 text-amber-300 border border-amber-700'
                    }`}
                  >
                    RISK: {req.riskLevel}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div>
                    <span className="text-slate-400 font-semibold text-[11px]">Policy Gate Reason: </span>
                    <span className="text-slate-200 text-xs">{req.reason}</span>
                  </div>

                  <div className="bg-[#080c14] border border-slate-800 p-2 rounded font-mono text-cyan-300 text-xs break-all">
                    {req.toolId} {req.parameters.join(' ')} {req.targetAddress}
                  </div>

                  <div className="flex items-center space-x-3 text-[10.5px] text-slate-500 font-mono">
                    <span>Requested by: <strong className="text-slate-300">{req.operatorId}</strong></span>
                    <span>Created: {new Date(req.createdAt).toLocaleTimeString()}</span>
                    {req.jobId && <span>Associated Job: {req.jobId}</span>}
                  </div>
                </div>

                {activeRejectId === req.requestId ? (
                  <div className="bg-red-950/20 border border-red-800/40 p-2.5 rounded space-y-1.5">
                    <label className="text-[11px] text-red-300 font-semibold block">Specify Rejection Justification:</label>
                    <input
                      type="text"
                      value={rejectReason}
                      onChange={e => setRejectReason(e.target.value)}
                      placeholder="e.g. Risk of disrupting staging telemetry cluster..."
                      className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200"
                    />
                    <div className="flex justify-end space-x-2">
                      <button
                        onClick={() => setActiveRejectId(null)}
                        className="px-2.5 py-1 bg-slate-800 text-slate-300 text-xs rounded"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={() => handleReject(req.requestId)}
                        className="px-2.5 py-1 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded"
                      >
                        Confirm Rejection
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-end space-x-2 pt-1">
                    <button
                      onClick={() => setActiveRejectId(req.requestId)}
                      className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-red-950/60 hover:text-red-300 border border-slate-700 text-slate-300 text-xs rounded transition-colors"
                    >
                      <XCircle className="w-3 h-3" />
                      <span>Reject</span>
                    </button>

                    <button
                      onClick={() => handleApprove(req.requestId)}
                      className="flex items-center space-x-1 px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded transition-colors"
                    >
                      <CheckCircle className="w-3 h-3" />
                      <span>Authorize Execution</span>
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Historical Approvals / Rejections */}
      {history.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Decision Audit Trail ({history.length})
          </h3>

          <div className="bg-[#0e1422] border border-slate-800 rounded-lg divide-y divide-slate-800/60 text-xs font-mono">
            {history.map(req => (
              <div key={req.requestId} className="px-3 py-2 flex items-center justify-between">
                <div>
                  <span className="text-slate-200 font-bold">{req.requestId}</span>
                  <span className="text-slate-500 mx-2">|</span>
                  <span className="text-slate-400">{req.toolId} on {req.targetAddress}</span>
                </div>

                <div className="flex items-center space-x-2.5">
                  <span className="text-slate-500 text-[11px]">{req.reviewedBy}</span>
                  {req.status === 'APPROVED' ? (
                    <span className="text-emerald-400 bg-emerald-950/70 border border-emerald-800/50 px-1.5 py-0.2 rounded text-[9.5px]">
                      APPROVED
                    </span>
                  ) : (
                    <span className="text-red-400 bg-red-950/70 border border-red-800/50 px-1.5 py-0.2 rounded text-[9.5px]">
                      REJECTED
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
