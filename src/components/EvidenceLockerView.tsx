import React, { useState } from 'react';
import { Database, ShieldCheck, CheckCircle2, AlertTriangle, Key, Search, FileCheck, RefreshCw, Hash, Lock } from 'lucide-react';
import { evidenceEngine } from '../engine/riskAndEvidenceEngine';
import { auditLedger } from '../engine/auditLedger';
import { EvidenceRecord, AuditBlock } from '../types';

export const EvidenceLockerView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'EVIDENCE' | 'AUDIT'>('EVIDENCE');
  const [evidenceList, setEvidenceList] = useState<EvidenceRecord[]>(evidenceEngine.getAllEvidence());
  const [auditBlocks, setAuditBlocks] = useState<AuditBlock[]>(auditLedger.getBlocks());
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [verificationFeedback, setVerificationFeedback] = useState<{ id: string; valid: boolean; message: string } | null>(null);
  const [chainIntegrity, setChainIntegrity] = useState<ReturnType<typeof auditLedger.verifyChainIntegrity>>(
    auditLedger.verifyChainIntegrity()
  );

  const handleVerifyEvidence = (ev: EvidenceRecord) => {
    const res = evidenceEngine.verifyEvidenceIntegrity(ev.evidenceId);
    if (res.isValid) {
      setVerificationFeedback({
        id: ev.evidenceId,
        valid: true,
        message: `Cryptographic Seal Verified: Stdout SHA-256 (${ev.rawStdoutHash.slice(0, 16)}...) and signature match locker provenance.`
      });
    } else {
      setVerificationFeedback({
        id: ev.evidenceId,
        valid: false,
        message: `Tamper Alert: ${res.error}`
      });
    }
  };

  const handleVerifyChain = () => {
    const res = auditLedger.verifyChainIntegrity();
    setChainIntegrity(res);
    setAuditBlocks([...auditLedger.getBlocks()]);
  };

  const filteredEvidence = evidenceList.filter(
    e =>
      !searchQuery ||
      e.evidenceId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.toolId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.target.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-3.5">
      {/* Top Banner & Sub-Tabs */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/60 border border-cyan-600/40 rounded-lg text-cyan-300">
            <Database className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100">Cryptographic Evidence & Audit Provenance Core</h2>
            <p className="text-[11px] text-slate-400">
              Tamper-evident SHA-256 raw output lockers and hash-chained blockchain ledger guaranteeing non-repudiation.
            </p>
          </div>
        </div>

        <div className="flex items-center bg-[#080c14] border border-slate-800 p-0.5 rounded-lg shrink-0">
          <button
            onClick={() => setActiveSubTab('EVIDENCE')}
            className={`px-2.5 py-1 rounded text-xs font-semibold transition-all ${
              activeSubTab === 'EVIDENCE'
                ? 'bg-cyan-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Evidence Locker ({evidenceList.length})
          </button>
          <button
            onClick={() => setActiveSubTab('AUDIT')}
            className={`px-2.5 py-1 rounded text-xs font-semibold transition-all ${
              activeSubTab === 'AUDIT'
                ? 'bg-cyan-600 text-white shadow-xs'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Audit Chain ({auditBlocks.length} Blocks)
          </button>
        </div>
      </div>

      {/* Verification Feedback Banner */}
      {verificationFeedback && (
        <div
          className={`p-2.5 rounded-lg border text-xs flex items-center justify-between ${
            verificationFeedback.valid
              ? 'bg-emerald-950/30 border-emerald-800/60 text-emerald-300'
              : 'bg-red-950/30 border-red-800/60 text-red-300'
          }`}
        >
          <div className="flex items-center space-x-2">
            {verificationFeedback.valid ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            )}
            <span className="font-mono text-xs">{verificationFeedback.message}</span>
          </div>
          <button
            onClick={() => setVerificationFeedback(null)}
            className="text-slate-400 hover:text-slate-200 text-[11px] underline ml-4"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* SUB-TAB 1: EVIDENCE LOCKER */}
      {activeSubTab === 'EVIDENCE' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search evidence records by ID, tool, or target..."
                className="w-full bg-[#080c14] border border-slate-800 rounded pl-8 pr-2.5 py-1 text-xs text-slate-200 placeholder:text-slate-500"
              />
            </div>

            <span className="text-[11px] font-mono text-slate-400">
              {filteredEvidence.length} sealed evidence records
            </span>
          </div>

          {filteredEvidence.length === 0 ? (
            <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-6 text-center text-xs text-slate-500 font-mono">
              No evidence records sealed yet. Execute security tools against in-scope targets to generate tamper-evident artifacts.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-2">
              {filteredEvidence.map(ev => (
                <div
                  key={ev.evidenceId}
                  className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 font-mono text-xs space-y-2"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-1.5 border-b border-slate-800/80 pb-1.5">
                    <div className="flex items-center space-x-2">
                      <FileCheck className="w-3.5 h-3.5 text-cyan-400" />
                      <span className="font-bold text-slate-100">{ev.evidenceId}</span>
                      <span className="text-slate-500">|</span>
                      <span className="text-slate-300">{ev.toolId}</span>
                      <span className="text-slate-500">|</span>
                      <span className="text-cyan-400">{ev.target}</span>
                    </div>

                    <div className="flex items-center space-x-2 text-[10.5px]">
                      <span className="text-slate-400">{new Date(ev.timestamp).toLocaleString()}</span>
                      <span className="bg-emerald-950/70 border border-emerald-700/50 text-emerald-400 px-1.5 py-0.2 rounded text-[9.5px]">
                        SEALED (SHA-256)
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10.5px]">
                    <div className="bg-[#080c14] border border-slate-800/80 p-1.5 rounded truncate">
                      <span className="text-slate-500 block text-[9.5px]">RAW STDOUT SHA-256 HASH:</span>
                      <span className="text-slate-200 select-all font-mono">{ev.rawStdoutHash}</span>
                    </div>
                    <div className="bg-[#080c14] border border-slate-800/80 p-1.5 rounded truncate">
                      <span className="text-slate-500 block text-[9.5px]">RAW STDERR SHA-256 HASH:</span>
                      <span className="text-slate-200 select-all font-mono">{ev.rawStderrHash}</span>
                    </div>
                  </div>

                  <div className="bg-[#080c14] border border-slate-800/80 p-1.5 rounded truncate text-[10.5px]">
                    <span className="text-slate-500 block text-[9.5px]">CRYPTOGRAPHIC SIGNATURE:</span>
                    <span className="text-cyan-300 select-all font-mono">{ev.cryptographicSignature}</span>
                  </div>

                  <div className="flex items-center justify-between pt-0.5">
                    <span className="text-[10.5px] text-slate-400">
                      Operator: <strong className="text-slate-200">{ev.operatorId}</strong> | Job: {ev.jobId}
                    </span>

                    <button
                      onClick={() => handleVerifyEvidence(ev)}
                      className="flex items-center space-x-1 px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs rounded transition-colors"
                    >
                      <ShieldCheck className="w-3 h-3" />
                      <span>Verify Cryptographic Seal</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 2: AUDIT LEDGER */}
      {activeSubTab === 'AUDIT' && (
        <div className="space-y-3">
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-semibold text-slate-200">Hash-Chained Audit Ledger Status:</span>
                {chainIntegrity.isValid ? (
                  <span className="text-emerald-400 font-mono font-bold flex items-center space-x-1 text-xs">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>INTACT / IMMUTABLE ({chainIntegrity.blocksCount} BLOCKS)</span>
                  </span>
                ) : (
                  <span className="text-red-400 font-mono font-bold flex items-center space-x-1 text-xs">
                    <AlertTriangle className="w-3 h-3" />
                    <span>CHAIN CORRUPTED AT #{chainIntegrity.tamperedIndex}</span>
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Every tool registration, job initiation, HITL authorization, and scope alteration is cryptographically chained to its predecessor.
              </p>
            </div>

            <button
              onClick={handleVerifyChain}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded transition-colors whitespace-nowrap"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Verify Hash Chain Integrity</span>
            </button>
          </div>

          {/* Block Chain Visualizer */}
          <div className="space-y-2 font-mono text-xs">
            {auditBlocks.map((block, idx) => (
              <div
                key={block.index}
                className="bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-1.5 relative"
              >
                <div className="flex items-center justify-between border-b border-slate-800/70 pb-1.5">
                  <div className="flex items-center space-x-2">
                    <span className="bg-cyan-950/80 border border-cyan-700/60 text-cyan-300 px-1.5 py-0.2 rounded font-bold text-[10.5px]">
                      BLOCK #{block.index}
                    </span>
                    <span className="font-bold text-slate-100">{block.action}</span>
                    <span className="text-slate-500">|</span>
                    <span className="text-slate-400">Actor: {block.actor}</span>
                  </div>

                  <span className="text-[10.5px] text-slate-400">{new Date(block.timestamp).toLocaleString()}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 text-[10.5px]">
                  <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded truncate">
                    <span className="text-slate-500 block text-[9.5px]">PREVIOUS BLOCK HASH:</span>
                    <span className="text-slate-400 font-mono">{block.prevHash}</span>
                  </div>
                  <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded truncate">
                    <span className="text-slate-500 block text-[9.5px]">CURRENT BLOCK SHA-256:</span>
                    <span className="text-emerald-400 font-mono">{block.hash}</span>
                  </div>
                </div>

                <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded text-[10.5px] text-slate-400 overflow-x-auto">
                  <span className="text-slate-500 block text-[9.5px]">BLOCK METADATA PAYLOAD:</span>
                  <pre className="mt-0.5 text-slate-300">{JSON.stringify(block.details, null, 2)}</pre>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
