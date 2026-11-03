import React, { useState, useEffect } from 'react';
import {
  Activity,
  CheckCircle2,
  XCircle,
  Clock,
  AlertTriangle,
  StopCircle,
  FileText,
  Database,
  Terminal,
  Shield,
  RefreshCw,
  Search,
  ExternalLink
} from 'lucide-react';
import { PentestJob } from '../types';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { toolRegistry } from '../engine/toolRegistry';

export const JobsMonitorView: React.FC = () => {
  const [jobs, setJobs] = useState<PentestJob[]>(sandboxExecutionManager.getAllJobs());
  const [selectedJob, setSelectedJob] = useState<PentestJob | null>(jobs[0] || null);
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    const interval = setInterval(() => {
      const all = sandboxExecutionManager.getAllJobs();
      setJobs(all);
      if (selectedJob) {
        const updated = all.find(j => j.jobId === selectedJob.jobId);
        if (updated) setSelectedJob(updated);
      }
    }, 1500);
    return () => clearInterval(interval);
  }, [selectedJob]);

  const handleCancel = (jobId: string) => {
    sandboxExecutionManager.cancelJob(jobId, 'operator-human-01');
    setJobs([...sandboxExecutionManager.getAllJobs()]);
  };

  const getStatusBadge = (status: PentestJob['status']) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="bg-emerald-950/70 border border-emerald-700/50 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1">
            <CheckCircle2 className="w-2.5 h-2.5 inline" />
            <span>COMPLETED</span>
          </span>
        );
      case 'RUNNING':
        return (
          <span className="bg-cyan-950/70 border border-cyan-700/50 text-cyan-300 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1 animate-pulse">
            <RefreshCw className="w-2.5 h-2.5 inline animate-spin" />
            <span>RUNNING</span>
          </span>
        );
      case 'APPROVAL_REQUIRED':
        return (
          <span className="bg-amber-950/70 border border-amber-700/50 text-amber-300 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1">
            <AlertTriangle className="w-2.5 h-2.5 inline" />
            <span>APPROVAL REQUIRED</span>
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="bg-slate-900 border border-slate-700 text-slate-400 text-[10px] font-mono px-2 py-0.5 rounded">
            CANCELLED
          </span>
        );
      case 'FAILED':
      case 'BLOCKED':
        return (
          <span className="bg-red-950/70 border border-red-700/50 text-red-400 text-[10px] font-mono px-2 py-0.5 rounded flex items-center space-x-1">
            <XCircle className="w-2.5 h-2.5 inline" />
            <span>{status}</span>
          </span>
        );
      default:
        return (
          <span className="bg-slate-900 text-slate-400 text-[10px] font-mono px-2 py-0.5 rounded">
            {status}
          </span>
        );
    }
  };

  const getProvenanceBadge = (job: PentestJob) => {
    switch (job.provenance) {
      case 'LIVE_LOCAL':
        return (
          <span className="bg-emerald-950/80 border border-emerald-600/50 text-emerald-300 text-[9.5px] font-mono px-1.5 py-0.5 rounded flex items-center space-x-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span>LIVE (Local)</span>
          </span>
        );
      case 'LIVE_AGENT':
        return (
          <span className="bg-cyan-950/80 border border-cyan-600/50 text-cyan-300 text-[9.5px] font-mono px-1.5 py-0.5 rounded flex items-center space-x-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
            <span>LIVE (Kali Agent)</span>
          </span>
        );
      case 'UNAVAILABLE':
        return (
          <span className="bg-red-950/80 border border-red-700/50 text-red-400 text-[9.5px] font-mono px-1.5 py-0.5 rounded">
            UNAVAILABLE
          </span>
        );
      case 'SIMULATED':
        return (
          <span className="bg-amber-950/80 border border-amber-700/50 text-amber-300 text-[9.5px] font-mono px-1.5 py-0.5 rounded">
            SIMULATED
          </span>
        );
      default:
        return (
          <span className="bg-slate-900 text-slate-400 text-[9.5px] font-mono px-1.5 py-0.5 rounded">
            {job.mode}
          </span>
        );
    }
  };

  const filteredJobs = jobs.filter(j => {
    const matchStatus = filterStatus === 'ALL' || j.status === filterStatus;
    const matchSearch =
      !searchQuery ||
      j.jobId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      j.toolName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      j.target.toLowerCase().includes(searchQuery.toLowerCase());
    return matchStatus && matchSearch;
  });

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 h-[calc(100vh-115px)]">
      {/* Jobs List Panel (5 cols) */}
      <div className="lg:col-span-5 flex flex-col bg-[#0e1422] border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-3.5 border-b border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Pentest Execution Pipeline</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">{jobs.length} jobs</span>
          </div>

          <div className="flex items-center space-x-2">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Filter jobs..."
                className="w-full bg-[#080c14] border border-slate-800 rounded pl-8 pr-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
              />
            </div>
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
              className="bg-[#080c14] border border-slate-800 rounded px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">All Status</option>
              <option value="RUNNING">RUNNING</option>
              <option value="COMPLETED">COMPLETED</option>
              <option value="APPROVAL_REQUIRED">APPROVAL_REQUIRED</option>
              <option value="CANCELLED">CANCELLED</option>
              <option value="FAILED">FAILED</option>
            </select>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60">
          {filteredJobs.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 font-mono">
              No pentest jobs match the selected filter.
            </div>
          ) : (
            filteredJobs.map(job => (
              <div
                key={job.jobId}
                onClick={() => setSelectedJob(job)}
                className={`p-3 cursor-pointer transition-all ${
                  selectedJob?.jobId === job.jobId
                    ? 'bg-slate-800/80 border-l-2 border-cyan-400'
                    : 'hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono font-bold text-slate-200">{job.jobId}</span>
                  <div className="flex items-center space-x-1.5">
                    {getProvenanceBadge(job)}
                    {getStatusBadge(job.status)}
                  </div>
                </div>

                <div className="text-xs text-slate-300 font-semibold truncate">{job.toolName}</div>
                <div className="text-xs font-mono text-cyan-400 truncate mt-0.5">Target: {job.target}</div>

                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 mt-2">
                  <span>{job.startTime.slice(11, 19)}</span>
                  <span>{job.findings.length} findings</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Job Details Inspector (7 cols) */}
      <div className="lg:col-span-7 flex flex-col bg-[#0b0f17] border border-slate-800 rounded-lg overflow-hidden font-mono">
        {selectedJob ? (
          <div className="flex flex-col h-full">
            {/* Header */}
            <div className="px-4 py-3 bg-[#0e1422] border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-2.5">
                  <span className="text-sm font-bold text-slate-100">{selectedJob.jobId}</span>
                  {getStatusBadge(selectedJob.status)}
                  {getProvenanceBadge(selectedJob)}
                </div>
                <div className="text-xs text-slate-400 mt-1 font-sans">
                  Tool: <strong className="text-slate-200">{selectedJob.toolName}</strong> ({selectedJob.toolId})
                  {selectedJob.agentName && (
                    <span className="text-cyan-400 ml-2">via Agent: {selectedJob.agentName}</span>
                  )}
                </div>
              </div>

              {selectedJob.status === 'RUNNING' && (
                <button
                  onClick={() => handleCancel(selectedJob.jobId)}
                  className="flex items-center space-x-1.5 bg-red-950/80 hover:bg-red-900/80 border border-red-700/50 text-red-300 text-xs px-3 py-1.5 rounded transition-colors font-sans font-medium"
                >
                  <StopCircle className="w-3.5 h-3.5" />
                  <span>Abort Process</span>
                </button>
              )}
            </div>

            {/* Scrollable details */}
            <div className="flex-1 p-4 overflow-y-auto space-y-4 text-xs">
              {/* Parameters & Environment */}
              <div className="space-y-1.5">
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Execution Invocation</span>
                <div className="bg-[#070a10] border border-slate-800 p-2.5 rounded text-cyan-300 text-xs break-all">
                  {(() => {
                    const tool = toolRegistry.getTool(selectedJob.toolId);
                    const binary = tool?.binaryName || selectedJob.toolId;
                    const paramsStr = selectedJob.parameters.join(' ');
                    const alreadyHasTarget = selectedJob.parameters.includes(selectedJob.target) || paramsStr.endsWith(selectedJob.target);
                    return `${binary} ${paramsStr}${alreadyHasTarget ? '' : ' ' + selectedJob.target}`;
                  })()}
                </div>
              </div>

              {/* Integrity & Metadata Row */}
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="bg-[#090d16] border border-slate-800/80 p-2.5 rounded">
                  <span className="text-slate-500 text-[10px] block">EVIDENCE LOCKER ID:</span>
                  <span className="text-emerald-400 font-semibold truncate block mt-0.5">
                    {selectedJob.evidenceId || 'Pending Sealing'}
                  </span>
                </div>
                <div className="bg-[#090d16] border border-slate-800/80 p-2.5 rounded">
                  <span className="text-slate-500 text-[10px] block">AUDIT BLOCK HASH:</span>
                  <span className="text-cyan-400 font-semibold truncate block mt-0.5">
                    {selectedJob.auditBlockId ? selectedJob.auditBlockId.slice(0, 16) + '...' : 'Pending Ledger'}
                  </span>
                </div>
              </div>

              {/* STDOUT Stream */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Process STDOUT Stream</span>
                  <span className="text-[11px] text-slate-500">Exit Code: {selectedJob.exitCode !== undefined ? selectedJob.exitCode : 'Running'}</span>
                </div>
                <div className="bg-[#070a10] border border-slate-800/90 rounded p-3 text-slate-200 text-xs max-h-56 overflow-y-auto font-mono">
                  <pre className="whitespace-pre-wrap leading-relaxed">{selectedJob.stdout || '(stdout stream empty)'}</pre>
                </div>
              </div>

              {/* STDERR Stream (if any) */}
              {selectedJob.stderr && (
                <div className="space-y-1.5">
                  <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">Process STDERR Stream</span>
                  <div className="bg-red-950/20 border border-red-900/40 rounded p-3 text-red-300 text-xs max-h-40 overflow-y-auto font-mono">
                    <pre className="whitespace-pre-wrap leading-relaxed">{selectedJob.stderr}</pre>
                  </div>
                </div>
              )}

              {/* Normalized Findings Discovered */}
              <div className="space-y-2">
                <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                  Normalized Findings Discovered ({selectedJob.findings.length})
                </span>
                {selectedJob.findings.length === 0 ? (
                  <div className="bg-[#090d16] border border-slate-800/80 p-3 rounded text-slate-500 text-center text-xs">
                    No vulnerability findings discovered by this tool execution.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {selectedJob.findings.map(f => (
                      <div key={f.findingId} className="bg-[#090d16] border border-slate-800 p-3 rounded space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-100 text-xs">{f.title}</span>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                              f.severity === 'CRITICAL'
                                ? 'bg-red-950 text-red-300 border border-red-700'
                                : f.severity === 'HIGH'
                                ? 'bg-amber-950 text-amber-300 border border-amber-700'
                                : 'bg-slate-900 text-slate-300 border border-slate-700'
                            }`}
                          >
                            {f.severity} (CVSS: {f.cvssScore})
                          </span>
                        </div>
                        <p className="text-slate-400 text-xs font-sans leading-relaxed">{f.description}</p>
                        {f.cwe && <div className="text-[10px] text-cyan-400">{f.cwe} | {f.owaspCategory}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-slate-500 text-xs">
            Select a job from the pipeline to inspect execution logs and findings.
          </div>
        )}
      </div>
    </div>
  );
};
