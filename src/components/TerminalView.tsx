/**
 * AWM Nexus — Unified Real Linux Pentest Terminal & Central Execution Workspace
 * THE primary execution engine and operator console of the entire platform.
 * Supports live process streaming, PID/stopwatch tracking, ASCL interactive CLI,
 * real binary execution (WHOIS, Nmap, WhatWeb, FFUF, Gobuster, etc.), and evidence sealing.
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Send,
  Trash2,
  Copy,
  Check,
  ChevronRight,
  Play,
  Square,
  Download,
  Activity,
  Cpu,
  Clock,
  Shield,
  Layers,
  ArrowRight,
  RefreshCw,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileText
} from 'lucide-react';
import { asclEngine } from '../engine/asclEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { toolRegistry } from '../engine/toolRegistry';
import { scopeEngine } from '../engine/scopeEngine';
import { PentestJob } from '../types';

interface LogEntry {
  id: string;
  type: 'COMMAND' | 'OUTPUT' | 'ERROR' | 'SUCCESS' | 'WARNING' | 'INFO';
  content: string;
  timestamp: string;
}

interface TerminalViewProps {
  initialJobId?: string;
}

export const TerminalView: React.FC<TerminalViewProps> = ({ initialJobId }) => {
  const [viewMode, setViewMode] = useState<'STREAM' | 'CLI'>('STREAM');
  const [allJobs, setAllJobs] = useState<PentestJob[]>(sandboxExecutionManager.getAllJobs());
  const [selectedJobId, setSelectedJobId] = useState<string>(
    initialJobId || sandboxExecutionManager.getAllJobs()[0]?.jobId || ''
  );

  // Live Stream State
  const [activeJob, setActiveJob] = useState<PentestJob | null>(
    sandboxExecutionManager.getJob(selectedJobId) || null
  );
  const [elapsedTimeMs, setElapsedTimeMs] = useState<number>(0);
  const [copied, setCopied] = useState<boolean>(false);
  const [autoScroll, setAutoScroll] = useState<boolean>(true);

  // ASCL CLI State
  const [input, setInput] = useState('');
  const [cliLogs, setCliLogs] = useState<LogEntry[]>([
    {
      id: 'init-1',
      type: 'INFO',
      content: `AWM NEXUS — REAL LINUX PENTEST CONSOLE (ASCL v4.8.2)
Real Linux Execution Engine: LOCAL_LINUX_WORKER [Debian 12 gVisor x86_64].
All executions spawn authentic installed binaries. Type 'help' for command manual.`,
      timestamp: new Date().toLocaleTimeString()
    },
    {
      id: 'init-2',
      type: 'SUCCESS',
      content: `[+] Scope RoE Engine Active: ENG-2026-ALPHA | Tenant: TENANT-AWM-01\n[+] Persistent Binary Storage: /app/applet/bin (whois, nmap, whatweb, ffuf, gobuster, feroxbuster ready)`,
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number>(-1);

  const terminalOutputRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const cliInputRef = useRef<HTMLInputElement>(null);

  // Poll active jobs & output
  useEffect(() => {
    const syncJobs = () => {
      const jobs = sandboxExecutionManager.getAllJobs();
      setAllJobs([...jobs]);

      if (selectedJobId) {
        const cur = sandboxExecutionManager.getJob(selectedJobId);
        if (cur) {
          setActiveJob({ ...cur });
          if (cur.status === 'RUNNING') {
            const start = new Date(cur.startTime).getTime();
            setElapsedTimeMs(Date.now() - start);
          } else if (cur.executionTimeMs) {
            setElapsedTimeMs(cur.executionTimeMs);
          }
        }
      } else if (jobs.length > 0) {
        setSelectedJobId(jobs[0].jobId);
        setActiveJob(jobs[0]);
      }
    };

    syncJobs();
    const timer = setInterval(syncJobs, 250);
    return () => clearInterval(timer);
  }, [selectedJobId]);

  // Auto-scroll terminal output
  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [activeJob?.stdout, activeJob?.stderr, cliLogs, autoScroll]);

  const handleSelectJob = (jobId: string) => {
    setSelectedJobId(jobId);
    const j = sandboxExecutionManager.getJob(jobId);
    if (j) setActiveJob({ ...j });
    setViewMode('STREAM');
  };

  const handleCancelRunningJob = () => {
    if (!activeJob) return;
    sandboxExecutionManager.cancelJob(activeJob.jobId, 'operator-human-01');
    setActiveJob(prev => (prev ? { ...prev, status: 'CANCELLED' } : null));
  };

  const handleCopyOutput = () => {
    if (!activeJob) return;
    const full = `${activeJob.stdout}\n${activeJob.stderr}`;
    navigator.clipboard.writeText(full);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadLog = () => {
    if (!activeJob) return;
    const full = `${activeJob.stdout}\n${activeJob.stderr}`;
    const blob = new Blob([full], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeJob.toolId}-${activeJob.jobId}-terminal.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Quick execution triggers for acceptance testing
  const handleTriggerQuickScan = (toolName: string, target: string, defaultFlags: string[]) => {
    const engagement = scopeEngine.getAllEngagements()[0];
    const tool = toolRegistry.getAllTools().find(t => t.binaryName === toolName || t.id.includes(toolName));

    if (!tool) {
      alert(`Tool '${toolName}' not found in registry.`);
      return;
    }

    const res = sandboxExecutionManager.createJob(
      'TENANT-AWM-01',
      engagement?.id || 'eng-2026-001',
      'operator-human-01',
      tool.id,
      target,
      tool.profiles[0]?.id || 'default',
      defaultFlags,
      'LIVE'
    );

    if (res.job) {
      setSelectedJobId(res.job.jobId);
      setActiveJob(res.job);
      setViewMode('STREAM');
      sandboxExecutionManager.executeJob(res.job.jobId);
    } else if (res.error) {
      alert(`Execution Error: ${res.error}`);
    }
  };

  // CLI Command Execution
  const handleCliSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const commandText = input.trim();
    if (!commandText) return;

    setHistory(prev => [commandText, ...prev.filter(h => h !== commandText)]);
    setHistoryIndex(-1);
    setInput('');

    const time = new Date().toLocaleTimeString();

    if (commandText.toLowerCase() === 'clear') {
      setCliLogs([]);
      return;
    }

    setCliLogs(prev => [
      ...prev,
      { id: `cmd-${Date.now()}`, type: 'COMMAND', content: commandText, timestamp: time }
    ]);

    const result = await asclEngine.execute(commandText);

    if (result.output === '__CLEAR__') {
      setCliLogs([]);
      return;
    }

    setCliLogs(prev => [
      ...prev,
      { id: `res-${Date.now()}`, type: result.type, content: result.output, timestamp: new Date().toLocaleTimeString() }
    ]);
  };

  return (
    <div className="space-y-3 font-mono text-xs select-none">
      {/* Top Banner: Central Real Linux Execution Engine */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-emerald-950/70 border border-emerald-600/50 rounded-lg text-emerald-400">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <span>Unified Real Linux Pentest Terminal</span>
              <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800/80 px-2 py-0.5 rounded font-bold">
                NATIVE EXECUTION ENGINE
              </span>
            </h2>
            <p className="text-[11px] text-slate-400">
              Primary operational console. Executes authentic binaries (WHOIS, Nmap, WhatWeb, FFUF, Gobuster) under Debian 12 Linux.
            </p>
          </div>
        </div>

        {/* Mode Switcher & Quick Launchers */}
        <div className="flex items-center space-x-2 shrink-0">
          <div className="flex items-center space-x-1 bg-slate-900 border border-slate-800 p-0.5 rounded-md text-xs">
            <button
              onClick={() => setViewMode('STREAM')}
              className={`px-3 py-1 rounded transition-colors flex items-center space-x-1.5 ${
                viewMode === 'STREAM' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Process Stream</span>
              {activeJob?.status === 'RUNNING' && (
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping ml-1" />
              )}
            </button>
            <button
              onClick={() => {
                setViewMode('CLI');
                setTimeout(() => cliInputRef.current?.focus(), 50);
              }}
              className={`px-3 py-1 rounded transition-colors flex items-center space-x-1.5 ${
                viewMode === 'CLI' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>ASCL Shell</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Terminal Grid: 3 Cols Job Selector + 9 Cols Real Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
        {/* Left Column: Executed Jobs Queue (3 Cols) */}
        <div className="lg:col-span-3 bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2.5">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider font-bold border-b border-slate-800/80 pb-2">
            <span>Execution Jobs ({allJobs.length})</span>
            <button
              onClick={() => setAllJobs([...sandboxExecutionManager.getAllJobs()])}
              className="hover:text-slate-200"
              title="Refresh Queue"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Quick Pre-Configured Test Execution Triggers */}
          <div className="bg-[#080c14] border border-slate-800/80 rounded p-2 space-y-1.5">
            <span className="text-[10px] text-slate-400 uppercase block font-semibold">Quick Verification Triggers:</span>
            <div className="grid grid-cols-1 gap-1">
              <button
                onClick={() => handleTriggerQuickScan('whois', 'example.com', [])}
                className="w-full text-left px-2 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700/60 rounded text-[11px] text-cyan-300 flex items-center justify-between"
              >
                <span>whois example.com</span>
                <Play className="w-3 h-3 text-emerald-400" />
              </button>
              <button
                onClick={() => handleTriggerQuickScan('nmap', '127.0.0.1', ['--unprivileged', '-sT', '-p', '3000,80,443'])}
                className="w-full text-left px-2 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700/60 rounded text-[11px] text-cyan-300 flex items-center justify-between"
              >
                <span>nmap -sT 127.0.0.1</span>
                <Play className="w-3 h-3 text-emerald-400" />
              </button>
              <button
                onClick={() => handleTriggerQuickScan('whatweb', 'http://127.0.0.1:3000', ['-v', '--color=never'])}
                className="w-full text-left px-2 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700/60 rounded text-[11px] text-cyan-300 flex items-center justify-between"
              >
                <span>whatweb localhost:3000</span>
                <Play className="w-3 h-3 text-emerald-400" />
              </button>
            </div>
          </div>

          <div className="space-y-1 max-h-[500px] overflow-y-auto pr-1">
            {allJobs.length === 0 ? (
              <div className="p-6 text-center text-slate-500 text-[11px]">
                No jobs executed yet. Launch a tool from Tool Catalog, Command Preview, or Quick Triggers above.
              </div>
            ) : (
              allJobs.map(j => {
                const isSelected = selectedJobId === j.jobId;
                return (
                  <div
                    key={j.jobId}
                    onClick={() => handleSelectJob(j.jobId)}
                    className={`p-2 rounded border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-slate-800/90 border-cyan-500/60 text-white shadow-sm'
                        : 'bg-[#080c14] border-slate-800/80 text-slate-300 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="font-bold text-xs truncate max-w-[120px] text-cyan-300">
                        {j.toolName || j.toolId}
                      </span>
                      <span
                        className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                          j.status === 'RUNNING'
                            ? 'bg-cyan-950 text-cyan-400 border border-cyan-700 animate-pulse'
                            : j.status === 'COMPLETED'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : j.status === 'CANCELLED'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {j.status}
                      </span>
                    </div>

                    <div className="text-[10px] text-slate-400 truncate font-mono">
                      Target: {j.target}
                    </div>

                    <div className="text-[9.5px] text-slate-500 flex justify-between mt-1">
                      <span>ID: {j.jobId.slice(-6)}</span>
                      <span>{j.provenance || 'LOCAL'}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Active Terminal Execution View (9 Cols) */}
        <div className="lg:col-span-9 bg-[#0b0f19] border border-slate-800 rounded-lg flex flex-col min-h-[580px]">
          {viewMode === 'STREAM' ? (
            activeJob ? (
              <>
                {/* Active Process Execution Header HUD */}
                <div className="bg-[#0e1422] border-b border-slate-800 px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                  <div className="flex items-center space-x-3">
                    <span
                      className={`w-2.5 h-2.5 rounded-full ${
                        activeJob.status === 'RUNNING'
                          ? 'bg-cyan-400 animate-pulse'
                          : activeJob.status === 'COMPLETED'
                          ? 'bg-emerald-400'
                          : activeJob.status === 'CANCELLED'
                          ? 'bg-amber-400'
                          : 'bg-red-400'
                      }`}
                    />
                    <div>
                      <div className="font-bold text-slate-100 flex items-center space-x-2">
                        <span>{activeJob.toolName} ({activeJob.toolId})</span>
                        <span className="text-[10px] bg-slate-900 border border-slate-700 px-1.5 py-0.2 rounded text-slate-300">
                          ID: {activeJob.jobId}
                        </span>
                      </div>
                      <div className="text-[10.5px] text-slate-400 font-mono">
                        Target: <span className="text-cyan-400">{activeJob.target}</span> • Worker: <span className="text-emerald-400">LOCAL_LINUX_WORKER [Debian 12 gVisor]</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    {/* Execution Stopwatch & Exit Code */}
                    <div className="bg-[#080c14] border border-slate-800 px-2.5 py-1 rounded text-[11px] flex items-center space-x-2">
                      <div className="flex items-center space-x-1 text-slate-300">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{(elapsedTimeMs / 1000).toFixed(2)}s</span>
                      </div>
                      <span className="text-slate-600">|</span>
                      <div className="text-slate-300">
                        Exit:{' '}
                        <strong className={activeJob.exitCode === 0 ? 'text-emerald-400' : 'text-red-400'}>
                          {activeJob.exitCode !== undefined ? activeJob.exitCode : (activeJob.status === 'RUNNING' ? 'RUN' : '?')}
                        </strong>
                      </div>
                    </div>

                    {/* Action Controls */}
                    {activeJob.status === 'RUNNING' && (
                      <button
                        onClick={handleCancelRunningJob}
                        className="flex items-center space-x-1 px-2.5 py-1 bg-red-950/80 hover:bg-red-900 border border-red-700 text-red-300 rounded font-semibold text-[11px] transition-colors"
                        title="Cancel running process (SIGTERM)"
                      >
                        <Square className="w-3 h-3" />
                        <span>Abort</span>
                      </button>
                    )}

                    <button
                      onClick={handleCopyOutput}
                      className="p-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded"
                      title="Copy full output to clipboard"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>

                    <button
                      onClick={handleDownloadLog}
                      className="p-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded"
                      title="Download raw execution log (.log)"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Command Bar */}
                <div className="bg-[#070a12] border-b border-slate-900 px-4 py-1.5 text-[11px] text-slate-400 font-mono flex items-center space-x-2">
                  <span className="text-emerald-400 font-bold">$</span>
                  <span className="text-slate-200 select-all truncate">
                    {(() => {
                      const tool = toolRegistry.getTool(activeJob.toolId);
                      const binary = tool?.binaryName || activeJob.toolId.replace(/-.*/, '');
                      const paramsStr = activeJob.parameters.join(' ');
                      const alreadyHasTarget = activeJob.parameters.includes(activeJob.target) || paramsStr.endsWith(activeJob.target);
                      return `${binary} ${paramsStr}${alreadyHasTarget ? '' : ' ' + activeJob.target}`;
                    })()}
                  </span>
                </div>

                {/* Live Output Terminal Screen */}
                <div
                  ref={terminalOutputRef}
                  className="flex-1 bg-[#050811] p-4 text-xs font-mono text-slate-200 overflow-y-auto leading-relaxed select-text space-y-1 max-h-[500px]"
                >
                  <pre className="whitespace-pre-wrap break-all font-mono text-[11.5px] text-cyan-200/90 leading-5">
                    {activeJob.stdout || ''}
                  </pre>
                  {activeJob.stderr && (
                    <pre className="whitespace-pre-wrap break-all font-mono text-[11.5px] text-red-400 leading-5 mt-2">
                      {activeJob.stderr}
                    </pre>
                  )}
                  {activeJob.status === 'RUNNING' && (
                    <div className="flex items-center space-x-2 text-cyan-400 pt-2 animate-pulse text-[11px]">
                      <span className="w-2 h-2 rounded-full bg-cyan-400" />
                      <span>Process active... streaming output from Linux worker...</span>
                    </div>
                  )}
                  <div ref={bottomRef} />
                </div>

                {/* Evidence & Hash Bar */}
                <div className="bg-[#080c14] border-t border-slate-800/80 px-4 py-1.5 text-[10px] text-slate-400 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center space-x-3">
                    <span>
                      Evidence ID: <strong className="text-cyan-400">{activeJob.evidenceId || 'PENDING'}</strong>
                    </span>
                    <span>
                      Findings Discovered: <strong className="text-emerald-400">{activeJob.findings.length}</strong>
                    </span>
                  </div>
                  <div>
                    Audit Hash:{' '}
                    <code className="text-slate-500">
                      {activeJob.auditBlockId ? activeJob.auditBlockId.slice(0, 18) + '...' : 'SEALED ON COMPLETION'}
                    </code>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500 space-y-2">
                <Terminal className="w-8 h-8 text-slate-600" />
                <div className="text-sm font-bold text-slate-300">No Execution Job Selected</div>
                <p className="text-xs max-w-md">
                  Select a job from the queue on the left, or launch an authorized tool scan from the Tool Catalog.
                </p>
              </div>
            )
          ) : (
            /* ASCL CLI Interactive Mode */
            <div className="flex-1 flex flex-col">
              <div className="bg-[#0e1422] border-b border-slate-800 px-4 py-2 flex items-center justify-between text-xs">
                <span className="font-bold text-slate-200 flex items-center space-x-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>ASCL Command Shell (Interactive REPL)</span>
                </span>
                <button
                  onClick={() => setCliLogs([])}
                  className="p-1 hover:text-white text-slate-400"
                  title="Clear CLI Screen"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="flex-1 bg-[#050811] p-4 text-xs font-mono overflow-y-auto space-y-2 max-h-[500px]">
                {cliLogs.map(log => (
                  <div key={log.id} className="space-y-0.5">
                    {log.type === 'COMMAND' ? (
                      <div className="flex items-center space-x-2 text-cyan-400 font-bold">
                        <span className="text-emerald-400">ascl&gt;</span>
                        <span>{log.content}</span>
                        <span className="text-[9px] text-slate-600 font-normal ml-auto">{log.timestamp}</span>
                      </div>
                    ) : (
                      <div
                        className={`whitespace-pre-wrap break-all text-[11.5px] leading-relaxed p-1.5 rounded ${
                          log.type === 'SUCCESS'
                            ? 'text-emerald-300 bg-emerald-950/20'
                            : log.type === 'ERROR'
                            ? 'text-red-300 bg-red-950/20'
                            : log.type === 'WARNING'
                            ? 'text-amber-300 bg-amber-950/20'
                            : 'text-slate-300'
                        }`}
                      >
                        {log.content}
                      </div>
                    )}
                  </div>
                ))}
                <div ref={bottomRef} />
              </div>

              {/* Input Form */}
              <form onSubmit={handleCliSubmit} className="bg-[#0a0e1a] border-t border-slate-800 p-2 flex items-center space-x-2">
                <span className="text-emerald-400 font-bold text-xs pl-2">ascl&gt;</span>
                <input
                  ref={cliInputRef}
                  type="text"
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  placeholder="tools list | run nmap-recon 127.0.0.1 | whois example.com | audit verify | help"
                  className="flex-1 bg-transparent border-0 text-slate-100 text-xs focus:outline-none font-mono placeholder:text-slate-600"
                />
                <button
                  type="submit"
                  className="p-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-bold"
                >
                  <Send className="w-3 h-3" />
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
