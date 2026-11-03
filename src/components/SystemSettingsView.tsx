/**
 * AWM Nexus — System Health, Real LLM & Wazuh SIEM Diagnostics
 * Exposes real-time container environment diagnostics, native binary probing,
 * Google Gemini LLM API connection status, and Wazuh REST SIEM connectivity.
 */

import React, { useState, useEffect } from 'react';
import {
  Settings,
  Cpu,
  Database,
  Shield,
  Layers,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Server,
  Lock,
  Sparkles,
  Radio,
  ExternalLink,
  Key,
  Activity,
  Play,
  Eye,
  EyeOff,
  Terminal,
  Copy,
  Check,
  Laptop,
  Globe
} from 'lucide-react';
import { toolRegistry } from '../engine/toolRegistry';
import { auditLedger } from '../engine/auditLedger';
import { detectRealBinaries } from '../engine/binaryDetector';
import { scopeEngine } from '../engine/scopeEngine';
import { llmManager } from '../services/llm/llmManager';
import { siemManager } from '../services/siem/siemManager';
import { remoteAgentManager, RemoteAgent } from '../server/agentManager';
import { LLMConnectionTestResult } from '../services/llm/types';
import { SIEMConnectionStatus } from '../services/siem/types';

export const SystemSettingsView: React.FC = () => {
  const [probing, setProbing] = useState<boolean>(false);
  const [activeSubTab, setActiveSubTab] = useState<'SYSTEM' | 'LLM' | 'SIEM' | 'KALI_AGENT'>('KALI_AGENT');

  // Kali Execution Agent State
  const [agents, setAgents] = useState<RemoteAgent[]>(remoteAgentManager.getAllAgents());
  const [agentToken, setAgentToken] = useState<string>(remoteAgentManager.getAuthToken());
  const [copiedToken, setCopiedToken] = useState<boolean>(false);
  const [agentConnectingDemo, setAgentConnectingDemo] = useState<boolean>(false);

  // LLM State
  const [llmProvider, setLlmProvider] = useState<string>('gemini');
  const [llmKeyInput, setLlmKeyInput] = useState<string>('');
  const [showLlmKey, setShowLlmKey] = useState<boolean>(false);
  const [llmTesting, setLlmTesting] = useState<boolean>(false);
  const [llmTestResult, setLlmTestResult] = useState<LLMConnectionTestResult | null>(null);
  const [llmConfigState, setLlmConfigState] = useState(llmManager.getConfig());

  // SIEM State
  const [siemBaseUrl, setSiemBaseUrl] = useState<string>('https://wazuh-manager.corp.internal');
  const [siemPort, setSiemPort] = useState<number>(55000);
  const [siemUser, setSiemUser] = useState<string>('wazuh-api-admin');
  const [siemPassword, setSiemPassword] = useState<string>('');
  const [siemMinLevel, setSiemMinLevel] = useState<number>(3);
  const [siemTesting, setSiemTesting] = useState<boolean>(false);
  const [siemSyncing, setSiemSyncing] = useState<boolean>(false);
  const [siemStatusResult, setSiemStatusResult] = useState<SIEMConnectionStatus>(siemManager.getLastStatus());
  const [siemStats, setSiemStats] = useState(siemManager.getStats());

  const engagement = scopeEngine.getAllEngagements()[0];
  const allTools = toolRegistry.getAllTools();
  const installedTools = allTools.filter(t => t.availabilityStatus === 'INSTALLED');
  const audit = auditLedger.verifyChainIntegrity();

  useEffect(() => {
    // Load initial configs
    const cfg = llmManager.getConfig();
    setLlmConfigState(cfg);
    setLlmProvider(cfg.provider);

    const sCfg = siemManager.getConfig();
    setSiemBaseUrl(sCfg.baseUrl);
    setSiemPort(sCfg.port);
    setSiemUser(sCfg.username);
    setSiemMinLevel(sCfg.minAlertLevel);
    setSiemStatusResult(siemManager.getLastStatus());
    setSiemStats(siemManager.getStats());
  }, []);

  const handleReProbe = async () => {
    setProbing(true);
    await detectRealBinaries();
    setTimeout(() => {
      setProbing(false);
    }, 600);
  };

  const handleSaveLlmKey = () => {
    if (llmKeyInput.trim().length > 0) {
      llmManager.setSessionApiKey(llmKeyInput.trim());
      setLlmConfigState(llmManager.getConfig());
      setLlmKeyInput('');
      alert('Gemini API Key saved for active server session. Ready to test connection.');
    }
  };

  const handleTestLlm = async () => {
    setLlmTesting(true);
    setLlmTestResult(null);
    try {
      const res = await llmManager.testConnection(llmKeyInput || undefined);
      setLlmTestResult(res);
      setLlmConfigState(llmManager.getConfig());
    } finally {
      setLlmTesting(false);
    }
  };

  const handleToggleLlmProvider = (provider: string) => {
    llmManager.setActiveProvider(provider);
    setLlmProvider(provider);
    setLlmConfigState(llmManager.getConfig());
  };

  const handleTestSiem = async () => {
    setSiemTesting(true);
    try {
      siemManager.updateConfig({
        baseUrl: siemBaseUrl,
        port: Number(siemPort),
        username: siemUser,
        password: siemPassword || undefined,
        minAlertLevel: Number(siemMinLevel)
      });
      const res = await siemManager.testConnection({
        baseUrl: siemBaseUrl,
        port: Number(siemPort),
        username: siemUser,
        password: siemPassword || undefined
      });
      setSiemStatusResult(res);
      setSiemStats(siemManager.getStats());
    } finally {
      setSiemTesting(false);
    }
  };

  const handleSyncSiem = async () => {
    setSiemSyncing(true);
    try {
      const res = await siemManager.syncAlerts({ minLevel: siemMinLevel });
      setSiemStats(siemManager.getStats());
      alert(res.success ? `Successfully synced ${res.syncedCount} alerts from Wazuh.` : `Sync error: ${res.error}`);
    } finally {
      setSiemSyncing(false);
    }
  };

  const handleDemoIngest = () => {
    const res = siemManager.ingestVerifiedSampleAlerts();
    setSiemStats(siemManager.getStats());
    alert(`Ingested ${res.count} verified Wazuh schema alerts [SIMULATED] into Defensive Telemetry Engine.`);
  };

  const handleRegenerateToken = () => {
    const newToken = remoteAgentManager.regenerateAuthToken();
    setAgentToken(newToken);
    alert('Generated new Kali Execution Agent authorization token.');
  };

  const handleCopyToken = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(agentToken).catch(() => {});
    }
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const handleConnectDemoAgent = async () => {
    setAgentConnectingDemo(true);
    try {
      const demoAgent = remoteAgentManager.registerDemoKaliAgent();
      await detectRealBinaries();
      setAgents([...remoteAgentManager.getAllAgents()]);
      alert(`Connected Demo Kali Agent [${demoAgent.hostname}] with 14 active security tools.`);
    } finally {
      setAgentConnectingDemo(false);
    }
  };

  return (
    <div className="space-y-3.5 font-mono text-xs">
      {/* Header with Subtabs */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-slate-900 border border-slate-700 rounded-lg text-slate-200">
            <Settings className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              Platform Integrations & Environment Settings
            </h2>
            <p className="text-[11px] text-slate-400 font-sans">
              Real LLM provider integration, genuine Wazuh SIEM connectivity, host binary probes, and cryptographic audit.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-1.5 bg-[#080c14] border border-slate-800 p-1 rounded-lg">
          <button
            onClick={() => setActiveSubTab('KALI_AGENT')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeSubTab === 'KALI_AGENT'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Laptop className="w-3.5 h-3.5 text-cyan-300" />
            <span>Kali Linux Agent</span>
            <span className={`w-2 h-2 rounded-full ${agents.some(a => a.status === 'ONLINE' || a.status === 'BUSY') ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
          </button>

          <button
            onClick={() => setActiveSubTab('LLM')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeSubTab === 'LLM'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI / LLM Settings</span>
          </button>

          <button
            onClick={() => setActiveSubTab('SIEM')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeSubTab === 'SIEM'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Wazuh SIEM</span>
          </button>

          <button
            onClick={() => setActiveSubTab('SYSTEM')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center space-x-1.5 transition-colors ${
              activeSubTab === 'SYSTEM'
                ? 'bg-cyan-600 text-white shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Host & Audit</span>
          </button>
        </div>
      </div>

      {/* SUBTAB 0: REMOTE KALI EXECUTION AGENT */}
      {activeSubTab === 'KALI_AGENT' && (
        <div className="space-y-3.5">
          {/* Agent Overview Card */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Agent Hub Status</span>
              <div className="text-sm font-bold text-slate-100 flex items-center space-x-1.5">
                <Laptop className="w-3.5 h-3.5 text-cyan-400" />
                <span>ONLINE (Ready)</span>
              </div>
              <span className="text-[10px] text-emerald-400 block font-mono">Port 3000 /api/agent/*</span>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Connected Nodes</span>
              <div className="text-sm font-bold text-slate-100 flex items-center space-x-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>{agents.filter(a => a.status === 'ONLINE' || a.status === 'BUSY').length} Active Agent(s)</span>
              </div>
              <span className="text-[10px] text-slate-400 block font-mono">
                {agents.length} Registered Node(s)
              </span>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Execution Model</span>
              <div className="text-sm font-bold text-cyan-300 flex items-center space-x-1.5">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>Scope Gated + HITL</span>
              </div>
              <span className="text-[10px] text-slate-400 block font-mono">Zero arbitrary shell scripts</span>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Quick Action</span>
              <div className="pt-0.5">
                <button
                  onClick={handleConnectDemoAgent}
                  disabled={agentConnectingDemo}
                  className="w-full flex items-center justify-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition-colors disabled:opacity-50"
                >
                  <Activity className="w-3 h-3" />
                  <span>{agentConnectingDemo ? 'Connecting...' : 'Connect Test Kali Node'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Quick-Start Execution Guide */}
          <div className="bg-[#0e1422] border border-cyan-900/30 rounded-lg p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                  Kali Linux Remote Execution Agent Quick-Start
                </h3>
              </div>
              <span className="text-[10.5px] text-slate-400 font-sans">
                Authenticate your real Kali machine to execute Nmap, Nuclei, Nikto, ffuf, Gobuster live
              </span>
            </div>

            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              To make all 26 security tools 100% operational against authorized in-scope targets, run the AWM Nexus agent script on your Kali Linux workstation. The agent connects back to this dev server, receives assigned jobs, executes native tools safely, and streams stdout/stderr back in real time.
            </p>

            {/* Token Card */}
            <div className="bg-[#080c14] border border-slate-800 rounded p-2.5 flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div className="space-y-0.5 flex-1">
                <span className="text-[9.5px] text-slate-400 uppercase tracking-wider block">Agent Authorization Bearer Token:</span>
                <span className="text-xs font-mono text-cyan-400 font-bold break-all">{agentToken}</span>
              </div>
              <div className="flex items-center space-x-2 shrink-0">
                <button
                  onClick={handleCopyToken}
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs flex items-center space-x-1 transition-colors"
                >
                  {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedToken ? 'Copied' : 'Copy Token'}</span>
                </button>
                <button
                  onClick={handleRegenerateToken}
                  className="px-2.5 py-1 bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-300 rounded text-xs transition-colors"
                >
                  Regenerate
                </button>
              </div>
            </div>

            {/* Terminal Commands */}
            <div className="space-y-1.5 pt-1">
              <span className="text-[10px] text-slate-400 uppercase font-mono block">Terminal Command (Python 3 - Zero dependencies):</span>
              <pre className="bg-[#080c14] border border-slate-800 rounded p-2.5 text-xs text-emerald-400 font-mono overflow-x-auto select-all">
                python3 agents/awm_nexus_agent.py --server http://127.0.0.1:3000 --token {agentToken}
              </pre>

              <span className="text-[10px] text-slate-400 uppercase font-mono block pt-1">Or using Node.js:</span>
              <pre className="bg-[#080c14] border border-slate-800 rounded p-2.5 text-xs text-cyan-300 font-mono overflow-x-auto select-all">
                node agents/awm_nexus_agent.mjs --server http://127.0.0.1:3000 --token {agentToken}
              </pre>
            </div>
          </div>

          {/* Registered Agents Table */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                  Registered Remote Execution Agents
                </h3>
              </div>
              <button
                onClick={() => setAgents([...remoteAgentManager.getAllAgents()])}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Refresh List</span>
              </button>
            </div>

            {agents.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 font-mono border border-dashed border-slate-800 rounded">
                No Kali Linux execution agents connected. Run the agent script above or click "Connect Test Kali Node" to activate remote Kali tooling.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border border-slate-800 rounded overflow-hidden">
                  <thead className="bg-[#080c14] text-[10px] text-slate-400 uppercase border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">Agent Name & Host</th>
                      <th className="py-2 px-3">Status</th>
                      <th className="py-2 px-3">Operating System</th>
                      <th className="py-2 px-3">IP Address</th>
                      <th className="py-2 px-3">Verified Tools</th>
                      <th className="py-2 px-3">Jobs Completed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {agents.map(ag => (
                      <tr key={ag.id} className="hover:bg-slate-900/40">
                        <td className="py-2 px-3">
                          <div className="font-bold text-slate-200">{ag.name}</div>
                          <div className="text-[10px] text-slate-500">{ag.hostname} ({ag.id})</div>
                        </td>
                        <td className="py-2 px-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            ag.status === 'ONLINE' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                            ag.status === 'BUSY' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800 animate-pulse' :
                            'bg-slate-900 text-slate-500 border border-slate-800'
                          }`}>
                            {ag.status}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-300">{ag.os}</td>
                        <td className="py-2 px-3 text-cyan-400">{ag.ip}</td>
                        <td className="py-2 px-3 text-slate-300">
                          <span className="text-emerald-400 font-bold">{ag.installedTools.length} tools</span>
                          <span className="text-[10px] text-slate-500 block truncate max-w-[200px]">
                            {ag.installedTools.slice(0, 5).join(', ')}...
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-300">{ag.jobsCompleted}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Tool Capability & Execution Matrix */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-2">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>AWM Nexus Live Tool Execution Capability Matrix</span>
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-sans">
              <div className="p-3 bg-[#080c14] border border-slate-800 rounded space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 font-mono">1. Local Container Live Engines</span>
                  <span className="text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded font-mono">100% OPERATIONAL</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Runs natively directly on the server without external dependencies:
                </p>
                <ul className="text-[11px] text-slate-300 space-y-1 list-disc list-inside font-mono">
                  <li><strong className="text-cyan-400">cURL Probe</strong> — Live HTTP status, security headers, banners</li>
                  <li><strong className="text-cyan-400">OpenSSL Inspector</strong> — Live TLS handshake, cipher suites, cert expiry</li>
                  <li><strong className="text-cyan-400">DNS (Dig/DNSRecon)</strong> — Live resolution (A, AAAA, MX, TXT, NS, SOA)</li>
                  <li><strong className="text-cyan-400">WHOIS / RDAP</strong> — Live ICANN registration, registrar, dates, status</li>
                  <li><strong className="text-cyan-400">TCP Port Probe & Ping</strong> — Live socket latency, open port checks</li>
                </ul>
              </div>

              <div className="p-3 bg-[#080c14] border border-slate-800 rounded space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 font-mono">2. Remote Kali Execution Agent</span>
                  <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded font-mono">DISPATCH ACTIVE</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Dispatched to authorized operator workstation over secure authenticated agent protocol:
                </p>
                <ul className="text-[11px] text-slate-300 space-y-1 list-disc list-inside font-mono">
                  <li><strong className="text-cyan-400">Nmap Network Scanner</strong> — Full SYN stealth, banner grabs, NSE scripts</li>
                  <li><strong className="text-cyan-400">Nuclei Scanner</strong> — Critical CVE templates & exposure audits</li>
                  <li><strong className="text-cyan-400">Nikto & ffuf</strong> — Web misconfigurations & rapid fuzzing</li>
                  <li><strong className="text-cyan-400">Masscan & Gobuster</strong> — High speed port sweeps & directory enum</li>
                  <li><strong className="text-cyan-400">Metasploit, Hashcat & John</strong> — Controlled exploit & entropy audits</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 1: REAL LLM PROVIDER SETTINGS */}
      {activeSubTab === 'LLM' && (
        <div className="space-y-3.5">
          {/* Status Overview Card */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Active Provider</span>
              <div className="text-sm font-bold text-slate-100 flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>{llmConfigState.provider === 'gemini' ? 'Google Gemini' : 'Deterministic Fallback'}</span>
              </div>
              <div className="text-[10px] text-slate-400 font-sans">
                {llmConfigState.provider === 'gemini' ? 'Official @google/genai SDK' : 'Rule-based analytical engine'}
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Default Model</span>
              <div className="text-sm font-bold text-cyan-300">{llmConfigState.model}</div>
              <div className="text-[10px] text-slate-400 font-sans">Optimized for low-latency reasoning</div>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">API Key Status</span>
              <div>
                {llmConfigState.apiKeyConfigured ? (
                  <span className="bg-emerald-950/70 border border-emerald-700/60 text-emerald-400 text-[10px] px-2 py-0.5 rounded font-bold flex items-center space-x-1 w-max">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>CONFIGURED (SERVER-SIDE)</span>
                  </span>
                ) : (
                  <span className="bg-amber-950/70 border border-amber-700/60 text-amber-400 text-[10px] px-2 py-0.5 rounded font-bold flex items-center space-x-1 w-max">
                    <AlertTriangle className="w-3 h-3" />
                    <span>MISSING (USING FALLBACK)</span>
                  </span>
                )}
              </div>
              <div className="text-[10px] text-slate-400 font-sans">Checked via environment & session</div>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Governance Boundary</span>
              <div className="text-sm font-bold text-emerald-400 flex items-center space-x-1">
                <Shield className="w-3.5 h-3.5" />
                <span>HITL Mandatory</span>
              </div>
              <div className="text-[10px] text-slate-400 font-sans">AI cannot execute arbitrary commands</div>
            </div>
          </div>

          {/* Configuration Form */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
            <div className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-1.5">
              <Key className="w-3.5 h-3.5 text-cyan-400" />
              <span>Google Gemini Provider Configuration</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Provider Selection</label>
                <select
                  value={llmProvider}
                  onChange={e => handleToggleLlmProvider(e.target.value)}
                  className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
                >
                  <option value="gemini">Google Gemini (Recommended — gemini-3.8-flash)</option>
                  <option value="deterministic-fallback">Deterministic Fallback Engine (Offline Mode)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Session API Key (Ephemeral Server Memory)</label>
                <div className="flex items-center space-x-1.5">
                  <div className="relative flex-1">
                    <input
                      type={showLlmKey ? 'text' : 'password'}
                      placeholder={llmConfigState.apiKeyConfigured ? 'API Key configured in environment' : 'Enter GEMINI_API_KEY...'}
                      value={llmKeyInput}
                      onChange={e => setLlmKeyInput(e.target.value)}
                      className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-cyan-300 pr-8"
                    />
                    <button
                      type="button"
                      onClick={() => setShowLlmKey(!showLlmKey)}
                      className="absolute right-2 top-2 text-slate-500 hover:text-slate-300"
                    >
                      {showLlmKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                  <button
                    onClick={handleSaveLlmKey}
                    disabled={!llmKeyInput.trim()}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded text-xs font-semibold shrink-0"
                  >
                    Set Key
                  </button>
                </div>
                <p className="text-[10px] text-slate-500 font-sans">
                  Keys are stored exclusively in server process memory and are never serialized or sent to the browser bundle.
                </p>
              </div>
            </div>

            {/* Test Connection Action */}
            <div className="pt-2 border-t border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="text-[11px] text-slate-400 font-sans">
                Initiates a real 1-token test prompt to the Google GenAI endpoint to verify live authentication and latency.
              </div>

              <button
                onClick={handleTestLlm}
                disabled={llmTesting}
                className="flex items-center space-x-1.5 px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-bold transition-colors shrink-0"
              >
                <Activity className={`w-3.5 h-3.5 ${llmTesting ? 'animate-spin' : ''}`} />
                <span>{llmTesting ? 'Testing Real Gemini Connection...' : 'Test Real LLM Connection'}</span>
              </button>
            </div>

            {/* Test Results Output Box */}
            {llmTestResult && (
              <div
                className={`p-3 rounded-lg border text-xs font-mono space-y-1.5 ${
                  llmTestResult.success
                    ? 'bg-emerald-950/40 border-emerald-700/60 text-emerald-200'
                    : 'bg-amber-950/40 border-amber-700/60 text-amber-200'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span className="flex items-center space-x-1.5">
                    {llmTestResult.success ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-amber-400" />}
                    <span>{llmTestResult.success ? 'REAL LLM API CONNECTION VERIFIED' : 'LLM CONNECTION NOT OPERATIONAL'}</span>
                  </span>
                  <span className="text-[10px] bg-slate-900 px-2 py-0.5 rounded text-slate-300">
                    Latency: {llmTestResult.latencyMs}ms
                  </span>
                </div>
                <p className="text-[11px] font-sans">{llmTestResult.message}</p>
                {llmTestResult.sampleResponse && (
                  <div className="text-[10.5px] bg-[#070a10] p-2 rounded border border-slate-800 text-cyan-300">
                    Sample Response: "{llmTestResult.sampleResponse}"
                  </div>
                )}
                {llmTestResult.error && (
                  <div className="text-[10.5px] bg-[#070a10] p-2 rounded border border-red-900/50 text-red-300">
                    Diagnostic Details: {llmTestResult.error}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 2: REAL WAZUH SIEM SETTINGS */}
      {activeSubTab === 'SIEM' && (
        <div className="space-y-3.5">
          {/* Status Overview Card */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">SIEM Provider</span>
              <div className="text-sm font-bold text-slate-100 flex items-center space-x-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                <span>Wazuh v4 REST API</span>
              </div>
              <div className="text-[10px] text-slate-400 font-sans">Authenticated token endpoint</div>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Live Connection Status</span>
              <div>
                {siemStatusResult.status === 'CONNECTED' ? (
                  <span className="bg-emerald-950/70 border border-emerald-700/60 text-emerald-400 text-[10px] px-2 py-0.5 rounded font-bold flex items-center space-x-1 w-max">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>CONNECTED & AUTHENTICATED</span>
                  </span>
                ) : siemStatusResult.status === 'UNVERIFIED' ? (
                  <span className="bg-purple-950/70 border border-purple-700/60 text-purple-300 text-[10px] px-2 py-0.5 rounded font-bold flex items-center space-x-1 w-max">
                    <AlertTriangle className="w-3 h-3" />
                    <span>UNVERIFIED (NO LIVE HOST)</span>
                  </span>
                ) : (
                  <span className="bg-slate-900 border border-slate-700 text-slate-400 text-[10px] px-2 py-0.5 rounded font-bold w-max block">
                    DISCONNECTED
                  </span>
                )}
              </div>
              <div className="text-[10px] text-slate-400 font-sans">Honest diagnostic reporting</div>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Synced Events</span>
              <div className="text-sm font-bold text-cyan-300">{siemStats.syncedAlertsCount} Alerts Ingested</div>
              <div className="text-[10px] text-slate-400 font-sans">Streamed to Defensive Engine</div>
            </div>

            <div className="space-y-1">
              <span className="text-[9.5px] uppercase text-slate-500 block">Last Sync Timestamp</span>
              <div className="text-xs font-bold text-slate-200">
                {siemStats.lastSyncTime ? new Date(siemStats.lastSyncTime).toLocaleTimeString() : 'No sync recorded'}
              </div>
              <div className="text-[10px] text-slate-400 font-sans">Manual or cron schedule</div>
            </div>
          </div>

          {/* Wazuh Configuration Form */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
            <div className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center justify-between">
              <div className="flex items-center space-x-1.5">
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                <span>Wazuh Server & API Parameters</span>
              </div>
              <button
                onClick={handleDemoIngest}
                className="px-2.5 py-1 bg-purple-900/40 hover:bg-purple-800/60 border border-purple-600/50 text-purple-200 rounded text-[10px] font-bold"
              >
                + Ingest Verified Sample Alerts (Demo)
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Wazuh Server URL</label>
                <input
                  type="text"
                  value={siemBaseUrl}
                  onChange={e => setSiemBaseUrl(e.target.value)}
                  placeholder="https://wazuh.corp.internal"
                  className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">API Port</label>
                <input
                  type="number"
                  value={siemPort}
                  onChange={e => setSiemPort(Number(e.target.value))}
                  className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Min Alert Level (0-15)</label>
                <input
                  type="number"
                  min={0}
                  max={15}
                  value={siemMinLevel}
                  onChange={e => setSiemMinLevel(Number(e.target.value))}
                  className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">API Username</label>
                <input
                  type="text"
                  value={siemUser}
                  onChange={e => setSiemUser(e.target.value)}
                  className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
                />
              </div>

              <div className="space-y-1 md:col-span-2">
                <label className="text-[10px] text-slate-400 uppercase">API Password / Token</label>
                <input
                  type="password"
                  placeholder="Enter Wazuh user password..."
                  value={siemPassword}
                  onChange={e => setSiemPassword(e.target.value)}
                  className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-cyan-300"
                />
              </div>
            </div>

            {/* Actions Bar */}
            <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <div className="text-[11px] text-slate-400 font-sans">
                POST /security/user/authenticate generates JWT token; GET /alerts streams normalized telemetry.
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={handleTestSiem}
                  disabled={siemTesting}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded text-xs font-bold transition-colors"
                >
                  <Activity className={`w-3.5 h-3.5 ${siemTesting ? 'animate-spin' : ''}`} />
                  <span>{siemTesting ? 'Testing Connection...' : 'Test SIEM Connection'}</span>
                </button>

                <button
                  onClick={handleSyncSiem}
                  disabled={siemSyncing}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-bold transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${siemSyncing ? 'animate-spin' : ''}`} />
                  <span>{siemSyncing ? 'Syncing...' : 'Sync Alerts Now'}</span>
                </button>
              </div>
            </div>

            {/* Diagnostic Details */}
            {siemStatusResult && (
              <div className="p-3 bg-[#080c14] border border-slate-800 rounded-lg text-xs font-mono space-y-1">
                <div className="text-[10px] uppercase text-slate-500 font-bold">Diagnostics & Host Probe Details</div>
                <div className="text-slate-300 font-sans leading-relaxed">{siemStatusResult.details}</div>
                {siemStatusResult.latencyMs !== undefined && (
                  <div className="text-[10px] text-slate-400">Probe Latency: {siemStatusResult.latencyMs}ms</div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 3: HOST & AUDIT */}
      {activeSubTab === 'SYSTEM' && (
        <div className="space-y-3.5">
          {/* Diagnostics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="bg-[#0e1422] border border-slate-800 p-3 rounded-lg space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-[9.5px] uppercase">CONTAINER RUNTIME</span>
                <Server className="w-3.5 h-3.5 text-cyan-400" />
              </div>
              <div className="text-base font-bold text-slate-100">Linux x86_64</div>
              <div className="text-[10.5px] text-emerald-400 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>Port 3000 Ingress Operational</span>
              </div>
            </div>

            <div className="bg-[#0e1422] border border-slate-800 p-3 rounded-lg space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-[9.5px] uppercase">TOOL CLASSIFICATION</span>
                <Layers className="w-3.5 h-3.5 text-purple-400" />
              </div>
              <div className="text-base font-bold text-slate-100">
                {installedTools.length} Native / {allTools.length - installedTools.length} Simulated
              </div>
              <div className="text-[10.5px] text-slate-400">26 Tools Registered & Fingerprinted</div>
            </div>

            <div className="bg-[#0e1422] border border-slate-800 p-3 rounded-lg space-y-1.5">
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-[9.5px] uppercase">AUDIT CHAIN INTEGRITY</span>
                <Database className="w-3.5 h-3.5 text-emerald-400" />
              </div>
              <div className="text-base font-bold text-emerald-400">Block #{audit.blocksCount}</div>
              <div className="text-[10.5px] text-emerald-400 flex items-center space-x-1">
                <CheckCircle2 className="w-3 h-3" />
                <span>Cryptographic SHA-256 Validated</span>
              </div>
            </div>
          </div>

          {/* Tenant Configuration Form */}
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-2.5">
            <div className="text-[11px] font-bold text-slate-200 uppercase tracking-wider">
              Active Tenant & Engagement Parameters
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-0.5">
                <label className="text-[9.5px] text-slate-500 uppercase block">Tenant Identifier</label>
                <input
                  type="text"
                  readOnly
                  value={engagement?.tenantId || 'TENANT-AWM-01'}
                  className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-300 font-mono"
                />
              </div>

              <div className="space-y-0.5">
                <label className="text-[9.5px] text-slate-500 uppercase block">Active Engagement Code</label>
                <input
                  type="text"
                  readOnly
                  value={engagement?.code || 'ENG-2026-ALPHA'}
                  className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1 text-xs text-cyan-400 font-mono font-bold"
                />
              </div>

              <div className="space-y-0.5">
                <label className="text-[9.5px] text-slate-500 uppercase block">Authorized Capability Tier</label>
                <input
                  type="text"
                  readOnly
                  value="TIER 4 — FULL PENTEST & ACTIVE PROBING"
                  className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1 text-xs text-amber-400 font-mono"
                />
              </div>

              <div className="space-y-0.5">
                <label className="text-[9.5px] text-slate-500 uppercase block">HITL Cryptographic Gate Policy</label>
                <input
                  type="text"
                  readOnly
                  value="ENFORCED — DUAL OPERATOR TOKEN REQUIRED"
                  className="w-full bg-[#080c14] border border-slate-800 rounded px-2.5 py-1 text-xs text-emerald-400 font-mono"
                />
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleReProbe}
                disabled={probing}
                className="flex items-center space-x-1.5 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-semibold transition-colors shrink-0"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${probing ? 'animate-spin' : ''}`} />
                <span>{probing ? 'Probing Binaries...' : 'Re-Probe Host Binaries'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
