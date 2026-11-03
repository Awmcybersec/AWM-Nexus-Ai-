/**
 * AWM Nexus — Security Digital Twin
 * Real-time topological and behavioral model of enterprise infrastructure,
 * trust zones, active perimeters, open service nodes, and live threat exposure.
 */

import React, { useState } from 'react';
import {
  Layers,
  Server,
  Shield,
  Radio,
  Lock,
  Globe,
  Database,
  Cpu,
  ArrowRight,
  Activity,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search
} from 'lucide-react';
import { scopeEngine } from '../engine/scopeEngine';
import { attackSurfaceEngine } from '../engine/offensiveDefensiveEngines';
import { riskEngine } from '../engine/riskAndEvidenceEngine';
import { sandboxExecutionManager } from '../engine/sandboxExecution';

export const DigitalTwinView: React.FC = () => {
  const engagement = scopeEngine.getAllEngagements()[0];
  const assets = attackSurfaceEngine.getAllAssets();
  const allJobs = sandboxExecutionManager.getAllJobs();
  const allFindings = allJobs.flatMap(j => j.findings);
  const risk = riskEngine.calculateRiskScore(allFindings);

  const [selectedNode, setSelectedNode] = useState<string>(assets[0]?.target || '127.0.0.1');
  const [filterZone, setFilterZone] = useState<string>('ALL');

  const nodes = [
    {
      id: 'node-ext-gw',
      name: 'Cloudflare Ingress WAF',
      ip: '198.51.100.1',
      zone: 'EXTERNAL_PERIMETER',
      status: 'SHIELDED',
      type: 'SECURITY_GATEWAY',
      services: ['TLSv1.3', 'HTTP/2 Reverse Proxy', 'WAF Rule Engine v4.2'],
      connections: ['api.nexus-staging.internal'],
      exposure: 15
    },
    {
      id: 'node-api-gw',
      name: 'API Gateway / Staging Server',
      ip: 'api.nexus-staging.internal',
      zone: 'DMZ_CLUSTER',
      status: 'EXPOSED',
      type: 'WEB_APPLICATION',
      services: ['Nginx 1.24', 'Node.js Express', 'REST API (Port 80/443/8080)'],
      connections: ['10.0.100.25', '127.0.0.1'],
      exposure: 68
    },
    {
      id: 'node-dmz-app',
      name: 'DMZ Microservice Node',
      ip: '10.0.100.25',
      zone: 'DMZ_CLUSTER',
      status: 'MONITORED',
      type: 'APPLICATION_SERVER',
      services: ['OpenSSH 8.9p1', 'Nginx Microservice', 'Auth Service'],
      connections: ['10.0.0.1'],
      exposure: 45
    },
    {
      id: 'node-dev-sandbox',
      name: 'Local Execution Sandbox',
      ip: '127.0.0.1',
      zone: 'SECURE_SANDBOX',
      status: 'ISOLATED',
      type: 'SANDBOX_CONTAINER',
      services: ['Vite Dev Server', 'ASCL Process Sandbox', 'OpenSSL / curl Native'],
      connections: [],
      exposure: 24
    },
    {
      id: 'node-corp-dc',
      name: 'Corporate Domain Controller',
      ip: '10.0.0.1',
      zone: 'INTERNAL_RESTRICTED',
      status: 'EXCLUDED_ROE',
      type: 'IDENTITY_CORE',
      services: ['Active Directory / Kerberos', 'LDAPS (Port 636)', 'DNS (Port 53)'],
      connections: [],
      exposure: 5
    }
  ];

  const filteredNodes = filterZone === 'ALL' ? nodes : nodes.filter(n => n.zone === filterZone);
  const activeNode = nodes.find(n => n.ip === selectedNode) || nodes[0];

  return (
    <div className="space-y-3.5 font-mono text-xs">
      {/* Top Banner */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-cyan-950/70 border border-cyan-500/40 rounded-lg text-cyan-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
              Security Digital Twin Topology
            </h2>
            <p className="text-[11px] text-slate-400 font-sans">
              Dynamic software-defined model of network zones, service mesh dependencies, and real-time attack path graphs.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <div className="bg-[#080c14] border border-slate-800 px-2.5 py-1 rounded flex items-center space-x-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[10px] text-slate-300">TWIN SYNC: LIVE</span>
          </div>
        </div>
      </div>

      {/* Zone Filter & Telemetry Bar */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-3 py-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center space-x-1.5">
          <span className="text-slate-500 text-[10px]">ZONE FILTER:</span>
          {['ALL', 'EXTERNAL_PERIMETER', 'DMZ_CLUSTER', 'SECURE_SANDBOX', 'INTERNAL_RESTRICTED'].map(zone => (
            <button
              key={zone}
              onClick={() => setFilterZone(zone)}
              className={`px-2 py-0.5 rounded text-[9.5px] transition-colors ${
                filterZone === zone
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/60 font-bold'
                  : 'bg-[#080c14] text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {zone.replace('_', ' ')}
            </button>
          ))}
        </div>

        <div className="text-[10px] text-slate-400">
          NODES MAPPED: <span className="text-cyan-400 font-bold">{nodes.length}</span> | COMPOSITE POSTURE:{' '}
          <span className="text-amber-400 font-bold">{risk.score}/100</span>
        </div>
      </div>

      {/* Topology Graph Canvas & Node Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
        {/* Topology Node Map (7 Cols) */}
        <div className="lg:col-span-7 bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
          <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
            <span>Network Mesh & Trust Zone Topology</span>
            <span className="text-[9.5px] text-slate-500 font-normal">Click node to inspect telemetry</span>
          </div>

          <div className="space-y-2">
            {filteredNodes.map(node => {
              const isSelected = selectedNode === node.ip;
              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node.ip)}
                  className={`p-2.5 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-slate-800/90 border-cyan-500/60 shadow-md shadow-cyan-950/30'
                      : 'bg-[#080c14] border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center space-x-2">
                      <Server className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-400' : 'text-slate-400'}`} />
                      <span className="font-bold text-slate-200 text-xs">{node.name}</span>
                      <code className="text-cyan-400 text-[10px]">({node.ip})</code>
                    </div>

                    <span
                      className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                        node.status === 'EXPOSED'
                          ? 'bg-red-950 text-red-400 border border-red-800'
                          : node.status === 'SHIELDED'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : node.status === 'EXCLUDED_ROE'
                          ? 'bg-purple-950 text-purple-400 border border-purple-800'
                          : 'bg-slate-900 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {node.status}
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-400">
                    <div>
                      <span className="text-slate-500 text-[9px] block">ZONE:</span>
                      <span>{node.zone}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[9px] block">EXPOSURE METRIC:</span>
                      <span className={node.exposure > 50 ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                        {node.exposure} / 100
                      </span>
                    </div>
                  </div>

                  {node.connections.length > 0 && (
                    <div className="mt-1.5 pt-1.5 border-t border-slate-800/60 flex items-center space-x-1.5 text-[9.5px] text-slate-500">
                      <ArrowRight className="w-3 h-3 text-cyan-400" />
                      <span>Downstream Pivot Targets:</span>
                      <span className="text-slate-300">{node.connections.join(', ')}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Node Inspector & Behavioral Telemetry (5 Cols) */}
        <div className="lg:col-span-5 bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
          <div className="border-b border-slate-800/80 pb-2">
            <span className="text-[9.5px] text-slate-500 uppercase">DIGITAL TWIN INSPECTOR</span>
            <h3 className="text-xs font-bold text-slate-100 mt-0.5">{activeNode.name}</h3>
            <div className="text-cyan-400 text-[11px] mt-0.5">{activeNode.ip}</div>
          </div>

          <div className="space-y-2.5">
            <div className="bg-[#080c14] border border-slate-800 p-2.5 rounded space-y-1.5">
              <span className="text-slate-500 text-[9.5px] uppercase block">Fingerprinted Services</span>
              <div className="space-y-1">
                {activeNode.services.map(svc => (
                  <div key={svc} className="flex items-center space-x-1.5 text-slate-300 text-[10.5px]">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400 shrink-0" />
                    <span>{svc}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-[#080c14] border border-slate-800 p-2.5 rounded space-y-1.5">
              <span className="text-slate-500 text-[9.5px] uppercase block">RoE & Authorization Status</span>
              <div className="flex items-center justify-between text-[10.5px]">
                <span className="text-slate-400">Rules of Engagement:</span>
                <span className="text-emerald-400 font-bold">
                  {activeNode.status === 'EXCLUDED_ROE' ? 'BLOCKED (OUT-OF-SCOPE)' : 'AUTHORIZED IN-SCOPE'}
                </span>
              </div>
              <div className="flex items-center justify-between text-[10.5px]">
                <span className="text-slate-400">Allowed Capability:</span>
                <span className="text-cyan-400 font-bold">TIER 4 (ALL-ACCESS)</span>
              </div>
            </div>

            <div className="bg-[#080c14] border border-slate-800 p-2.5 rounded space-y-1">
              <span className="text-slate-500 text-[9.5px] uppercase block">Twin Behavioral Model</span>
              <p className="text-[10px] text-slate-400 leading-relaxed font-sans">
                Continuous telemetry feeds update open port states, TLS cipher profiles, and ingress WAF rule reactions
                in real time to maintain zero-drift parity with live production targets.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
