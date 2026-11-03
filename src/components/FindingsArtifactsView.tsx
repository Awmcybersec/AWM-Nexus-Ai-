/**
 * AWM Nexus — Dedicated Findings, External Tool Imports & Risk Inspector
 * Displays discovered normalized vulnerabilities, CWE/OWASP/CVSS classification,
 * raw execution artifact logs, crown-jewel risk impact, and external tool results ingestion.
 */

import React, { useState } from 'react';
import {
  AlertTriangle,
  FileCode,
  ShieldAlert,
  Search,
  ExternalLink,
  CheckCircle2,
  Lock,
  Download,
  Eye,
  Crosshair,
  Hash,
  Database,
  Upload,
  FileCheck,
  XCircle,
  Copy,
  Check,
  RefreshCw,
  Clock,
  Sparkles,
  Layers
} from 'lucide-react';
import { sandboxExecutionManager } from '../engine/sandboxExecution';
import { riskEngine } from '../engine/riskAndEvidenceEngine';
import { externalToolImportEngine } from '../engine/externalToolImportEngine';
import {
  SAMPLE_NMAP_XML,
  SAMPLE_BURP_XML,
  SAMPLE_NESSUS_XML,
  SAMPLE_NUCLEI_JSONL
} from '../engine/sampleImportData';
import {
  NormalizedFinding,
  ArtifactFile,
  ExternalToolFormat,
  ExternalToolImportRecord
} from '../types';

export const FindingsArtifactsView: React.FC = () => {
  const allJobs = sandboxExecutionManager.getAllJobs();
  const jobFindings = allJobs.flatMap(j => j.findings);
  const [importedFindings, setImportedFindings] = useState<NormalizedFinding[]>(
    externalToolImportEngine.getAllImportedFindings()
  );
  const [importsHistory, setImportsHistory] = useState<ExternalToolImportRecord[]>(
    externalToolImportEngine.getAllImports()
  );

  // Combine findings from sandbox jobs and external imports
  const allFindings = [...importedFindings, ...jobFindings];
  const allArtifacts = allJobs.flatMap(j => j.artifacts);

  const [activeSubTab, setActiveSubTab] = useState<'findings' | 'imports' | 'artifacts' | 'risk'>('findings');
  const [selectedFinding, setSelectedFinding] = useState<NormalizedFinding | null>(allFindings[0] || null);
  const [selectedArtifact, setSelectedArtifact] = useState<ArtifactFile | null>(allArtifacts[0] || null);
  const [selectedImport, setSelectedImport] = useState<ExternalToolImportRecord | null>(importsHistory[0] || null);
  const [searchQuery, setSearchQuery] = useState('');

  // Import Modal & Form State
  const [showImportModal, setShowImportModal] = useState<boolean>(false);
  const [importFilename, setImportFilename] = useState<string>('nmap_scan_results.xml');
  const [importContent, setImportContent] = useState<string>('');
  const [selectedFormat, setSelectedFormat] = useState<ExternalToolFormat | 'AUTO'>('AUTO');
  const [importing, setImporting] = useState<boolean>(false);
  const [importFeedback, setImportFeedback] = useState<{ success: boolean; message: string; record?: ExternalToolImportRecord } | null>(null);

  const refreshData = () => {
    setImportedFindings([...externalToolImportEngine.getAllImportedFindings()]);
    setImportsHistory([...externalToolImportEngine.getAllImports()]);
  };

  const filteredFindings = allFindings.filter(f =>
    f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.cwe.toLowerCase().includes(searchQuery.toLowerCase()) ||
    f.owaspCategory.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (f.sourceTool && f.sourceTool.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const handleLoadSample = (type: 'NMAP' | 'BURP' | 'NESSUS' | 'NUCLEI') => {
    switch (type) {
      case 'NMAP':
        setImportFilename('perimeter_nmap_vuln.xml');
        setImportContent(SAMPLE_NMAP_XML);
        setSelectedFormat('NMAP_XML');
        break;
      case 'BURP':
        setImportFilename('web_burp_issues.xml');
        setImportContent(SAMPLE_BURP_XML);
        setSelectedFormat('BURP_XML');
        break;
      case 'NESSUS':
        setImportFilename('infra_nessus_report.nessus');
        setImportContent(SAMPLE_NESSUS_XML);
        setSelectedFormat('NESSUS_XML');
        break;
      case 'NUCLEI':
        setImportFilename('nuclei_cve_scans.jsonl');
        setImportContent(SAMPLE_NUCLEI_JSONL);
        setSelectedFormat('NUCLEI_JSONL');
        break;
    }
    setImportFeedback(null);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setImportFilename(file.name);
    const reader = new FileReader();
    reader.onload = event => {
      const text = event.target?.result as string;
      setImportContent(text);
      setImportFeedback(null);
    };
    reader.readAsText(file);
  };

  const handleExecuteImport = async () => {
    if (!importContent.trim()) {
      setImportFeedback({ success: false, message: 'Upload or paste results file content first.' });
      return;
    }

    setImporting(true);
    setImportFeedback(null);

    try {
      const formatToUse = selectedFormat === 'AUTO' ? undefined : selectedFormat;
      const record = await externalToolImportEngine.importResults(
        importFilename,
        importContent,
        'eng-2026-001',
        'TENANT-AWM-01',
        'operator-human-01',
        formatToUse
      );

      refreshData();
      setSelectedImport(record);

      if (record.status === 'REJECTED') {
        setImportFeedback({
          success: false,
          message: `Import Rejected: ${record.errors.join('; ')}`,
          record
        });
      } else {
        setImportFeedback({
          success: true,
          message: `Successfully ingested ${record.validFindingsCount} findings (${record.duplicateCount} duplicates merged, ${record.outOfScopeCount} out-of-scope targets isolated).`,
          record
        });
      }
    } catch (err: unknown) {
      setImportFeedback({
        success: false,
        message: err instanceof Error ? err.message : String(err)
      });
    } finally {
      setImporting(false);
    }
  };

  const handleFindingValidationChange = (
    findingId: string,
    newStatus: NormalizedFinding['validationStatus']
  ) => {
    externalToolImportEngine.updateFindingValidation(findingId, newStatus, 'operator-human-01');
    refreshData();
    if (selectedFinding?.findingId === findingId) {
      setSelectedFinding({ ...selectedFinding, validationStatus: newStatus });
    }
  };

  return (
    <div className="space-y-3.5">
      {/* Top Banner & Sub-Navigation */}
      <div className="bg-[#0e1422] border border-slate-800 rounded-lg px-4 py-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-amber-950/60 border border-amber-600/40 rounded-lg text-amber-400">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <span>Findings, Evidence & External Tool Ingestion</span>
              <span className="text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800/60 px-1.5 py-0.5 rounded font-mono">
                PHASE 2
              </span>
            </h2>
            <p className="text-[11px] text-slate-400">
              Normalized CWE/CVSS vulnerabilities, Nmap/Burp/Nessus/Nuclei parser, and cryptographic SHA-256 evidence.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={() => {
              setShowImportModal(true);
              setImportFeedback(null);
            }}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold font-mono transition-colors shadow-sm"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import Results</span>
          </button>

          <div className="flex items-center space-x-1 bg-slate-900 border border-slate-800 p-0.5 rounded-md text-xs font-mono shrink-0">
            <button
              onClick={() => setActiveSubTab('findings')}
              className={`px-2.5 py-1 rounded transition-colors ${
                activeSubTab === 'findings' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Findings ({allFindings.length})
            </button>
            <button
              onClick={() => setActiveSubTab('imports')}
              className={`px-2.5 py-1 rounded transition-colors ${
                activeSubTab === 'imports' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Imports ({importsHistory.length})
            </button>
            <button
              onClick={() => setActiveSubTab('artifacts')}
              className={`px-2.5 py-1 rounded transition-colors ${
                activeSubTab === 'artifacts' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Artifacts ({allArtifacts.length})
            </button>
            <button
              onClick={() => setActiveSubTab('risk')}
              className={`px-2.5 py-1 rounded transition-colors ${
                activeSubTab === 'risk' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Risk Matrix
            </button>
          </div>
        </div>
      </div>

      {/* 1. FINDINGS SUBTAB */}
      {activeSubTab === 'findings' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 font-mono text-xs">
          {/* Findings List (5 Cols) */}
          <div className="lg:col-span-5 bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2 text-slate-500" />
              <input
                type="text"
                placeholder="Filter by title, CWE, OWASP, tool or host..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-[#080c14] border border-slate-800 rounded pl-8 pr-2.5 py-1 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="space-y-1.5 max-h-[540px] overflow-y-auto pr-1">
              {filteredFindings.length === 0 ? (
                <div className="p-8 text-center text-slate-500">
                  No findings match query or none discovered yet. Use "Import Results" to ingest Nmap, Burp, Nessus, or Nuclei scans.
                </div>
              ) : (
                filteredFindings.map(f => {
                  const isSelected = selectedFinding?.findingId === f.findingId;
                  return (
                    <div
                      key={f.findingId}
                      onClick={() => setSelectedFinding(f)}
                      className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-slate-800/90 border-cyan-500/50 shadow-sm'
                          : 'bg-[#080c14] border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span
                          className={`text-[9.5px] px-1.5 py-0.5 rounded font-bold ${
                            f.severity === 'CRITICAL'
                              ? 'bg-red-950/80 text-red-400 border border-red-800/60'
                              : f.severity === 'HIGH'
                              ? 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                              : f.severity === 'MEDIUM'
                              ? 'bg-yellow-950/80 text-yellow-400 border border-yellow-800/60'
                              : 'bg-blue-950/80 text-blue-400 border border-blue-800/60'
                          }`}
                        >
                          {f.severity}
                        </span>

                        <div className="flex items-center space-x-1.5">
                          {f.outOfScope && (
                            <span className="text-[9px] bg-red-900/60 border border-red-700 text-red-300 px-1 rounded">
                              OUT-OF-SCOPE
                            </span>
                          )}
                          <span
                            className={`text-[9.5px] px-1.5 py-0.5 rounded font-medium ${
                              f.validationStatus === 'CONFIRMED'
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                : f.validationStatus === 'FALSE_POSITIVE'
                                ? 'bg-slate-800 text-slate-400 border border-slate-700'
                                : f.validationStatus === 'REMEDIATED'
                                ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                                : 'bg-amber-950/70 text-amber-300 border border-amber-800'
                            }`}
                          >
                            {f.validationStatus}
                          </span>
                        </div>
                      </div>

                      <div className="font-semibold text-slate-200 text-xs truncate">{f.title}</div>

                      <div className="text-[10px] text-slate-400 mt-1 flex items-center justify-between truncate">
                        <span className="truncate text-cyan-400">
                          {f.host}
                          {f.port ? `:${f.port}` : ''}
                        </span>
                        <span className="text-slate-500 ml-2 shrink-0">{f.sourceTool || f.toolId}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Finding Detail Inspector (7 Cols) */}
          <div className="lg:col-span-7 bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
            {selectedFinding ? (
              <div className="space-y-3">
                <div className="flex items-start justify-between border-b border-slate-800/80 pb-2.5">
                  <div className="space-y-0.5">
                    <div className="text-[10px] text-slate-500">
                      ID: <span className="text-slate-400 font-mono">{selectedFinding.findingId}</span> • Host: <span className="text-cyan-400 font-bold">{selectedFinding.host}{selectedFinding.port ? `:${selectedFinding.port}` : ''}</span>
                    </div>
                    <h3 className="text-xs font-bold text-slate-100">{selectedFinding.title}</h3>
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold shrink-0 ${
                      selectedFinding.severity === 'CRITICAL'
                        ? 'bg-red-950 text-red-400 border border-red-800'
                        : selectedFinding.severity === 'HIGH'
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : selectedFinding.severity === 'MEDIUM'
                        ? 'bg-yellow-950 text-yellow-400 border border-yellow-800'
                        : 'bg-blue-950 text-blue-400 border border-blue-800'
                    }`}
                  >
                    {selectedFinding.severity}
                  </span>
                </div>

                {/* Scope Warning if target was outside ROE */}
                {selectedFinding.outOfScope && (
                  <div className="bg-red-950/40 border border-red-700/60 rounded p-2 text-red-300 text-[11px] flex items-center space-x-2">
                    <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                    <span>
                      <strong>Out-of-Scope Asset:</strong> Target <code className="text-white">{selectedFinding.host}</code> is not authorized by the engagement rules of engagement. This finding is quarantined for compliance audit.
                    </span>
                  </div>
                )}

                <div className="grid grid-cols-2 md:grid-cols-4 gap-1.5 text-[10.5px]">
                  <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded">
                    <span className="text-slate-500 block text-[9.5px]">CVSS SCORE:</span>
                    <span className="text-red-400 font-bold text-xs">{selectedFinding.cvssScore} / 10.0</span>
                  </div>
                  <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded">
                    <span className="text-slate-500 block text-[9.5px]">CWE TAXONOMY:</span>
                    <span className="text-cyan-400 font-semibold">{selectedFinding.cwe}</span>
                  </div>
                  <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded">
                    <span className="text-slate-500 block text-[9.5px]">SOURCE ENGINE:</span>
                    <span className="text-slate-200 font-semibold truncate block" title={selectedFinding.sourceTool || selectedFinding.toolId}>
                      {selectedFinding.sourceTool || selectedFinding.toolId}
                    </span>
                  </div>
                  <div className="bg-[#080c14] border border-slate-800 p-1.5 rounded">
                    <span className="text-slate-500 block text-[9.5px]">CONFIDENCE:</span>
                    <span className="text-emerald-400 font-semibold">{selectedFinding.confidence}</span>
                  </div>
                </div>

                {/* Manual Review / Validation Controls */}
                <div className="bg-[#080c14] border border-slate-800 p-2.5 rounded space-y-1.5">
                  <div className="text-[10px] text-slate-400 uppercase font-semibold flex items-center justify-between">
                    <span>Manual Review & Validation Posture:</span>
                    <span className="text-amber-400 font-bold">{selectedFinding.validationStatus}</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => handleFindingValidationChange(selectedFinding.findingId, 'CONFIRMED')}
                      className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                        selectedFinding.validationStatus === 'CONFIRMED'
                          ? 'bg-emerald-600 text-white'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                      }`}
                    >
                      Confirm Finding
                    </button>
                    <button
                      onClick={() => handleFindingValidationChange(selectedFinding.findingId, 'FALSE_POSITIVE')}
                      className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                        selectedFinding.validationStatus === 'FALSE_POSITIVE'
                          ? 'bg-slate-700 text-white'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                      }`}
                    >
                      Mark False Positive
                    </button>
                    <button
                      onClick={() => handleFindingValidationChange(selectedFinding.findingId, 'REMEDIATED')}
                      className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                        selectedFinding.validationStatus === 'REMEDIATED'
                          ? 'bg-cyan-600 text-white'
                          : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                      }`}
                    >
                      Mark Remediated
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-slate-400 font-bold text-[10.5px] block mb-0.5">TECHNICAL DETAILS & EVIDENCE:</span>
                  <div className="bg-[#080c14] border border-slate-800 p-2.5 rounded text-slate-300 text-xs leading-relaxed space-y-1.5">
                    <div>{selectedFinding.description}</div>
                    {selectedFinding.evidenceSnippet && (
                      <div className="pt-1.5 border-t border-slate-800 font-mono text-[11px] text-cyan-300 bg-[#05080f] p-2 rounded break-all whitespace-pre-wrap">
                        {selectedFinding.evidenceSnippet}
                      </div>
                    )}
                  </div>
                </div>

                {selectedFinding.references && selectedFinding.references.length > 0 && (
                  <div>
                    <span className="text-slate-400 font-bold text-[10.5px] block mb-0.5">EXTERNAL REFERENCES:</span>
                    <div className="bg-[#080c14] border border-slate-800 p-2 rounded space-y-0.5 text-[10.5px] text-slate-400">
                      {selectedFinding.references.map((r, i) => (
                        <div key={i} className="truncate">
                          • <a href={r} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">{r}</a>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <span className="text-slate-400 font-bold text-[10.5px] block mb-0.5">REMEDIATION GUIDANCE:</span>
                  <div className="bg-[#080c14] border border-slate-800 p-2.5 rounded text-emerald-300 text-xs leading-relaxed">
                    {selectedFinding.remediation}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500">Select a finding to inspect CVSS & remediation details.</div>
            )}
          </div>
        </div>
      )}

      {/* 2. EXTERNAL IMPORTS SUBTAB */}
      {activeSubTab === 'imports' && (
        <div className="space-y-3 font-mono text-xs">
          <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center space-x-2">
                <Upload className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-slate-200 uppercase tracking-wider text-xs">
                  External Assessment Results Import Ledger
                </span>
              </div>
              <span className="text-slate-400 text-[11px]">
                {importsHistory.length} Ingestion Records Sealed in Audit Chain
              </span>
            </div>

            {importsHistory.length === 0 ? (
              <div className="p-10 text-center space-y-3">
                <div className="text-slate-500">No external tool results imported yet.</div>
                <button
                  onClick={() => setShowImportModal(true)}
                  className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-semibold text-xs transition-colors"
                >
                  Import Assessment File Now
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[10px] uppercase">
                      <th className="py-2 px-2.5">Import ID</th>
                      <th className="py-2 px-2.5">Format</th>
                      <th className="py-2 px-2.5">Filename</th>
                      <th className="py-2 px-2.5 text-center">Parsed</th>
                      <th className="py-2 px-2.5 text-center">Dups</th>
                      <th className="py-2 px-2.5 text-center">Out-Scope</th>
                      <th className="py-2 px-2.5">Evidence / Audit</th>
                      <th className="py-2 px-2.5">Status</th>
                      <th className="py-2 px-2.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {importsHistory.map(imp => {
                      const isSelected = selectedImport?.importId === imp.importId;
                      return (
                        <tr
                          key={imp.importId}
                          onClick={() => setSelectedImport(imp)}
                          className={`hover:bg-slate-800/40 cursor-pointer ${
                            isSelected ? 'bg-slate-800/70' : ''
                          }`}
                        >
                          <td className="py-2 px-2.5 font-bold text-cyan-400">{imp.importId}</td>
                          <td className="py-2 px-2.5 font-semibold text-slate-300">
                            <span className="bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded text-[10px]">
                              {imp.format}
                            </span>
                          </td>
                          <td className="py-2 px-2.5 text-slate-200 truncate max-w-[200px]" title={imp.sanitizedFilename}>
                            {imp.sanitizedFilename}
                          </td>
                          <td className="py-2 px-2.5 text-center font-bold text-slate-100">{imp.validFindingsCount}</td>
                          <td className="py-2 px-2.5 text-center text-slate-400">{imp.duplicateCount}</td>
                          <td className="py-2 px-2.5 text-center text-amber-400">{imp.outOfScopeCount}</td>
                          <td className="py-2 px-2.5 text-slate-400 text-[10px]">
                            <div>{imp.evidenceId}</div>
                            <div className="text-slate-500">{imp.auditBlockId}</div>
                          </td>
                          <td className="py-2 px-2.5">
                            <span
                              className={`text-[9.5px] px-2 py-0.5 rounded font-bold ${
                                imp.status === 'SUCCESS'
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : imp.status === 'PARTIAL'
                                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                  : 'bg-red-950 text-red-400 border border-red-800'
                              }`}
                            >
                              {imp.status}
                            </span>
                          </td>
                          <td className="py-2 px-2.5 text-right">
                            <button
                              onClick={e => {
                                e.stopPropagation();
                                setSelectedImport(imp);
                              }}
                              className="text-cyan-400 hover:text-cyan-300 text-[11px] underline"
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Selected Import Inspection Drawer */}
          {selectedImport && (
            <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="space-y-0.5">
                  <div className="text-[10px] text-slate-400">
                    Import Record: <strong className="text-cyan-400">{selectedImport.importId}</strong> • Source: {selectedImport.sanitizedFilename} ({selectedImport.fileSizeBytes} bytes)
                  </div>
                  <div className="text-xs font-bold text-slate-200">
                    Format: {selectedImport.format} • Extracted Targets: {selectedImport.extractedTargets.join(', ') || '127.0.0.1'}
                  </div>
                </div>
                <div className="text-right text-[10px] text-slate-400">
                  SHA-256: <code className="text-cyan-400">{selectedImport.sha256.slice(0, 16)}...</code>
                </div>
              </div>

              {selectedImport.errors.length > 0 && (
                <div className="bg-amber-950/30 border border-amber-700/50 p-2.5 rounded text-amber-300 text-[11px] space-y-1">
                  <div className="font-bold flex items-center space-x-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Parser Warnings / Diagnostics:</span>
                  </div>
                  {selectedImport.errors.map((err, i) => (
                    <div key={i}>• {err}</div>
                  ))}
                </div>
              )}

              <div>
                <span className="text-[11px] font-bold text-slate-300 uppercase block mb-1">
                  Normalized Findings from this Import ({selectedImport.findings.length}):
                </span>
                <div className="space-y-1 max-h-[300px] overflow-y-auto">
                  {selectedImport.findings.map(f => (
                    <div
                      key={f.findingId}
                      className="bg-[#080c14] border border-slate-800 p-2 rounded flex items-center justify-between text-xs"
                    >
                      <div className="flex items-center space-x-2 truncate">
                        <span
                          className={`text-[9.5px] px-1.5 py-0.5 rounded font-bold shrink-0 ${
                            f.severity === 'CRITICAL' ? 'bg-red-950 text-red-400' : f.severity === 'HIGH' ? 'bg-amber-950 text-amber-400' : 'bg-blue-950 text-blue-400'
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="text-slate-200 font-semibold truncate">{f.title}</span>
                      </div>
                      <div className="flex items-center space-x-2 shrink-0 text-[11px]">
                        <span className="text-cyan-400">{f.host}{f.port ? `:${f.port}` : ''}</span>
                        <span className="text-slate-400">[{f.validationStatus}]</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. ARTIFACTS SUBTAB */}
      {activeSubTab === 'artifacts' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5 font-mono text-xs">
          {/* Artifacts List (4 Cols) */}
          <div className="lg:col-span-4 bg-[#0e1422] border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="text-[11px] font-bold text-slate-300 uppercase tracking-wider">Captured Log & Ingest Artifacts</div>
            <div className="space-y-1.5 max-h-[520px] overflow-y-auto">
              {allArtifacts.length === 0 ? (
                <div className="p-6 text-center text-slate-500">No output artifacts captured yet.</div>
              ) : (
                allArtifacts.map(art => {
                  const isSelected = selectedArtifact?.filename === art.filename;
                  return (
                    <div
                      key={art.filename}
                      onClick={() => setSelectedArtifact(art)}
                      className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-slate-800/90 border-cyan-500/50 shadow-sm'
                          : 'bg-[#080c14] border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center space-x-2 text-slate-200 font-semibold truncate">
                        <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                        <span className="truncate text-xs">{art.filename}</span>
                      </div>
                      <div className="text-[9.5px] text-slate-500 mt-0.5 flex justify-between">
                        <span>{art.contentType}</span>
                        <span>{art.sizeBytes} bytes</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Artifact Log Viewer (8 Cols) */}
          <div className="lg:col-span-8 bg-[#0e1422] border border-slate-800 rounded-lg p-3.5 space-y-2.5">
            {selectedArtifact ? (
              <div className="space-y-2.5">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <div>
                    <div className="text-xs font-bold text-slate-200">{selectedArtifact.filename}</div>
                    <div className="text-[9.5px] text-slate-500 mt-0.5">
                      SHA-256: <code className="text-cyan-400">{selectedArtifact.sha256}</code>
                    </div>
                  </div>
                </div>

                <div className="bg-[#05080f] border border-slate-900 rounded p-3 text-[11px] font-mono text-slate-300 max-h-[460px] overflow-y-auto whitespace-pre-wrap leading-relaxed">
                  {selectedArtifact.content}
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-slate-500">Select an artifact to view cryptographic log content.</div>
            )}
          </div>
        </div>
      )}

      {/* 4. RISK MATRIX SUBTAB */}
      {activeSubTab === 'risk' && (
        <div className="bg-[#0e1422] border border-slate-800 rounded-lg p-4 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <div className="text-sm font-bold text-slate-100">Crown-Jewel & Asset Vulnerability Risk Posture</div>
              <div className="text-[11px] text-slate-400">Aggregated mathematically from {allFindings.length} confirmed & ingested findings</div>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
            <div className="bg-[#080c14] border border-red-900/40 p-3 rounded">
              <div className="text-xl font-bold text-red-400">{allFindings.filter(f => f.severity === 'CRITICAL').length}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">Critical Severity</div>
            </div>
            <div className="bg-[#080c14] border border-amber-900/40 p-3 rounded">
              <div className="text-xl font-bold text-amber-400">{allFindings.filter(f => f.severity === 'HIGH').length}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">High Severity</div>
            </div>
            <div className="bg-[#080c14] border border-yellow-900/40 p-3 rounded">
              <div className="text-xl font-bold text-yellow-400">{allFindings.filter(f => f.severity === 'MEDIUM').length}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">Medium Severity</div>
            </div>
            <div className="bg-[#080c14] border border-blue-900/40 p-3 rounded">
              <div className="text-xl font-bold text-blue-400">{allFindings.filter(f => f.severity === 'LOW' || f.severity === 'INFO').length}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">Low & Info Exposure</div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: IMPORT RESULTS DIALOG */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 font-mono text-xs">
          <div className="bg-[#0d121e] border border-slate-700 rounded-xl shadow-2xl max-w-2xl w-full p-4 space-y-3.5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center space-x-2">
                <Upload className="w-4 h-4 text-cyan-400" />
                <h3 className="font-bold text-sm text-slate-100">Import External Assessment Results</h3>
              </div>
              <button
                onClick={() => setShowImportModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              {/* Format Selection & Quick Samples */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-[10.5px] text-slate-400 uppercase font-semibold">Parser Target Format</label>
                  <select
                    value={selectedFormat}
                    onChange={e => setSelectedFormat(e.target.value as ExternalToolFormat | 'AUTO')}
                    className="w-full bg-[#080c14] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200"
                  >
                    <option value="AUTO">Auto-Detect Format (Recommended)</option>
                    <option value="NMAP_XML">Nmap XML (.xml)</option>
                    <option value="NMAP_JSON">Nmap JSON (.json)</option>
                    <option value="BURP_XML">PortSwigger Burp Suite XML</option>
                    <option value="BURP_JSON">PortSwigger Burp Suite JSON</option>
                    <option value="NESSUS_XML">Tenable Nessus (.nessus XML)</option>
                    <option value="NUCLEI_JSONL">ProjectDiscovery Nuclei (.jsonl)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[10.5px] text-slate-400 uppercase font-semibold">Load Verified Test Sample</label>
                  <div className="flex flex-wrap gap-1.5 pt-0.5">
                    <button
                      onClick={() => handleLoadSample('NMAP')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[10px]"
                    >
                      Nmap XML
                    </button>
                    <button
                      onClick={() => handleLoadSample('BURP')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-amber-300 rounded text-[10px]"
                    >
                      Burp XML
                    </button>
                    <button
                      onClick={() => handleLoadSample('NESSUS')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-blue-300 rounded text-[10px]"
                    >
                      Nessus XML
                    </button>
                    <button
                      onClick={() => handleLoadSample('NUCLEI')}
                      className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-purple-300 rounded text-[10px]"
                    >
                      Nuclei JSONL
                    </button>
                  </div>
                </div>
              </div>

              {/* File Upload Selector */}
              <div className="space-y-1">
                <label className="text-[10.5px] text-slate-400 uppercase font-semibold">Select File from Disk</label>
                <div className="flex items-center space-x-2">
                  <input
                    type="file"
                    accept=".xml,.nessus,.json,.jsonl,.txt"
                    onChange={handleFileUpload}
                    className="block w-full text-xs text-slate-400 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-300 hover:file:bg-slate-700"
                  />
                  <input
                    type="text"
                    value={importFilename}
                    onChange={e => setImportFilename(e.target.value)}
                    placeholder="Filename"
                    className="w-1/3 bg-[#080c14] border border-slate-700 rounded px-2 py-1 text-xs text-slate-200"
                  />
                </div>
              </div>

              {/* Raw Content Area */}
              <div className="space-y-1">
                <div className="flex items-center justify-between text-[10.5px] text-slate-400 uppercase">
                  <span>File Content Preview / Paste</span>
                  <span>{Buffer.byteLength(importContent, 'utf8')} bytes</span>
                </div>
                <textarea
                  rows={8}
                  value={importContent}
                  onChange={e => setImportContent(e.target.value)}
                  placeholder="Paste XML or JSON output here, or select a file above..."
                  className="w-full bg-[#060910] border border-slate-800 rounded p-2.5 text-xs text-cyan-200 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              {/* Feedback Alert */}
              {importFeedback && (
                <div
                  className={`p-2.5 rounded text-xs flex items-start space-x-2 ${
                    importFeedback.success
                      ? 'bg-emerald-950/70 border border-emerald-700/60 text-emerald-300'
                      : 'bg-red-950/70 border border-red-700/60 text-red-300'
                  }`}
                >
                  {importFeedback.success ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <div>{importFeedback.message}</div>
                    {importFeedback.record && (
                      <div className="text-[10px] text-slate-400 mt-1">
                        Import ID: {importFeedback.record.importId} • Evidence: {importFeedback.record.evidenceId} • Audit: {importFeedback.record.auditBlockId}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[10px] text-slate-500">
                Data is validated, scope-checked against active ROE, and sealed in blockchain ledger.
              </span>
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-semibold text-xs"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={handleExecuteImport}
                  disabled={importing || !importContent.trim()}
                  className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white rounded font-bold text-xs flex items-center space-x-1.5 shadow"
                >
                  {importing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                  <span>{importing ? 'Validating & Ingesting...' : 'Validate & Ingest Results'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
