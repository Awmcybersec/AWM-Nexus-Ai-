/**
 * AWM NEXUS — Human Pentester Operating System & Execution Pipeline
 * Full-featured Kali/Enterprise SOC-style pentest workspace with dual ASCL & Visual UI synchronization.
 */

import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { PentestSidebar } from './components/PentestSidebar';
import { OverviewView } from './components/OverviewView';
import { TerminalView } from './components/TerminalView';
import { CommandPreviewPanel } from './components/CommandPreviewPanel';
import { ToolCatalogView } from './components/ToolCatalogView';
import { ScopeManagerView } from './components/ScopeManagerView';
import { JobsMonitorView } from './components/JobsMonitorView';
import { HitlGateView } from './components/HitlGateView';
import { FindingsArtifactsView } from './components/FindingsArtifactsView';
import { EvidenceLockerView } from './components/EvidenceLockerView';
import { AttackSurfaceView } from './components/AttackSurfaceView';
import { DefensiveTelemetryView } from './components/DefensiveTelemetryView';
import { ReportGeneratorView } from './components/ReportGeneratorView';
import { DigitalTwinView } from './components/DigitalTwinView';
import { ThreatDetectionView } from './components/ThreatDetectionView';
import { ClosedLoopView } from './components/ClosedLoopView';
import { AgentFleetView } from './components/AgentFleetView';
import { SystemSettingsView } from './components/SystemSettingsView';

import { toolRegistry } from './engine/toolRegistry';
import { scopeEngine } from './engine/scopeEngine';
import { auditLedger } from './engine/auditLedger';
import { policyAndHitlEngine } from './engine/policyAndHitlEngine';
import { sandboxExecutionManager } from './engine/sandboxExecution';
import { detectRealBinaries } from './engine/binaryDetector';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [installedCount, setInstalledCount] = useState<number>(0);
  const [totalTools, setTotalTools] = useState<number>(toolRegistry.getAllTools().length);
  const [auditValid, setAuditValid] = useState<boolean>(true);
  const [pendingHitl, setPendingHitl] = useState<number>(0);
  const [activeJobs, setActiveJobs] = useState<number>(0);
  const [completedJobs, setCompletedJobs] = useState<number>(0);
  const [findingsCount, setFindingsCount] = useState<number>(0);
  const [evidenceCount, setEvidenceCount] = useState<number>(0);

  // Selected tool/target to pass into Command Preview when navigating from catalog/scope
  const [previewToolId, setPreviewToolId] = useState<string>('');
  const [previewTarget, setPreviewTarget] = useState<string>('');
  const [activeTerminalJobId, setActiveTerminalJobId] = useState<string>('');

  const engagement = scopeEngine.getAllEngagements()[0];

  useEffect(() => {
    // Initial verification of real system binaries
    detectRealBinaries().then(res => {
      setInstalledCount(res.installedCount);
      setTotalTools(toolRegistry.getAllTools().length);
    });

    const updateMetrics = () => {
      const allTools = toolRegistry.getAllTools();
      const inst = allTools.filter(t => t.availabilityStatus === 'INSTALLED').length;
      setInstalledCount(inst);
      setTotalTools(allTools.length);

      const auditCheck = auditLedger.verifyChainIntegrity();
      setAuditValid(auditCheck.isValid);

      const pending = policyAndHitlEngine.getPendingRequests().length;
      setPendingHitl(pending);

      const allJobsList = sandboxExecutionManager.getAllJobs();
      const runningJobs = allJobsList.filter(j => j.status === 'RUNNING' || j.status === 'QUEUED').length;
      const completed = allJobsList.filter(j => j.status === 'COMPLETED').length;
      setActiveJobs(runningJobs);
      setCompletedJobs(completed);

      const allFinds = allJobsList.flatMap(j => j.findings).length;
      setFindingsCount(allFinds);

      const allEv = allJobsList.filter(j => !!j.evidenceId).length;
      setEvidenceCount(allEv);
    };

    updateMetrics();
    const interval = setInterval(updateMetrics, 1200);
    return () => clearInterval(interval);
  }, []);

  const handleLaunchPreview = (toolId: string, target?: string) => {
    setPreviewToolId(toolId);
    if (target) setPreviewTarget(target);
    setActiveTab('preview');
  };

  const handleJobCreated = (jobId: string) => {
    setActiveTerminalJobId(jobId);
    setActiveTab('terminal');
  };

  return (
    <div className="min-h-screen bg-[#070a10] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        installedToolsCount={installedCount}
        totalToolsCount={totalTools}
        auditValid={auditValid}
        pendingHitlCount={pendingHitl}
        activeJobsCount={activeJobs}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* Persistent Unified 17-Area Operational Sidebar */}
        <PentestSidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          installedToolsCount={installedCount}
          totalToolsCount={totalTools}
          auditValid={auditValid}
          pendingHitlCount={pendingHitl}
          activeJobsCount={activeJobs}
          completedJobsCount={completedJobs}
          findingsCount={findingsCount}
          evidenceCount={evidenceCount}
          engagementCode={engagement?.code || 'ENG-2026-ALPHA'}
          tenantId={engagement?.tenantId || 'TENANT-AWM-01'}
        />

        {/* Main Content Workspace Canvas */}
        <main className="flex-1 p-3 md:p-4 overflow-y-auto max-w-[1600px] w-full mx-auto">
          {activeTab === 'overview' && <OverviewView onNavigate={setActiveTab} />}
          {activeTab === 'digital-twin' && <DigitalTwinView />}
          {activeTab === 'surface' && <AttackSurfaceView />}
          {activeTab === 'preview' && (
            <CommandPreviewPanel
              initialToolId={previewToolId}
              initialTarget={previewTarget}
              onJobCreated={handleJobCreated}
            />
          )}
          {activeTab === 'scope' && (
            <ScopeManagerView onSelectTarget={tgt => handleLaunchPreview('curl-probe', tgt)} />
          )}
          {activeTab === 'catalog' && (
            <ToolCatalogView onJobStarted={handleJobCreated} onSelectTool={handleLaunchPreview} />
          )}
          {activeTab === 'terminal' && <TerminalView initialJobId={activeTerminalJobId} />}
          {activeTab === 'defensive' && <DefensiveTelemetryView />}
          {activeTab === 'threat-detection' && <ThreatDetectionView />}
          {activeTab === 'findings' && <FindingsArtifactsView />}
          {activeTab === 'closed-loop' && <ClosedLoopView />}
          {activeTab === 'hitl' && <HitlGateView />}
          {activeTab === 'ai-fleet' && <AgentFleetView />}
          {activeTab === 'jobs' && <JobsMonitorView />}
          {activeTab === 'evidence' && <EvidenceLockerView />}
          {activeTab === 'report' && <ReportGeneratorView />}
          {activeTab === 'settings' && <SystemSettingsView />}
        </main>
      </div>
    </div>
  );
}
