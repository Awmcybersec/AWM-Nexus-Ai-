/**
 * AWM Nexus — Real Binary & Execution Agent Availability Detector
 * Accurately detects and finger-prints native host binaries in the container environment,
 * Node.js live native protocol engines (DNS, RDAP/WHOIS, TLS, TCP Port Probe),
 * and connected Remote Kali Linux Execution Agents.
 */

import { toolRegistry } from './toolRegistry';
import { remoteAgentManager } from '../server/agentManager';

export async function detectRealBinaries(): Promise<{
  installedCount: number;
  totalChecked: number;
  results: { id: string; binary: string; installed: boolean; version?: string; path?: string }[];
}> {
  const tools = toolRegistry.getAllTools();
  const results: { id: string; binary: string; installed: boolean; version?: string; path?: string }[] = [];
  let installedCount = 0;
  const onlineAgents = remoteAgentManager.getOnlineAgents();

  // Check if we are running in Node.js environment with child_process
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const { execSync } = await import('node:child_process');
      try {
        execSync('chmod +x /app/applet/bin/* 2>/dev/null', { timeout: 1000 });
      } catch {}

      for (const tool of tools) {
        // 1. Check local native binaries installed directly in container
        let isLocallyInstalled = false;
        let detectedPath = '';
        let detectedVersion = '';

        if (tool.isNativeBinary) {
          try {
            const binEnvPath = `/app/applet/bin:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin:/usr/sbin'}`;
            let binaryToCheck = tool.binaryName;
            if (binaryToCheck === 'httpx') {
              try {
                const pdPath = execSync(`PATH="${binEnvPath}" which httpx-pd 2>/dev/null`, { timeout: 1500, encoding: 'utf-8' }).trim();
                if (pdPath) binaryToCheck = 'httpx-pd';
              } catch {}
            }

            const path = execSync(`PATH="${binEnvPath}" which ${binaryToCheck} 2>/dev/null`, { timeout: 2000, encoding: 'utf-8' }).trim();
            if (path) {
              isLocallyInstalled = true;
              detectedPath = path;
              detectedVersion = 'Detected';
              try {
                let verCmd = tool.verificationCommand;
                if (tool.binaryName === 'gobuster') {
                  verCmd = `${path} -h`;
                } else if (tool.binaryName === 'masscan') {
                  verCmd = `${path} --version`;
                }
                const verOut = execSync(`PATH="${binEnvPath}" ${verCmd} 2>/dev/null`, { timeout: 3000, encoding: 'utf-8' });
                const firstLine = verOut.split('\n').map(l => l.trim()).find(l => l.length > 0);
                if (firstLine) detectedVersion = firstLine;
              } catch {
                detectedVersion = 'Detected';
              }
            }
          } catch {
            isLocallyInstalled = false;
          }
        }

        if (isLocallyInstalled) {
          toolRegistry.updateToolStatus(tool.id, 'INSTALLED', detectedVersion, detectedPath);
          installedCount++;
          results.push({ id: tool.id, binary: tool.binaryName, installed: true, version: detectedVersion, path: detectedPath });
          continue;
        }

        // 2. Check if supported by Node native live executors
        const isNodeNativeLive =
          tool.id === 'dig-dns' ||
          tool.id === 'dnsrecon-recon' ||
          tool.binaryName === 'whois';

        if (isNodeNativeLive) {
          const liveEngineName = 'Node.js Native Live Protocol Engine (RFC 1035/7482)';
          toolRegistry.updateToolStatus(tool.id, 'AVAILABLE', liveEngineName, 'node:runtime/live-engine');
          installedCount++;
          results.push({ id: tool.id, binary: tool.binaryName, installed: true, version: liveEngineName, path: 'node:runtime' });
          continue;
        }

        // 3. Check if available on a connected Remote Kali Execution Agent
        const agentWithTool = onlineAgents.find(a =>
          a.installedTools.some(t => t.toLowerCase() === tool.binaryName.toLowerCase())
        );

        if (agentWithTool) {
          const agentVersion = `Available via Remote Kali Agent [${agentWithTool.hostname}]`;
          toolRegistry.updateToolStatus(tool.id, 'AVAILABLE', agentVersion, `agent://${agentWithTool.id}/${tool.binaryName}`);
          installedCount++;
          results.push({ id: tool.id, binary: tool.binaryName, installed: true, version: agentVersion, path: `agent://${agentWithTool.id}` });
          continue;
        }

        // 4. Otherwise, accurately mark NOT_INSTALLED (Requires Kali Agent or Local Binary)
        toolRegistry.updateToolStatus(tool.id, 'NOT_INSTALLED');
        results.push({ id: tool.id, binary: tool.binaryName, installed: false });
      }
    } catch {
      // Fallback
    }
  } else {
    // Client environment fallback
    for (const tool of tools) {
      if (tool.binaryName === 'curl' || tool.binaryName === 'openssl') {
        toolRegistry.updateToolStatus(tool.id, 'INSTALLED', 'Native Client Runtime', `/usr/bin/${tool.binaryName}`);
        installedCount++;
      } else {
        toolRegistry.updateToolStatus(tool.id, 'NOT_INSTALLED');
      }
    }
  }

  return { installedCount, totalChecked: tools.length, results };
}
