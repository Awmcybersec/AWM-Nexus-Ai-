#!/usr/bin/env node
/**
 * AWM NEXUS — Remote Kali Linux Security Execution Agent (Node.js version)
 * Zero external npm dependencies (uses node:child_process, node:os, node:http/https).
 */

import { spawn } from 'node:child_process';
import os from 'node:os';

const PERMITTED_BINARIES = new Set([
  'nmap', 'nuclei', 'nikto', 'ffuf', 'gobuster', 'masscan',
  'whatweb', 'subfinder', 'amass', 'dnsrecon', 'dig', 'whois',
  'testssl', 'curl', 'openssl', 'ping', 'hashcat', 'john', 'msfconsole'
]);

const args = process.argv.slice(2);
function getArg(flag, def = '') {
  const idx = args.indexOf(flag);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : def;
}

const serverUrl = getArg('--server', 'http://127.0.0.1:3000').replace(/\/$/, '');
const token = getArg('--token', process.env.AWM_AGENT_TOKEN || 'nexus-kali-token-live-2026');
const agentName = getArg('--name', 'Kali Node Agent');

console.log(`[*] Starting AWM Nexus Node Execution Agent...`);
console.log(`[*] Server:   ${serverUrl}`);
console.log(`[*] Hostname: ${os.hostname()} (${os.type()} ${os.release()} ${os.arch()})`);

async function api(path, method = 'GET', body = null) {
  const res = await fetch(`${serverUrl}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`
    },
    body: body ? JSON.stringify(body) : undefined
  });
  return res.json();
}

async function run() {
  const regResp = await api('/api/agent/register', 'POST', {
    name: agentName,
    hostname: os.hostname(),
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    installedTools: Array.from(PERMITTED_BINARIES)
  });

  const agentId = regResp.data?.id || regResp.id || 'kali-node-agent';
  console.log(`[+] Agent registered with ID: ${agentId}`);

  setInterval(() => {
    api('/api/agent/heartbeat', 'POST', { agentId }).catch(() => {});
  }, 15000);

  console.log(`[*] Polling for jobs...`);
  while (true) {
    try {
      const pollRes = await api(`/api/agent/poll-jobs?agentId=${agentId}`, 'GET');
      const job = pollRes.data;

      if (job && job.jobId) {
        console.log(`[+] Executing job ${job.jobId}: ${job.binaryName} ${job.parameters?.join(' ')}`);
        const startTime = Date.now();
        let stdout = '';
        let stderr = '';

        if (!PERMITTED_BINARIES.has(job.binaryName)) {
          await api('/api/agent/submit-result', 'POST', {
            jobId: job.jobId,
            exitCode: 126,
            stdout: '',
            stderr: `Binary ${job.binaryName} is not permitted.`,
            executionTimeMs: 0,
            completedAt: new Date().toISOString()
          });
          continue;
        }

        await new Promise(resolve => {
          const proc = spawn(job.binaryName, job.parameters || [], {
            shell: false,
            env: { ...process.env, ...job.environment }
          });

          proc.stdout.on('data', chunk => {
            const str = chunk.toString();
            stdout += str;
            api('/api/agent/submit-chunk', 'POST', { jobId: job.jobId, type: 'stdout', chunk: str }).catch(() => {});
          });

          proc.stderr.on('data', chunk => {
            const str = chunk.toString();
            stderr += str;
            api('/api/agent/submit-chunk', 'POST', { jobId: job.jobId, type: 'stderr', chunk: str }).catch(() => {});
          });

          proc.on('close', async code => {
            await api('/api/agent/submit-result', 'POST', {
              jobId: job.jobId,
              exitCode: code ?? 0,
              stdout,
              stderr,
              executionTimeMs: Date.now() - startTime,
              completedAt: new Date().toISOString()
            });
            console.log(`[+] Finished job ${job.jobId} (code: ${code})`);
            resolve();
          });

          proc.on('error', async err => {
            await api('/api/agent/submit-result', 'POST', {
              jobId: job.jobId,
              exitCode: 1,
              stdout,
              stderr: String(err),
              executionTimeMs: Date.now() - startTime,
              completedAt: new Date().toISOString()
            });
            resolve();
          });
        });
      }
    } catch {
      // transient poll error
    }
    await new Promise(r => setTimeout(r, 2000));
  }
}

run().catch(console.error);
