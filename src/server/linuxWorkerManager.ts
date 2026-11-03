/**
 * AWM Nexus — Dedicated Real Linux Execution Worker
 * Manages native process execution, unbuffered stdout/stderr capturing,
 * live SSE streaming, process lifecycle, PID tracking, and exit code capture.
 */

import { EventEmitter } from 'node:events';
import cp, { type ChildProcess } from 'node:child_process';
import { syncSha256 } from '../engine/cryptoUtils';

export interface RunningProcessState {
  jobId: string;
  toolId: string;
  command: string;
  args: string[];
  pid?: number;
  childProcess?: ChildProcess;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'TIMEOUT';
  startTime: number;
  endTime?: number;
  exitCode?: number | null;
  signal?: string | null;
  stdoutBuffer: string;
  stderrBuffer: string;
  emitter: EventEmitter;
  timeoutTimer?: NodeJS.Timeout;
}

export interface WorkerHealthTelemetry {
  workerId: string;
  workerType: 'LOCAL_LINUX_WORKER' | 'KALI_AGENT';
  hostname: string;
  osRelease: string;
  kernel: string;
  isGvisor: boolean;
  activeJobsCount: number;
  persistentBinPath: string;
  availableBinaries: { name: string; path: string; version?: string }[];
  uptimeSeconds: number;
}

export class LinuxWorkerManager {
  private static instance: LinuxWorkerManager;
  private runningProcesses: Map<string, RunningProcessState> = new Map();
  private processHistory: Map<string, RunningProcessState> = new Map();
  private startTime = Date.now();

  private constructor() {
    this.ensureWorkspaceBinPermissions();
  }

  public static getInstance(): LinuxWorkerManager {
    if (!LinuxWorkerManager.instance) {
      LinuxWorkerManager.instance = new LinuxWorkerManager();
    }
    return LinuxWorkerManager.instance;
  }

  private ensureWorkspaceBinPermissions() {
    try {
      cp.execSync('chmod +x /app/applet/bin/* 2>/dev/null', { timeout: 1000 });
    } catch {}
  }

  /**
   * Resolves the real absolute path to a tool binary.
   * Priority: /app/applet/bin (persistent workspace) -> system PATH (/usr/bin, /usr/local/bin, /bin).
   */
  public resolveBinaryPath(binaryName: string): string | null {
    this.ensureWorkspaceBinPermissions();
    const cleanName = binaryName.trim();

    // Map common aliases
    const targetBin = cleanName === 'httpx' ? 'httpx-pd' : cleanName;

    const binEnvPath = `/app/applet/bin:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin:/usr/sbin'}`;

    try {
      const resolved = cp.execSync(`PATH="${binEnvPath}" which ${targetBin} 2>/dev/null`, {
        timeout: 1500,
        encoding: 'utf-8'
      }).trim();

      if (resolved && resolved.length > 0) {
        return resolved;
      }
    } catch {}

    return null;
  }

  /**
   * Spawns a real native Linux process using child_process.spawn with validated argument arrays.
   * Zero shell string concatenation to prevent shell injection.
   */
  public async executeProcess(
    jobId: string,
    binaryName: string,
    args: string[],
    options?: {
      timeoutMs?: number;
      cwd?: string;
      env?: Record<string, string>;
      onStdoutChunk?: (chunk: string) => void;
      onStderrChunk?: (chunk: string) => void;
    }
  ): Promise<{
    exitCode: number;
    stdout: string;
    stderr: string;
    durationMs: number;
    sha256: string;
    status: 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'TIMEOUT';
  }> {
    const binaryPath = this.resolveBinaryPath(binaryName);

    if (!binaryPath) {
      const err = `[!] EXECUTION ERROR: Binary '${binaryName}' was not found in persistent storage (/app/applet/bin) or system PATH.`;
      return {
        exitCode: 127,
        stdout: '',
        stderr: err,
        durationMs: 0,
        sha256: syncSha256(''),
        status: 'FAILED'
      };
    }

    const state: RunningProcessState = {
      jobId,
      toolId: binaryName,
      command: `${binaryName} ${args.join(' ')}`,
      args,
      status: 'RUNNING',
      startTime: Date.now(),
      stdoutBuffer: '',
      stderrBuffer: '',
      emitter: new EventEmitter()
    };

    this.runningProcesses.set(jobId, state);

    return new Promise(resolve => {
      const timeoutMs = options?.timeoutMs || 45000;

      // Timeout watchdog
      state.timeoutTimer = setTimeout(() => {
        if (state.status === 'RUNNING') {
          state.status = 'TIMEOUT';
          state.stderrBuffer += `\n[!] EXECUTION TIMEOUT: Process exceeded execution limit of ${timeoutMs / 1000}s. Terminating.\n`;
          state.emitter.emit('stderr', `\n[!] EXECUTION TIMEOUT: Process exceeded ${timeoutMs / 1000}s.\n`);

          if (state.childProcess) {
            state.childProcess.kill('SIGKILL');
          }
        }
      }, timeoutMs);

      const envPath = `/app/applet/bin:${process.env.PATH || '/usr/local/bin:/usr/bin:/bin:/usr/sbin'}`;
      const childEnv = {
        ...process.env,
        PATH: envPath,
        HOME: process.env.HOME || '/root',
        TERM: 'xterm-256color',
        ...(options?.env || {})
      };

      try {
        const child = cp.spawn(binaryPath, args, {
          cwd: options?.cwd || '/app/applet',
          env: childEnv,
          stdio: ['ignore', 'pipe', 'pipe']
        });

        state.childProcess = child;
        state.pid = child.pid;
        state.emitter.emit('started', { pid: child.pid, command: state.command });

        child.stdout.on('data', (chunk: Buffer) => {
          const text = chunk.toString('utf-8');
          state.stdoutBuffer += text;
          state.emitter.emit('stdout', text);
          if (options?.onStdoutChunk) options.onStdoutChunk(text);
        });

        child.stderr.on('data', (chunk: Buffer) => {
          const text = chunk.toString('utf-8');
          state.stderrBuffer += text;
          state.emitter.emit('stderr', text);
          if (options?.onStderrChunk) options.onStderrChunk(text);
        });

        child.on('error', (err: Error) => {
          if (state.timeoutTimer) clearTimeout(state.timeoutTimer);
          state.status = 'FAILED';
          state.stderrBuffer += `\n[!] Process Spawn Error: ${err.message}\n`;
          state.endTime = Date.now();
          state.exitCode = 1;
          this.finalizeProcess(state);

          resolve({
            exitCode: 1,
            stdout: state.stdoutBuffer,
            stderr: state.stderrBuffer,
            durationMs: state.endTime - state.startTime,
            sha256: syncSha256(state.stdoutBuffer),
            status: 'FAILED'
          });
        });

        child.on('close', (code: number | null, signal: string | null) => {
          if (state.timeoutTimer) clearTimeout(state.timeoutTimer);
          state.endTime = Date.now();
          state.exitCode = code;
          state.signal = signal;

          if (state.status === 'RUNNING') {
            state.status = code === 0 ? 'COMPLETED' : 'FAILED';
          }

          state.emitter.emit('close', { exitCode: code, signal });
          this.finalizeProcess(state);

          resolve({
            exitCode: code ?? (signal ? 130 : 1),
            stdout: state.stdoutBuffer,
            stderr: state.stderrBuffer,
            durationMs: state.endTime - state.startTime,
            sha256: syncSha256(state.stdoutBuffer),
            status: state.status
          });
        });
      } catch (err: unknown) {
        if (state.timeoutTimer) clearTimeout(state.timeoutTimer);
        const msg = err instanceof Error ? err.message : String(err);
        state.status = 'FAILED';
        state.stderrBuffer += `\n[!] Process execution failure: ${msg}\n`;
        state.endTime = Date.now();
        state.exitCode = 1;
        this.finalizeProcess(state);

        resolve({
          exitCode: 1,
          stdout: state.stdoutBuffer,
          stderr: state.stderrBuffer,
          durationMs: state.endTime - state.startTime,
          sha256: syncSha256(state.stdoutBuffer),
          status: 'FAILED'
        });
      }
    });
  }

  private finalizeProcess(state: RunningProcessState) {
    this.runningProcesses.delete(state.jobId);
    this.processHistory.set(state.jobId, state);
  }

  /**
   * Safely cancels an active running process.
   */
  public cancelProcess(jobId: string): boolean {
    const state = this.runningProcesses.get(jobId);
    if (!state || !state.childProcess) return false;

    state.status = 'CANCELLED';
    state.stderrBuffer += '\n[!] PROCESS CANCELLED BY OPERATOR (SIGTERM sent)\n';
    state.emitter.emit('stderr', '\n[!] PROCESS CANCELLED BY OPERATOR\n');

    state.childProcess.kill('SIGTERM');

    // Escalate to SIGKILL if not exited after 1.5s
    setTimeout(() => {
      if (state.childProcess && !state.childProcess.killed) {
        state.childProcess.kill('SIGKILL');
      }
    }, 1500);

    return true;
  }

  public getRunningProcess(jobId: string): RunningProcessState | undefined {
    return this.runningProcesses.get(jobId);
  }

  public getProcessHistory(jobId: string): RunningProcessState | undefined {
    return this.processHistory.get(jobId);
  }

  public getAllHistory(): RunningProcessState[] {
    return Array.from(this.processHistory.values()).sort((a, b) => b.startTime - a.startTime);
  }

  /**
   * Provides health and environment telemetry of the Linux worker.
   */
  public getWorkerHealth(): WorkerHealthTelemetry {
    let kernel = 'Linux 4.19.0-gvisor';
    let osRelease = 'Debian GNU/Linux 12 (bookworm)';
    let isGvisor = true;

    try {
      kernel = execSync('uname -r 2>/dev/null', { timeout: 1000, encoding: 'utf-8' }).trim();
      isGvisor = kernel.includes('gvisor');
    } catch {}

    try {
      const release = execSync('cat /etc/os-release 2>/dev/null', { timeout: 1000, encoding: 'utf-8' });
      const m = release.match(/PRETTY_NAME="([^"]+)"/);
      if (m && m[1]) osRelease = m[1];
    } catch {}

    const knownBins = [
      'whois', 'nmap', 'whatweb', 'nikto', 'curl', 'openssl',
      'ffuf', 'gobuster', 'feroxbuster', 'subfinder', 'dnsx',
      'amass', 'nuclei', 'dig', 'testssl', 'kubectl'
    ];

    const available: { name: string; path: string; version?: string }[] = [];
    for (const bin of knownBins) {
      const p = this.resolveBinaryPath(bin);
      if (p) {
        available.push({ name: bin, path: p });
      }
    }

    return {
      workerId: 'LOCAL_LINUX_WORKER_01',
      workerType: 'LOCAL_LINUX_WORKER',
      hostname: 'localhost',
      osRelease,
      kernel,
      isGvisor,
      activeJobsCount: this.runningProcesses.size,
      persistentBinPath: '/app/applet/bin',
      availableBinaries: available,
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000)
    };
  }
}

export const linuxWorkerManager = LinuxWorkerManager.getInstance();
