#!/usr/bin/env python3
"""
AWM NEXUS — Remote Kali Linux Security Execution Agent
Author: AWM Nexus Core Architecture Team
Description: Connects to AWM Nexus platform, polls authorized pentest jobs,
             executes verified security binaries locally, and streams evidence back securely.
Zero dependencies beyond Python 3 standard library.
"""

import sys
import os
import time
import json
import socket
import platform
import subprocess
import argparse
import urllib.request
import urllib.error

# Whitelist of permissible security tool binaries
PERMITTED_BINARIES = {
    'nmap', 'nuclei', 'nikto', 'ffuf', 'gobuster', 'masscan',
    'whatweb', 'subfinder', 'amass', 'dnsrecon', 'dig', 'whois',
    'testssl', 'curl', 'openssl', 'ping', 'hashcat', 'john', 'msfconsole'
}

def detect_installed_tools():
    installed = []
    for binary in PERMITTED_BINARIES:
        try:
            res = subprocess.run(['which', binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode == 0:
                installed.append(binary)
        except Exception:
            pass
    return installed

def http_post(url, data, token):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'AWM-Nexus-Kali-Agent/4.8'
        }
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8'))

def http_get(url, token):
    req = urllib.request.Request(
        url,
        headers={
            'Accept': 'application/json',
            'Authorization': f'Bearer {token}',
            'User-Agent': 'AWM-Nexus-Kali-Agent/4.8'
        }
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode('utf-8'))

def main():
    parser = argparse.ArgumentParser(description='AWM Nexus Remote Kali Execution Agent')
    parser.add_argument('--server', default='http://127.0.0.1:3000', help='AWM Nexus server URL')
    parser.add_argument('--token', required=True, help='Agent authorization token from AWM Nexus Settings')
    parser.add_argument('--name', default='Kali Workstation Agent', help='Display name for this agent')
    args = parser.parse_args()

    server_url = args.server.rstrip('/')
    token = args.token
    installed_tools = detect_installed_tools()

    print(f"[*] Starting AWM Nexus Kali Execution Agent...")
    print(f"[*] Target Server: {server_url}")
    print(f"[*] Hostname:      {socket.gethostname()}")
    print(f"[*] OS:            {platform.system()} {platform.release()}")
    print(f"[*] Detected {len(installed_tools)} installed security tools: {', '.join(installed_tools)}")

    # 1. Register with Server
    reg_url = f"{server_url}/api/agent/register"
    reg_data = {
        'name': args.name,
        'hostname': socket.gethostname(),
        'os': f"{platform.system()} {platform.release()} ({platform.machine()})",
        'installedTools': installed_tools
    }

    try:
        reg_resp = http_post(reg_url, reg_data, token)
        agent_id = reg_resp.get('data', {}).get('id') or reg_resp.get('id', 'kali-agent')
        print(f"[+] Agent successfully registered! Agent ID: {agent_id}")
    except Exception as e:
        print(f"[!] Registration failed: {e}")
        sys.exit(1)

    # 2. Main Poll Loop
    poll_url = f"{server_url}/api/agent/poll-jobs?agentId={agent_id}"
    heartbeat_url = f"{server_url}/api/agent/heartbeat"
    submit_url = f"{server_url}/api/agent/submit-result"
    chunk_url = f"{server_url}/api/agent/submit-chunk"

    last_heartbeat = time.time()
    print("[*] Polling for assigned pentest jobs (Press Ctrl+C to terminate)...")

    while True:
        try:
            # Heartbeat every 15s
            if time.time() - last_heartbeat > 15:
                http_post(heartbeat_url, {'agentId': agent_id}, token)
                last_heartbeat = time.time()

            # Poll for jobs
            resp = http_get(poll_url, token)
            job = resp.get('data')

            if job and job.get('jobId'):
                job_id = job['jobId']
                binary = job.get('binaryName')
                params = job.get('parameters', [])
                target = job.get('target')

                print(f"\n[+] RECEIVED JOB: {job_id} | Binary: {binary} | Target: {target}")

                if binary not in PERMITTED_BINARIES:
                    print(f"[!] Rejected unpermitted binary: {binary}")
                    http_post(submit_url, {
                        'jobId': job_id,
                        'exitCode': 126,
                        'stdout': '',
                        'stderr': f"Binary '{binary}' is not on the permitted agent execution whitelist.",
                        'executionTimeMs': 0,
                        'completedAt': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }, token)
                    continue

                # Execute binary safely
                cmd = [binary] + params
                print(f"[*] Executing: {' '.join(cmd)}")
                start_exec = time.time()

                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1
                    )

                    stdout_accum = []
                    stderr_accum = []

                    # Read stdout line by line and stream
                    for line in iter(proc.stdout.readline, ''):
                        stdout_accum.append(line)
                        http_post(chunk_url, {'jobId': job_id, 'type': 'stdout', 'chunk': line}, token)

                    for line in iter(proc.stderr.readline, ''):
                        stderr_accum.append(line)
                        http_post(chunk_url, {'jobId': job_id, 'type': 'stderr', 'chunk': line}, token)

                    proc.wait()
                    duration_ms = int((time.time() - start_exec) * 1000)

                    # Submit final completed result
                    result_payload = {
                        'jobId': job_id,
                        'exitCode': proc.returncode,
                        'stdout': ''.join(stdout_accum),
                        'stderr': ''.join(stderr_accum),
                        'executionTimeMs': duration_ms,
                        'completedAt': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                    http_post(submit_url, result_payload, token)
                    print(f"[+] Job {job_id} completed (Exit Code: {proc.returncode}, Duration: {duration_ms}ms)")

                except Exception as ex:
                    print(f"[!] Execution error on job {job_id}: {ex}")
                    http_post(submit_url, {
                        'jobId': job_id,
                        'exitCode': 1,
                        'stdout': '',
                        'stderr': f"Subprocess exception: {str(ex)}",
                        'executionTimeMs': int((time.time() - start_exec) * 1000),
                        'completedAt': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }, token)

            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[*] Shutting down Kali Agent gracefully...")
            break
        except urllib.error.HTTPError as e:
            if e.code == 401:
                print(f"[!] Authentication Error: Token rejected by server (HTTP 401).")
                time.sleep(5)
            else:
                time.sleep(3)
        except Exception as e:
            time.sleep(3)

if __name__ == '__main__':
    main()
