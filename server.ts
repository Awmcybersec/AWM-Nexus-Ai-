/**
 * AWM Nexus — Production & Full-Stack Server
 */

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Dynamically import API handler bundle if compiled
type ApiHandlerFn = (url: string, method: string, body?: Record<string, unknown>) => Promise<{ status: number; data: unknown }>;
let apiHandler: ApiHandlerFn | null = null;

try {
  const bundlePath = path.resolve(__dirname, 'dist-server', 'apiHandler.js');
  if (fs.existsSync(bundlePath)) {
    const mod = await import('./dist-server/apiHandler.js');
    if (typeof mod.handleApiRequest === 'function') {
      apiHandler = mod.handleApiRequest;
    }
  }
} catch (err) {
  console.warn('[!] Note: API Handler bundle not loaded; running static mode:', err);
}

// Serve API Routes
app.all('/api/*', async (req, res) => {
  if (apiHandler) {
    try {
      const result = await apiHandler(req.url, req.method, req.body);
      return res.status(result.status).json(result.data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return res.status(500).json({ error: msg });
    }
  }
  return res.status(200).json({ status: 'ONLINE', message: 'AWM Nexus API running' });
});

// Serve static frontend assets
const distPath = path.resolve(__dirname, 'dist');
app.use(express.static(distPath));

app.get('*', (req, res) => {
  const indexPath = path.join(distPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(200).send('<!DOCTYPE html><html><head><title>AWM Nexus</title></head><body>AWM Nexus is starting up...</body></html>');
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[+] AWM Nexus Human Pentester Server listening on http://0.0.0.0:${PORT}`);
});
