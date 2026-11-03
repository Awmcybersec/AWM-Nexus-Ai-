import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig, Plugin} from 'vite';
import {handleApiRequest} from './src/server/apiHandler';

function apiMiddlewarePlugin(): Plugin {
  return {
    name: 'awm-nexus-api-middleware',
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (req.url && req.url.startsWith('/api/')) {
          let bodyData: Record<string, unknown> = {};
          if (req.method === 'POST' || req.method === 'PUT') {
            const buffers: Buffer[] = [];
            for await (const chunk of req) {
              buffers.push(chunk);
            }
            const rawBody = Buffer.concat(buffers).toString('utf-8');
            if (rawBody) {
              try {
                bodyData = JSON.parse(rawBody);
              } catch {
                bodyData = { raw: rawBody };
              }
            }
          }

          const response = await handleApiRequest(req.url, req.method || 'GET', bodyData);
          res.setHeader('Content-Type', 'application/json');
          res.statusCode = response.status;
          res.end(JSON.stringify(response.data));
          return;
        }
        next();
      });
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), apiMiddlewarePlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâ€”file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
