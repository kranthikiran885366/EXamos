import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000 http://127.0.0.1:8000 ws://localhost:5173 ws://127.0.0.1:5173; object-src 'none'; base-uri 'none'; form-action 'self'; frame-src 'none'; worker-src 'self'";
// Vite's dev client injects an inline React refresh preamble, so development needs
// 'unsafe-inline'. Production builds keep the strict policy above.
const devCsp = csp.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'");
const headers = {
  'Content-Security-Policy': csp + "; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), usb=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
};
// CSP meta is injected at build only (dev HMR needs inline preamble).
const cspMeta = { name: 'csp-meta', apply: 'build', transformIndexHtml: (h) => h.replace('</head>', `<meta http-equiv="Content-Security-Policy" content="${csp}" /></head>`) };

export default defineConfig({
  plugins: [react(), cspMeta],
  build: { sourcemap: false, target: 'es2022' },
  server: {
    headers: { ...Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== undefined)), 'Content-Security-Policy': devCsp },
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      }
    }
  },
  preview: { headers: Object.fromEntries(Object.entries(headers).filter(([, v]) => v !== undefined)) },
});
