import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The server-mode web build (PD-218, PD-220): the `web/*.html` pages with the HTTP transport,
// output in `dist-server/` (`index.html`, `login.html`, ... and flat `assets/<name>`), which
// `atlas-duck-server` serves from `ATLAS_DUCK_WEB_DIR`. No credential chunk rule: server mode has
// no credential window. Everything is bundled locally: no CDN, no remote module loads.
// `static_files::PAGES` in crates/server lists the same pages.
const PAGES = ['index', 'login', 'approvals', 'credentials', 'api-keys', 'admin', 'oauth-consent', 'connected-apps', 'audit'];

export default defineConfig({
  root: 'web',
  publicDir: false,
  plugins: [react()],
  define: {
    'import.meta.env.VITE_ATLAS_DUCK_TRANSPORT': JSON.stringify('http'),
  },
  build: {
    outDir: '../dist-server',
    emptyOutDir: true,
    sourcemap: false,
    assetsDir: 'assets',
    modulePreload: { polyfill: false },
    rollupOptions: {
      input: Object.fromEntries(PAGES.map((p) => [p, `web/${p}.html`])),
    },
  },
});
