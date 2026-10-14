import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const ENTRIES = [
  'approvals',
  'settings',
  'audit',
  'running_scripts',
  'onboarding',
  'setup',
  'credential',
];

// UI shell for the Tauri app (app/src-tauri reads ../ui/dist).
// Everything is bundled locally: no CDN, no remote module loads (spec §2.4).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // ci/check-credential-bundle.mjs reads the manifest.
    manifest: true,
    // The preload polyfill is a module every entry would share, the
    // credential page included (PD-71).
    modulePreload: { polyfill: false },
    rollupOptions: {
      input: Object.fromEntries(ENTRIES.map((e) => [e, `${e}.html`])),
      output: {
        // Every module under src/credential/ goes into the one "credential"
        // chunk and nothing else joins it (PD-71, spec 10.3). The page script
        // main.ts stays in the entry chunk so that Vite's manifest still maps
        // the credential.html entry to it.
        manualChunks(id: string) {
          const path = id.replaceAll('\\', '/');
          return path.includes('/src/credential/') && !path.endsWith('/src/credential/main.ts')
            ? 'credential'
            : undefined;
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./vitest.setup.ts'],
  },
});
