import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// UI shell for the Tauri app (app/src-tauri reads ../ui/dist).
// Everything is bundled locally: no CDN, no remote module loads (spec §2.4).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.tsx'],
    setupFiles: ['./vitest.setup.ts'],
  },
});
