/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** `'http'` only in the server build (`vite.server.config.ts`, PD-218); unset on desktop. */
  readonly VITE_ATLAS_DUCK_TRANSPORT?: 'http';
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
