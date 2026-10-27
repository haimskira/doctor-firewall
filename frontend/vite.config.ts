import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// Everything is bundled locally: no CDN, no external fonts, no runtime fetches
// other than the same-origin /api. Inline scripts are never emitted, so the
// strict CSP (script-src 'self') served by nginx holds.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    sourcemap: false,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    restoreMocks: true,
    // jsdom renders of the larger pages take ~1.5 s alone; under a loaded CI machine they can
    // pass the 5 s default.
    testTimeout: 15000,
  },
});
