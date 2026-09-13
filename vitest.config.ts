import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';

import { defineConfig } from 'vitest/config';

/**
 * The sidecar consumes the framework-neutral V2 control loop from the sibling
 * `@mudraid/adapter-node` package by RELATIVE SOURCE reference (see README, "How
 * the adapter-node core is consumed"). The alias maps the package specifier onto
 * that package's `src/index.ts`, so `npm ci && npm test` needs no build of the
 * core and no publish — the exact same decision code is exercised, never a copy.
 */
const core = existsSync(fileURLToPath(new URL('../mudraid-adapter-node/src/index.ts', import.meta.url)))
  ? '../mudraid-adapter-node/' : './vendor/adapter-node/';
const adapterNodeSrc = fileURLToPath(new URL(core + 'src/index.ts', import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@mudraid/adapter-node': adapterNodeSrc,
      '@mudraid/test-authority': fileURLToPath(new URL(core + 'test/authorityFixtures.ts', import.meta.url)),
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
