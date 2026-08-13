import { fileURLToPath } from 'node:url';

import { defineConfig } from 'vitest/config';

/**
 * The sidecar consumes the framework-neutral V2 control loop from the sibling
 * `@mudraid/adapter-node` package by RELATIVE SOURCE reference (see README, "How
 * the adapter-node core is consumed"). The alias maps the package specifier onto
 * that package's `src/index.ts`, so `npm ci && npm test` needs no build of the
 * core and no publish — the exact same decision code is exercised, never a copy.
 */
const adapterNodeSrc = fileURLToPath(
  new URL('../mudraid-adapter-node/src/index.ts', import.meta.url),
);

export default defineConfig({
  resolve: {
    alias: {
      '@mudraid/adapter-node': adapterNodeSrc,
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
  },
});
