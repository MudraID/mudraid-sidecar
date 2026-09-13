/**
 * Packaging claims must be true of the tree that gets packed.
 *
 * npm translation of the Python packages' packaging guards
 * (sdks/mudraid-sdk-python/tests/unit/test_packaging_metadata.py and
 * sdks/mudraid-middleware-python/tests/unit/test_version_single_source.py),
 * sibling of the same test in sdks/mudraid-adapter-node. These tests hold the
 * METADATA to its promises; what ends up inside the built tarball is asserted
 * separately by `.github/inspect_tarball.mjs`, which publish.yml runs against
 * the actual artifact after `npm pack`.
 *
 * NOTE ON CHANNELS: the support matrix lists this package on the `oci`
 * channel — the Dockerfile image is the primary distribution — and the npm
 * tarball is the compiled runtime form the publish workflow governs. The version is
 * one fact either way: the matrix row's version tracks package.json.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const readJson = (path: string): any => JSON.parse(readFileSync(path, 'utf8'));
const manifest = readJson(join(PACKAGE_ROOT, 'package.json'));

/**
 * Two layouts, one guard — full matrix one level up in the monorepo, trimmed
 * excerpt (name + version) beside the package in a public mirror. Absence in
 * BOTH places is a failure, not a skip: the publish run in the public
 * repository is the only run that uploads, which makes it exactly the run
 * this guard exists for.
 */
function matrixRow(name: string): any {
  const candidates = [
    join(PACKAGE_ROOT, 'support-matrix.json'), // public mirror layout
    join(PACKAGE_ROOT, '..', 'support-matrix.json'), // monorepo layout
  ];
  const found = candidates.find((c) => existsSync(c));
  if (!found) {
    throw new Error(
      'support-matrix.json exists neither beside the package (mirror layout) nor ' +
        'one level up (monorepo layout); the publishable-version guard has nothing ' +
        'to hold the manifest against',
    );
  }
  const row = readJson(found).packages.find((p: any) => p.name === name);
  expect(row, `${found} has no row for ${name}`).toBeDefined();
  return row;
}

describe('version single-source', () => {
  it('declares in package.json the version the support matrix publishes', () => {
    // Pinned literally, as the Python guard pins "1.1.0": bumping the version
    // is a deliberate multi-file act — manifest, lockfile, matrix row, this
    // test — never a drive-by edit that two of the four fail to notice.
    const row = matrixRow('@mudraid/sidecar');
    expect(manifest.version).toBe(row.version);
    expect(manifest.version).toBe('1.1.0');
  });

  it('keeps the lockfile agreeing with the manifest', () => {
    const lock = readJson(join(PACKAGE_ROOT, 'package-lock.json'));
    expect(lock.version).toBe(manifest.version);
    expect(lock.packages[''].version).toBe(manifest.version);
  });

  it('claims in the matrix only what the manifest can deliver', () => {
    const row = matrixRow('@mudraid/sidecar');
    if (row.support_status !== undefined && manifest.private === true) {
      // "On the receipt, not the vibe": a manifest still marked private
      // cannot have produced a recorded upload, so the row may claim nothing
      // beyond prerelease. The row flips only after an upload is recorded.
      expect(row.support_status).toBe('prerelease');
    }
    if (row.runtimes !== undefined) {
      expect(row.runtimes).toContain(`node${manifest.engines.node}`);
    }
  });
});

describe('packaging metadata', () => {
  it('either declares a licence and ships its text, or explicitly declares none', () => {
    const shipsText = existsSync(join(PACKAGE_ROOT, 'LICENSE'));
    expect(manifest.license !== 'UNLICENSED').toBe(shipsText);
  });

  it('points the entry surface inside the files allowlist', () => {
    // Customer entry points must resolve inside the compiled artifact.
    const allow: string[] = manifest.files;
    expect(allow).toContain('dist');
    const rel = (manifest.main as string).replace(/^\.\//, '');
    expect(
      allow.some((prefix) => rel === prefix || rel.startsWith(`${prefix}/`)),
      `${manifest.main} is not under any files[] prefix ${JSON.stringify(allow)}`,
    ).toBe(true);
  });

  it('packs the compiled standalone runtime and none of the forbidden classes', () => {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const files: string[] = JSON.parse(out)[0].files.map((f: any) => f.path);

    for (const required of ['package.json', 'README.md', 'dist/index.js', 'dist/server.js', 'dist/build-inputs.json', 'dist/ADAPTER-LICENSE']) {
      expect(files).toContain(required);
    }

    const forbidden: Array<[RegExp, string]> = [
      [/(^|\/)\.env($|\..*)/, 'environment files carry credentials by convention'],
      [/\.(pem|key|p12|pfx|jks)$/, 'private key material'],
      [/(^|\/)\.npmrc$/, 'npm credentials'],
      [/(^|\/)\.git(hub)?($|\/)/, 'repository internals / CI furniture'],
      [/(^|\/)node_modules($|\/)/, 'a dependency tree from the build machine'],
      [/(^|\/)test($|\/)/, 'the suite runs in the repository, not out of the tarball'],
      [/(vitest\.config|tsconfig(\..+)?\.json)/, 'build/test configuration'],
      // The image recipe belongs to the OCI lane (adapter-release.yml), not
      // inside the npm artifact — same "whose artifact is this?" rule the
      // Kong mirror applies to its Dockerfile.
      [/(^|\/)Dockerfile$/, 'the OCI channel build recipe'],
      [/\.tgz$/, 'a stale packed artifact'],
    ];
    for (const [pattern, reason] of forbidden) {
      const hits = files.filter((f) => pattern.test(f));
      expect(hits, `tarball would ship ${JSON.stringify(hits)} — ${reason}`).toEqual([]);
    }
  });
});
