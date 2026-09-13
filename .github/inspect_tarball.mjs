#!/usr/bin/env node
/**
 * Assert what the packed npm tarball actually contains, and whether the
 * manifest inside it is releasable — before an upload nobody can undo.
 *
 * This is the npm translation of the Python packages' `inspect_distribution.py`
 * (sdks/mudraid-sdk-python/.github/inspect_distribution.py). The reasoning is
 * identical: every other gate in publish.yml reads the package through an
 * import. vitest imports from `src/`, tsc reads the source tree, and neither
 * ever opens the archive and looks, so a distribution can be wrong in two
 * directions while everything stays green:
 *
 *   - A file that should ship and does not. `dist/server.js` is this package's
 *     example: the sidecar runs from compiled JavaScript (`node dist/server.js`,
 *     see README), every in-tree test passes without the `files` allowlist
 *     being right, and the first person to notice a missing module is the
 *     customer whose sidecar fails to boot.
 *   - A file that ships and should not. A stray `.npmrc` or `.env` inside a
 *     tarball is published to everyone, and npm blocks re-publishing a version
 *     number even after `npm unpublish` — the remedy is a new version and an
 *     advisory, forever.
 *
 * This runs in the mirrored public repository, so it deliberately uses nothing
 * but the Node standard library and nothing outside this package directory.
 *
 * Usage:
 *   node .github/inspect_tarball.mjs contents  [dist-dir]   # archive truth
 *   node .github/inspect_tarball.mjs preflight [dist-dir]   # releasability
 *
 * `contents` always exits 1 on a violation. `preflight` lists every reason a
 * real publish would be refused; with PUBLISH_INTENT=true it exits 1 on any
 * blocker (a refusal), otherwise it exits 0 after reporting (a rehearsal that
 * tells the operator exactly what the real run will say).
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PACKAGE_NAME = '@mudraid/sidecar';

/** What must be in the tarball — the thing `npm install` actually delivers. */
const REQUIRED = [
  'package/package.json',
  // Plain Node entry points and bundled-source inventory.
  'package/dist/index.js',
  'package/dist/server.js',
  'package/dist/build-inputs.json',
  'package/dist/ADAPTER-LICENSE',
  // The README is the operator's runbook for a customer-hosted proxy. npm
  // packs a root README unconditionally, so its absence here means the
  // `files` allowlist broke that rule somehow — worth refusing over.
  'package/README.md',
];

/**
 * Patterns that must never appear in a published archive, with the reason
 * each one is here. A bare list would be edited by whoever hit it; a reason
 * is something they have to disagree with first.
 */
const FORBIDDEN = [
  [/(^|\/)\.env($|\..*)/, 'an environment file carries credentials by convention'],
  [/\.(pem|key|p12|pfx|jks)$/, 'private key material'],
  [/(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/, 'an SSH private key'],
  [/(^|\/)\.npmrc$/, 'npm credentials — the registry token itself'],
  [/(^|\/)\.git($|\/)/, 'repository internals, including full history in .git'],
  [/(^|\/)\.github($|\/)/, 'CI configuration is repository furniture, not library code'],
  [/(^|\/)node_modules($|\/)/, 'a dependency tree from the build machine'],
  [/(^|\/)coverage($|\/)/, 'coverage output from the build machine'],
  [/\.tsbuildinfo$/, 'incremental-build state from the build machine'],
  [/(^|\/)\.DS_Store$/, 'editor and OS debris'],
  [/\.tgz$/, 'a tarball inside the tarball is a stale artifact that leaked in'],
  [/(^|\/)test($|\/)/, 'the test suite runs in the repository, not out of the tarball'],
  [/(vitest\.config|tsconfig(\..+)?\.json)/, 'build/test configuration is repository furniture'],
  // The Dockerfile builds the OCI distribution of this sidecar — a different
  // channel with its own lane (adapter-release.yml). Same rule as the Kong
  // mirror's exclusions: WHOSE ARTIFACT IS THIS? The npm tarball is the
  // compiled runtime form, and shipping the image recipe inside it blurs which
  // artifact a customer is holding.
  [/(^|\/)Dockerfile$/, 'the OCI channel’s build recipe, not part of the npm artifact'],
];

function fail(problems) {
  console.error('inspect_tarball: the archive is not what it should be:');
  for (const p of problems) console.error(`  ${p}`);
  console.error(
    '\nnpm blocks re-publishing a version number, even after unpublish. ' +
      'Fix the build and cut a new version rather than publishing this one.',
  );
  return 1;
}

/**
 * List the entry names in a gzipped ustar archive using only the standard
 * library — the same posture as the Python script's `tarfile`/`zipfile`.
 * Handles the pax extended headers npm emits (typeflag x/g carry metadata,
 * and a `path=` record overrides the following entry's name).
 */
function tarEntries(tgzPath) {
  const buf = gunzipSync(readFileSync(tgzPath));
  const names = [];
  let offset = 0;
  let paxPath = null;
  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break; // end-of-archive
    const rawName = header.toString('utf8', 0, 100).replace(/\0.*$/, '');
    const prefix = header.toString('utf8', 345, 500).replace(/\0.*$/, '');
    const size = parseInt(header.toString('utf8', 124, 136).replace(/\0.*$/, '').trim() || '0', 8);
    const typeflag = String.fromCharCode(header[156]);
    const body = buf.subarray(offset + 512, offset + 512 + size);
    if (typeflag === 'x' || typeflag === 'g') {
      const m = body.toString('utf8').match(/\d+ path=([^\n]+)\n/);
      if (typeflag === 'x' && m) paxPath = m[1];
    } else {
      names.push(paxPath ?? (prefix ? `${prefix}/${rawName}` : rawName));
      paxPath = null;
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return names;
}

function theOneTarball(distDir) {
  const tarballs = existsSync(distDir)
    ? readdirSync(distDir).filter((f) => f.endsWith('.tgz'))
    : [];
  // Exactly one. Two tarballs in the staging directory means a stale artifact
  // is present, and a `*.tgz` glob would publish BOTH — the older one silently
  // claiming its version.
  if (tarballs.length !== 1) {
    process.exit(
      fail([`expected exactly one .tgz in ${distDir}/, found [${tarballs.join(', ')}]`]),
    );
  }
  return join(distDir, tarballs[0]);
}

function readManifestFromTarball(names, tgzPath) {
  // The manifest that matters is the one INSIDE the artifact, not the one in
  // the working directory — they are the same today, but the artifact is what
  // ships, so the artifact is what gets read.
  const buf = gunzipSync(readFileSync(tgzPath));
  let offset = 0;
  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = header.toString('utf8', 0, 100).replace(/\0.*$/, '');
    const size = parseInt(header.toString('utf8', 124, 136).replace(/\0.*$/, '').trim() || '0', 8);
    const typeflag = String.fromCharCode(header[156]);
    if (typeflag !== 'x' && typeflag !== 'g' && name === 'package/package.json') {
      return JSON.parse(buf.subarray(offset + 512, offset + 512 + size).toString('utf8'));
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  process.exit(fail([`${tgzPath}: no package/package.json entry`]));
}

function checkContents(distDir) {
  const tgz = theOneTarball(distDir);
  const names = tarEntries(tgz);
  const problems = [];

  for (const entry of REQUIRED) {
    if (!names.includes(entry)) problems.push(`${tgz}: missing ${entry}`);
  }
  for (const [pattern, reason] of FORBIDDEN) {
    const hits = names.filter((n) => pattern.test(n)).sort();
    if (hits.length) problems.push(`${tgz}: ships [${hits.join(', ')}] — ${reason}`);
  }

  const manifest = readManifestFromTarball(names, tgz);
  if (manifest.name !== PACKAGE_NAME) {
    problems.push(`${tgz}: manifest names '${manifest.name}', expected '${PACKAGE_NAME}'`);
  }
  // The licence must be either declared away or shipped, never merely absent.
  // UNLICENSED is an explicit statement; any real licence id promises a text
  // that has to travel with the artifact.
  if (manifest.license !== 'UNLICENSED' && !names.some((n) => /^package\/LICENSE/i.test(n))) {
    problems.push(
      `${tgz}: license is '${manifest.license}' but no LICENSE file ships — ` +
        'the metadata names a licence and the installed package carries no text of it',
    );
  }

  if (problems.length) process.exit(fail(problems));
  console.log(
    `inspect_tarball: ${tgz} carries the compiled runtime and its README, and ` +
      `nothing from the ${FORBIDDEN.length} forbidden classes.`,
  );
}

function checkPreflight(distDir) {
  const tgz = theOneTarball(distDir);
  const names = tarEntries(tgz);
  const manifest = readManifestFromTarball(names, tgz);
  const blockers = [];

  // `private: true` is the manifest's own statement that it must not be
  // published. npm enforces it too, but npm's error names none of the release
  // acts that removing the flag is part of; this one does.
  if (manifest.private === true) {
    blockers.push(
      "package.json says `private: true`. Removing that flag is a RELEASE DECISION, " +
        'made in a reviewed commit together with a real version — never in CI.',
    );
  }
  if (manifest.version === '0.0.0') {
    blockers.push(
      'version is 0.0.0 — the pre-release placeholder. Publishing it would burn a ' +
        'version number npm never lets this package use again.',
    );
  }
  if (!manifest.repository) {
    blockers.push(
      'package.json has no `repository` field. `npm publish --provenance` refuses ' +
        'without one that names the repository the publish runs in, so the field must ' +
        'be added (pointing at the PUBLIC package repository) before a release.',
    );
  }
  if (!names.some((n) => /^package\/README(\.md)?$/i.test(n))) {
    blockers.push(
      'no README ships, so the npm project page would render empty. The Python lane ' +
        'treats a broken project page as its highest-value refusal (twine check --strict); ' +
        'an absent page fails the same way for the same reason.',
    );
  }

  // Every bare import specifier the shipped code uses must be a declared
  // dependency — the npm analogue of the Python workflow's "prove the v2
  // extra resolved". A specifier that resolves in this repository through a
  // vitest alias or tsconfig path resolves NOWHERE on a customer's machine.
  const declared = new Set(Object.keys(manifest.dependencies ?? {}));
  const undeclared = new Set();
  const buf = gunzipSync(readFileSync(tgz));
  let offset = 0;
  while (offset + 512 <= buf.length) {
    const header = buf.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = header.toString('utf8', 0, 100).replace(/\0.*$/, '');
    const size = parseInt(header.toString('utf8', 124, 136).replace(/\0.*$/, '').trim() || '0', 8);
    const typeflag = String.fromCharCode(header[156]);
    if (typeflag !== 'x' && typeflag !== 'g' && /\.(m?[jt]s|c[jt]s)$/.test(name)) {
      const source = buf.subarray(offset + 512, offset + 512 + size).toString('utf8');
      for (const m of source.matchAll(/(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"]([^'"]+)['"]/g)) {
        const spec = m[1];
        if (spec.startsWith('.') || spec.startsWith('node:')) continue;
        const pkg = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
        if (!declared.has(pkg)) undeclared.add(pkg);
      }
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (undeclared.size) {
    blockers.push(
      `shipped code imports [${[...undeclared].sort().join(', ')}] but package.json ` +
        'declares no such dependency. It resolves here through repository wiring ' +
        '(vitest alias / tsconfig paths) and resolves nowhere once installed.',
    );
  }

  // The support matrix is the authority on which version is publishable.
  // Two layouts, one guard — monorepo (../support-matrix.json) and public
  // mirror (a trimmed excerpt beside the package). Absence in BOTH places is
  // a blocker, not a skip: the publish run in the public repository is the
  // only run that uploads, which makes it exactly the run this exists for.
  const candidates = [join(PACKAGE_ROOT, 'support-matrix.json'), join(PACKAGE_ROOT, '..', 'support-matrix.json')];
  const matrixPath = candidates.find((p) => existsSync(p));
  if (!matrixPath) {
    blockers.push(
      'support-matrix.json exists neither beside the package (mirror layout) nor one ' +
        'level up (monorepo layout); the publishable-version guard has nothing to hold ' +
        'the manifest against.',
    );
  } else {
    const matrix = JSON.parse(readFileSync(matrixPath, 'utf8'));
    const row = matrix.packages.find((p) => p.name === PACKAGE_NAME);
    if (!row) {
      blockers.push(`${matrixPath} has no row for ${PACKAGE_NAME}.`);
    } else if (row.version !== manifest.version) {
      blockers.push(
        `manifest version ${manifest.version} != matrix-declared ${row.version} — a ` +
          'manifest that has moved past the matrix would publish an artifact nothing declares.',
      );
    }
  }

  if (blockers.length === 0) {
    console.log(`inspect_tarball: preflight clean — ${manifest.name}@${manifest.version} is releasable.`);
    return;
  }
  const intent = process.env.PUBLISH_INTENT === 'true';
  console.error(
    intent
      ? 'inspect_tarball: REFUSING to publish. Blockers:'
      : 'inspect_tarball: dry run — a real publish WOULD BE REFUSED for these reasons:',
  );
  for (const b of blockers) console.error(`  - ${b}`);
  if (intent) process.exit(1);
  console.error(
    '\n(dry run exits 0: its job is to say what the real run will do, and it just did.)',
  );
}

const [mode, distArg] = process.argv.slice(2);
const distDir = resolve(distArg ?? 'dist-tarball');
if (mode === 'contents') checkContents(distDir);
else if (mode === 'preflight') checkPreflight(distDir);
else {
  console.error("usage: inspect_tarball.mjs <contents|preflight> [dist-dir]");
  process.exit(1);
}
