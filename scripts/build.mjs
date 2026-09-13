/** Compile one self-contained runtime from the exact reviewed adapter source. */
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const core = [resolve(root, '../mudraid-adapter-node'), resolve(root, 'vendor/adapter-node')]
  .find(path => existsSync(resolve(path, 'src/index.ts')));
if (!core) throw new Error('Reviewed adapter source is missing');
const manifest = JSON.parse(readFileSync(resolve(core, 'package.json'), 'utf8'));
if (manifest.name !== '@mudraid/adapter-node') throw new Error('Unexpected decision core');
rmSync(resolve(root, 'dist'), {recursive: true, force: true});
mkdirSync(resolve(root, 'dist'));
const result = await build({
  absWorkingDir: root,
  entryPoints: {index: 'src/index.ts', server: 'src/cli.ts'},
  outdir: 'dist', bundle: true, splitting: true, format: 'esm', platform: 'node',
  target: 'node20', metafile: true, legalComments: 'eof',
  alias: {'@mudraid/adapter-node': resolve(core, 'src/index.ts')},
});
// Record every bundled input without absolute developer paths. This is source
// inventory, not a substitute for the release workflow's signed provenance.
const inputs = Object.keys(result.metafile.inputs).sort().map(path => {
  const absolute = resolve(root, path);
  const coreRelative = relative(core, absolute);
  const name = coreRelative.startsWith('..') ? relative(root, absolute) : `adapter-node/${coreRelative}`;
  if (name.startsWith('..')) throw new Error('Unexpected external build input');
  return {path: name, sha256: createHash('sha256').update(readFileSync(absolute)).digest('hex')};
});
if (!inputs.some(input => input.path.startsWith('adapter-node/src/'))) throw new Error('Decision core was not bundled');
writeFileSync(resolve(root, 'dist/build-inputs.json'), JSON.stringify({
  schema: 'mudraid.sidecar.build-inputs/1',
  bundledCore: {name: manifest.name, version: manifest.version, license: manifest.license}, inputs,
}, null, 2) + '\n');
writeFileSync(resolve(root, 'dist/ADAPTER-LICENSE'), readFileSync(resolve(core, 'LICENSE')));
