/** Run the packed artifact in an empty install with no development dependencies. */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const directory = resolve(process.argv[2] ?? 'dist-tarball');
const candidates = readdirSync(directory).filter(name => name.endsWith('.tgz'));
if (candidates.length !== 1) throw new Error('Expected exactly one candidate tarball');
const isolated = mkdtempSync(join(tmpdir(), 'mudraid-sidecar-installed-'));
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('MUDRAID_')));
try {
  execFileSync('npm', ['install', '--prefix', isolated, '--omit=dev', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', join(directory, candidates[0])], {env, stdio: 'pipe', timeout: 30000});
  // Compile only the synthetic signing oracle using the test host's tools.
  // The child uses HttpAuthority from the INSTALLED artifact, never this
  // oracle's source implementation. Nothing from the oracle ships in npm.
  const core = ['../../mudraid-adapter-node/test/authorityFixtures.ts', '../vendor/adapter-node/test/authorityFixtures.ts']
    .map(path => fileURLToPath(new URL(path, import.meta.url))).find(existsSync);
  if (!core) throw new Error('Synthetic authority oracle missing');
  await build({entryPoints: [core], outfile: join(isolated, 'oracle.mjs'),
    bundle: true, format: 'esm', platform: 'node', target: 'node20'});
  execFileSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import {createServer} from 'node:http';
    import {createSidecarServer, HttpAuthority, httpUpstreamForwarder, staticDecideClient} from '@mudraid/sidecar';
    import {harness} from './oracle.mjs';
    const modes = ['allow', 'deny', 'unsigned', 'replayed', 'altered', 'foreign_action',
      'expired_deadline', 'missing_deadline', 'foreign_body', 'missing_execution', 'unreachable', 'tampered'];
    const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const close = async server => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); };
    for (const withArguments of [false, true]) for (const mode of modes) {
      const observed = [];
      const body = JSON.stringify({jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'read', arguments: {amount_minor: 1250, recipient: 'approved'}}});
      const upstream = createServer(async (req, res) => {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        observed.push({body: Buffer.concat(chunks).toString(), headers: req.headers, path: req.url});
        res.end('accepted');
      });
      await listen(upstream);
      const {options, calls} = harness(mode, undefined, withArguments);
      const authority = new HttpAuthority(options);
      await authority.refresh();
      const origin = 'http://127.0.0.1:' + upstream.address().port;
      const server = createSidecarServer({
        config: {upstreamBaseUrl: origin, protectedSurface: true, bundleActive: false, actionMap: {}, maxBodyBytes: 1048576},
        authority, decide: staticDecideClient({status: 'allow', decisionId: 'forged-fallback'}),
        forwardUpstream: httpUpstreamForwarder(origin),
      }, 1048576);
      await listen(server);
      try {
        const response = await fetch('http://127.0.0.1:' + server.address().port + '/mcp', {
          method: 'POST', body, headers: {'content-type': 'application/json', authorization: 'Bearer synthetic-caller', 'x-mudraid-decision-id': 'forged'},
        });
        await response.arrayBuffer();
        const decisionCall = calls.find(call => call.path === 'decide');
        if (decisionCall) {
          if (withArguments) assert.equal(Buffer.from(decisionCall.body.execution.body_base64, 'base64').toString(), body);
          else assert.equal(decisionCall.body.execution.body_base64, undefined);
        }
        assert.equal(observed.length, mode === 'allow' ? 1 : 0, mode);
        if (mode === 'allow') {
          assert.equal(response.status, 200);
          assert.equal(observed[0].body, body);
          assert.equal(observed[0].path, '/mcp');
          assert.equal(observed[0].headers.authorization, 'Bearer synthetic-caller');
          assert.equal(observed[0].headers['x-mudraid-decision-id'], calls.find(call => call.path === 'decide').body.decision_id);
        } else assert.ok(response.status >= 400, mode);
      } finally { await close(server); await close(upstream); }
    }
  `], {cwd: isolated, env, stdio: 'pipe', timeout: 30000});
  // No alias or sibling checkout is visible to this process. Exercise actual
  // HTTP handling and show an unconfigured authority cannot reach the upstream.
  execFileSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import {createSidecarServer, staticDecideClient} from '@mudraid/sidecar';
    let forwards = 0;
    const server = createSidecarServer({
      config: {upstreamBaseUrl: 'http://127.0.0.1:1', protectedSurface: true,
        bundleActive: false, actionMap: {}, maxBodyBytes: 1048576},
      decide: staticDecideClient({status: 'unconfigured'}),
      forwardUpstream: async () => { forwards++; throw new Error('Unexpected forward'); },
    }, 1048576);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const response = await fetch('http://127.0.0.1:' + server.address().port + '/mcp', {
        method: 'POST', headers: {'content-type': 'application/json'},
        body: JSON.stringify({jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'pay', arguments: {amount: 1}}}),
      });
      assert.ok(response.status >= 400, 'Unconfigured runtime must refuse');
      assert.equal(forwards, 0);
      await response.arrayBuffer();
    } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  `], {cwd: isolated, env, stdio: 'pipe', timeout: 15000});
  // The compiled executable must boot under plain Node, without tsx/tsconfig.
  const child = spawn(process.execPath, [join(isolated, 'node_modules/@mudraid/sidecar/dist/server.js')], {
    cwd: isolated, env: {...env, PORT: '0'}, stdio: ['ignore', 'pipe', 'pipe'],
  });
  // PORT=0 is deliberately invalid. A nonzero exit proves the actual CLI ran
  // its configuration validation, rather than importing a library and exiting 0.
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk.toString(); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('close', resolve); });
  clearTimeout(timer);
  if (code === 0 || !stderr.includes('PORT')) throw new Error('Compiled CLI did not validate its configuration');
  console.log('Installed runtime: 24 signed-authority cases with and without configured request arguments, real HTTP exact-body forwarding only on allow, unconfigured refusal and CLI validation passed');
} finally {
  rmSync(isolated, {recursive: true, force: true});
}
