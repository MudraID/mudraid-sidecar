/**
 * Runtime HTTP entrypoint for the sidecar.
 *
 * A thin `node:http` adapter over {@link enforce}: it reads the inbound request
 * (bounded body), runs enforcement, and writes back either the deny-closed
 * response or the proxied upstream response.
 *
 * DEFERRED remainders wired to safe defaults here:
 *   - the real authenticated HTTP `/decide` client — until it exists the sidecar
 *     runs with a deny-closed `unconfigured` seam, so an unconfigured sidecar
 *     DENIES every protected request (installed, not enforcing == deny-closed,
 *     never bypass);
 *   - signed-config distribution / provenance / live bundle activation —
 *     `bundleActive` comes from static env config for now.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { staticDecideClient, type DecideClient } from '@mudraid/adapter-node';

import { DEFAULT_MAX_BODY_BYTES, type SidecarConfig } from './config.js';
import { enforce, type ProxyDeps } from './proxy.js';
import { httpUpstreamForwarder } from './upstream.js';
import type { InboundRequest } from './facts.js';

/** Read the body up to a hard cap; report truncation as `bodyTooLarge`. */
async function readBody(
  req: IncomingMessage,
  maxBytes: number,
): Promise<{ body: Buffer; bodyTooLarge: boolean; bodyReadable: boolean }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        tooLarge = true;
        return; // stop accumulating; we already know it is over the bound
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      resolve({ body: Buffer.concat(chunks), bodyTooLarge: tooLarge, bodyReadable: true });
    });
    req.on('error', () => {
      resolve({ body: Buffer.alloc(0), bodyTooLarge: tooLarge, bodyReadable: false });
    });
  });
}

function singleValuedHeaders(req: IncomingMessage): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(req.headers)) {
    out[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

export function createSidecarServer(deps: ProxyDeps, maxBodyBytes: number) {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const { body, bodyTooLarge, bodyReadable } = await readBody(req, maxBodyBytes);
      const inbound: InboundRequest = {
        method: req.method ?? 'GET',
        path: req.url ?? '/',
        headers: singleValuedHeaders(req),
        body,
        bodyTooLarge,
        bodyReadable,
      };
      const result = await enforce(inbound, deps);
      res.writeHead(result.status, { ...result.headers });
      res.end(result.body);
    })().catch(() => {
      // Deny-closed on any unexpected server-side failure; leak no detail.
      if (!res.headersSent) {
        res.writeHead(503, { 'content-type': 'application/json' });
      }
      res.end(JSON.stringify({ error: 'mudraid_enforced', code: 'ENFORCE_DECIDE_UNAVAILABLE' }));
    });
  });
}

function configFromEnv(): { config: SidecarConfig; port: number; maxBodyBytes: number } {
  const maxBodyBytes = Number(process.env['MUDRAID_MAX_BODY_BYTES'] ?? DEFAULT_MAX_BODY_BYTES);
  const config: SidecarConfig = {
    upstreamBaseUrl: process.env['MUDRAID_UPSTREAM_URL'] ?? 'http://127.0.0.1:8080',
    protectedSurface: process.env['MUDRAID_PROTECTED_SURFACE'] !== 'false',
    // DEFERRED: real bundle verification. Default false ⇒ deny-closed until a
    // verified bundle is configured active.
    bundleActive: process.env['MUDRAID_BUNDLE_ACTIVE'] === 'true',
    actionMap: {},
    maxBodyBytes,
  };
  return { config, port: Number(process.env['PORT'] ?? 8000), maxBodyBytes };
}

/** Boot the sidecar from environment configuration (deny-closed `/decide` seam). */
export function main(): void {
  const { config, port, maxBodyBytes } = configFromEnv();
  // DEFERRED: real authenticated HTTP `/decide` client. Deny-closed until wired.
  const decide: DecideClient = staticDecideClient({ status: 'unconfigured' });
  const deps: ProxyDeps = {
    config,
    decide,
    forwardUpstream: httpUpstreamForwarder(config.upstreamBaseUrl),
  };
  const server = createSidecarServer(deps, maxBodyBytes);
  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`mudraid-sidecar listening on :${port} → ${config.upstreamBaseUrl}`);
  });
}

// Run when invoked directly (tsx src/server.ts).
if (process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`) {
  main();
}
