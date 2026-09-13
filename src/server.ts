/**
 * Runtime HTTP entrypoint for the sidecar.
 *
 * A thin `node:http` adapter over {@link enforce}: it reads the inbound request
 * (bounded body), runs enforcement, and writes back either the deny-closed
 * response or the proxied upstream response.
 *
 * Complete authority settings enable authenticated configuration refresh and
 * signed decisions. Missing settings leave protected traffic deny-closed;
 * partial settings fail startup. Environment flags cannot activate a bundle.
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { HttpAuthority, staticDecideClient, type DecideClient } from '@mudraid/adapter-node';

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

function positiveInteger(
  raw: string,
  name: string,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    // Never echo the supplied value: configuration may contain sensitive text.
    throw new Error(
      `${name} must be a positive integer within its supported range`,
    );
  }
  return value;
}

export function configFromEnv(env: NodeJS.ProcessEnv = process.env): {
  config: SidecarConfig;
  port: number;
  maxBodyBytes: number;
} {
  const maxBodyBytes = positiveInteger(
    env['MUDRAID_MAX_BODY_BYTES'] ?? String(DEFAULT_MAX_BODY_BYTES),
    'MUDRAID_MAX_BODY_BYTES',
    8 * 1024 * 1024,
  );
  const port = positiveInteger(env['PORT'] ?? '8000', 'PORT', 65535);
  const config: SidecarConfig = {
    upstreamBaseUrl: env['MUDRAID_UPSTREAM_URL'] ?? 'http://127.0.0.1:8080',
    protectedSurface: env['MUDRAID_PROTECTED_SURFACE'] !== 'false',
    // Only authority verification can activate configuration; environment
    // flags cannot substitute for a verified signed bundle.
    bundleActive: false,
    actionMap: {},
    maxBodyBytes,
  };
  return { config, port, maxBodyBytes };
}

/** No configuration assertion can substitute for signature verification. */
export function authorityFromEnv(env: NodeJS.ProcessEnv = process.env): HttpAuthority | undefined {
  const fields = ['MUDRAID_API_URL', 'MUDRAID_ADAPTER_TOKEN', 'MUDRAID_PLATFORM_ID', 'MUDRAID_ENVIRONMENT', 'MUDRAID_RESOURCE_URI'] as const;
  if (!fields.some(field => env[field])) return undefined;
  if (fields.some(field => !env[field]?.trim())) throw new Error('Incomplete sidecar authority configuration');
  return new HttpAuthority({adapterType: 'node_sidecar', apiBase: env['MUDRAID_API_URL']!, adapterToken: env['MUDRAID_ADAPTER_TOKEN']!, binding: {
    platformId: env['MUDRAID_PLATFORM_ID']!, environment: env['MUDRAID_ENVIRONMENT']!, resource: env['MUDRAID_RESOURCE_URI']!,
  }});
}

/** Boot with public-key verification; an unconfigured authority stays denied. */
export function main(): void {
  const { config, port, maxBodyBytes } = configFromEnv();
  const authority = authorityFromEnv();
  const decide: DecideClient = staticDecideClient({ status: 'unconfigured' });
  const deps: ProxyDeps = {
    config, decide, ...(authority ? {authority} : {}),
    forwardUpstream: httpUpstreamForwarder(config.upstreamBaseUrl),
  };
  const server = createSidecarServer(deps, maxBodyBytes);
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  const refresh = authority ? setInterval(() => { void authority.refresh(); }, 30000) : undefined;
  refresh?.unref();
  server.on('close', () => { if (refresh) clearInterval(refresh); });
  if (authority) void authority.refresh();
  server.listen(port, () => {
    // Log no URLs or credential-bearing configuration.
    console.log(`mudraid-sidecar listening on :${port}`);
  });
}
