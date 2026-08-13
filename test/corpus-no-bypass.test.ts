/**
 * Corpus-driven NO-BYPASS proof.
 *
 * Reuses the portable adapter-decision corpus from the sibling
 * `@mudraid/adapter-node` package (referenced by relative path — no copy, no
 * drift) and drives EVERY fixture end-to-end through the sidecar's `enforce`,
 * with a spy upstream forwarder.
 *
 * The load-bearing invariant, asserted for all fixtures:
 *   - a fixture whose expected outcome is `allow` reaches the upstream EXACTLY
 *     once;
 *   - EVERY other outcome (`deny`, `not_safely_decided`) reaches the upstream
 *     ZERO times.
 *
 * That is the "direct application access is blocked" property at the proxy
 * layer: the app is reached only after a bound V2 allow. The test also asserts
 * the sidecar reproduces each fixture's HTTP status, adapter code, and stripped
 * reserved-header set, so proxy-level enforcement stays in lockstep with the
 * core contract.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  staticDecideClient,
  throwingDecideClient,
  type DecideClient,
  type DecideResult,
  type DecideStatus,
} from '@mudraid/adapter-node';

import type { SidecarConfig } from '../src/config.js';
import { enforce, type ProxyDeps } from '../src/proxy.js';
import type { InboundRequest } from '../src/facts.js';
import type { ForwardedRequest, UpstreamForwarder, UpstreamResponse } from '../src/upstream.js';

type JsonShape = 'object' | 'array' | 'scalar' | 'not_json';

interface CorpusFactsRaw {
  readonly protected?: boolean;
  readonly reserved_headers_presented?: readonly string[];
  readonly bundle_active?: boolean;
  readonly method?: string;
  readonly body_readable?: boolean;
  readonly body_too_large?: boolean;
  readonly json_shape?: JsonShape;
  readonly jsonrpc?: string | null;
  readonly rpc_method?: string | null;
  readonly tool_name?: string | null;
  readonly action_mapped?: boolean;
  readonly decide?: DecideStatus;
  readonly decide_reason?: string;
}

interface CorpusExpect {
  readonly outcome: 'allow' | 'deny' | 'not_safely_decided';
  readonly http_status: number;
  readonly adapter_code: string | null;
  readonly stripped_reserved_headers: readonly string[];
}

interface CorpusFixture {
  readonly id: string;
  readonly category: string;
  readonly facts: CorpusFactsRaw;
  readonly expect: CorpusExpect;
}

interface Corpus {
  readonly fixtures: readonly CorpusFixture[];
}

// Relative reference into the adapter-node package's pinned corpus snapshot —
// the same fixtures the core's own parity suite runs against.
const corpusPath = fileURLToPath(
  new URL('../../mudraid-adapter-node/test/fixtures/adapter-decision-corpus.json', import.meta.url),
);
const corpus = JSON.parse(readFileSync(corpusPath, 'utf-8')) as Corpus;

const OK_UPSTREAM: UpstreamResponse = {
  status: 200,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from('{"ok":true}'),
};

/** Synthesize a concrete inbound HTTP request that reproduces a fixture's facts. */
function inboundFromFixture(facts: CorpusFactsRaw): InboundRequest {
  const method = facts.method ?? 'POST';
  const bodyTooLarge = facts.body_too_large ?? false;
  const bodyReadable = facts.body_readable ?? true;

  let body = Buffer.alloc(0);
  const shape = facts.json_shape;
  if (!bodyTooLarge && bodyReadable) {
    if (shape === 'array') {
      body = Buffer.from('[]');
    } else if (shape === 'scalar') {
      body = Buffer.from('"scalar"');
    } else if (shape === 'not_json') {
      body = Buffer.from('not-json{');
    } else if (shape === 'object' || facts.rpc_method !== undefined || facts.jsonrpc !== undefined) {
      const obj: Record<string, unknown> = {
        jsonrpc: facts.jsonrpc !== undefined ? facts.jsonrpc : '2.0',
      };
      if (facts.rpc_method !== undefined) {
        obj['method'] = facts.rpc_method;
      }
      if (facts.tool_name !== undefined) {
        obj['params'] = { name: facts.tool_name };
      }
      body = Buffer.from(JSON.stringify(obj));
    }
  }

  const headers: Record<string, string | undefined> = {};
  for (const name of facts.reserved_headers_presented ?? []) {
    headers[name] = 'synthetic-value';
  }

  return { method, path: '/mcp', headers, body, bodyTooLarge, bodyReadable };
}

function configFromFixture(facts: CorpusFactsRaw): SidecarConfig {
  const actionMap: Record<string, string> = {};
  if (facts.action_mapped === true && typeof facts.tool_name === 'string' && facts.tool_name !== '') {
    actionMap[facts.tool_name] = facts.tool_name;
  }
  return {
    upstreamBaseUrl: 'http://upstream.internal',
    protectedSurface: facts.protected ?? true,
    bundleActive: facts.bundle_active ?? true,
    actionMap,
    maxBodyBytes: 1_048_576,
  };
}

function decideFromFixture(facts: CorpusFactsRaw): DecideClient {
  if (facts.decide === undefined) {
    // No decide fact ⇒ the live call must never be reached; if it is, throw.
    return throwingDecideClient(new Error('decide reached for a no-decide fixture'));
  }
  const result: DecideResult = {
    status: facts.decide,
    ...(facts.decide_reason !== undefined ? { reason: facts.decide_reason } : {}),
  };
  return staticDecideClient(result);
}

describe('corpus-driven no-bypass: deny NEVER proxies, allow proxies exactly once', () => {
  it('covers a non-trivial corpus', () => {
    expect(corpus.fixtures.length).toBeGreaterThanOrEqual(20);
  });

  for (const fixture of corpus.fixtures) {
    it(`[${fixture.category}] ${fixture.id}`, async () => {
      const calls: ForwardedRequest[] = [];
      const forward: UpstreamForwarder = async (req) => {
        calls.push(req);
        return OK_UPSTREAM;
      };

      const deps: ProxyDeps = {
        config: configFromFixture(fixture.facts),
        decide: decideFromFixture(fixture.facts),
        forwardUpstream: forward,
      };

      const result = await enforce(inboundFromFixture(fixture.facts), deps);

      // The no-bypass invariant.
      const expectedForwardCount = fixture.expect.outcome === 'allow' ? 1 : 0;
      expect(calls.length).toBe(expectedForwardCount);
      expect(result.forwarded).toBe(fixture.expect.outcome === 'allow');

      // End-to-end parity with the contract.
      expect(result.decision.outcome).toBe(fixture.expect.outcome);
      expect(result.decision.adapterCode).toBe(fixture.expect.adapter_code);
      expect([...result.decision.strippedReservedHeaders]).toEqual([
        ...fixture.expect.stripped_reserved_headers,
      ]);
      // On a deny/deny-closed the sidecar returns the decision's HTTP status; on
      // an allow it returns the (fake) upstream's 200 — which the allow fixtures
      // also expect.
      expect(result.status).toBe(fixture.expect.http_status);
    });
  }
});
