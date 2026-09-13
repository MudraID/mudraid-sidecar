/**
 * The V2-enforcing reverse-proxy core.
 *
 * For every inbound request the sidecar:
 *   1. extracts portable {@link RequestFacts} (framing / JSON-RPC / headers),
 *   2. runs the shared `evaluateV2` control loop from `@mudraid/adapter-node`
 *      (the decision core — NOT re-implemented here) with an injectable
 *      `/decide` seam, and
 *   3. forwards to the upstream ONLY on a bound allow.
 *
 * NO-BYPASS INVARIANT: there is exactly one call to the upstream forwarder in
 * this file, and it is unconditionally guarded by `shouldForward(decision)`.
 * Every other outcome — no bundle, `/decide` unavailable, unmapped action,
 * framing violation, explicit deny — returns a deny-closed response and the
 * forwarder is never touched. A request reaches the application only after a
 * bound V2 allow.
 */

import {
  evaluateV2,
  type HttpAuthority,
  shouldForward,
  type DecideClient,
  type Decision,
} from '@mudraid/adapter-node';

import type { SidecarConfig } from './config.js';
import { buildFacts, type InboundRequest } from './facts.js';
import type { UpstreamForwarder, UpstreamResponse } from './upstream.js';

export interface ProxyDeps {
  readonly config: SidecarConfig;
  /** Verified live authority used by the standalone server. */
  readonly authority?: HttpAuthority;
  /** Injectable decision seam for embedded integrations and tests. */
  readonly decide: DecideClient;
  /** Injectable upstream forwarder — never called except on a bound allow. */
  readonly forwardUpstream: UpstreamForwarder;
}

export interface SidecarResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
  /** True iff the request was actually proxied to the upstream (a bound allow). */
  readonly forwarded: boolean;
  /** The normalized V2 decision that produced this response (for logging/audit). */
  readonly decision: Decision;
}

/**
 * Build the outgoing headers for a forwarded request: start from the inbound
 * headers, remove every reserved header the core reported stripped (so no
 * client-forged trusted context reaches the app), then inject the trusted
 * context the core minted for this bound allow.
 */
function outgoingHeaders(
  inbound: InboundRequest,
  decision: Decision,
): Record<string, string> {
  const stripped = new Set(decision.strippedReservedHeaders.map((h) => h.toLowerCase()));
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(inbound.headers)) {
    if (value === undefined) {
      continue;
    }
    if (stripped.has(name.toLowerCase())) {
      continue; // reserved / forged trusted-context header — never forward
    }
    headers[name] = value;
  }
  for (const [name, value] of decision.trustedContext) {
    headers[name] = value;
  }
  return headers;
}

/** A deny-closed JSON error body carrying only secret-free, typed fields. */
function denyBody(decision: Decision): Buffer {
  const payload = {
    error: 'mudraid_enforced',
    code: decision.adapterCode,
    reason: decision.reasonCode,
    message: decision.message,
  };
  return Buffer.from(JSON.stringify(payload), 'utf-8');
}

/**
 * Enforce V2 for one inbound request and either proxy to the upstream (bound
 * allow) or return a deny-closed response. This function is the sidecar's whole
 * enforcement path; the HTTP server is a thin adapter over it.
 */
export async function enforce(
  inbound: InboundRequest,
  deps: ProxyDeps,
): Promise<SidecarResponse> {
  // Own the exact bytes and headers before awaiting authority. A caller must
  // not change what reaches the application while its decision is in flight.
  inbound = {...inbound, headers: Object.freeze({...inbound.headers}), body: Buffer.from(inbound.body)};
  const snapshot = deps.authority?.bundle;
  const config = deps.authority ? {
    ...deps.config, protectedSurface: true, bundleActive: snapshot !== undefined,
    actionMap: Object.fromEntries(Object.entries(snapshot?.actions ?? {}).map(([tool, action]) => [tool, String(action['action_key'])])),
  } : deps.config;
  const facts = buildFacts(inbound, config);
  const decide = deps.authority ? () => deps.authority!.decide(facts.toolName ?? '', {
    presentedAuthorization: Object.entries(inbound.headers).find(([name]) => name.toLowerCase() === 'authorization')?.[1] ?? '',
    httpMethod: inbound.method, path: inbound.path, body: inbound.body,
    contentType: Object.entries(inbound.headers).find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? '',
  }, snapshot) : deps.decide;
  const decision = await evaluateV2(facts, decide);

  if (!shouldForward(decision)) {
    // Deny / deny-closed: the forwarder is NOT called. The upstream is never
    // reached, regardless of what the client sent.
    return {
      status: decision.httpStatus,
      headers: { 'content-type': 'application/json' },
      body: denyBody(decision),
      forwarded: false,
      decision,
    };
  }

  // Bound allow (authorized tool call, or a control-plane pass-through). This is
  // the ONLY code path that reaches the upstream.
  const upstream: UpstreamResponse = await deps.forwardUpstream({
    method: inbound.method,
    path: inbound.path,
    headers: outgoingHeaders(inbound, decision),
    body: inbound.body,
  });

  return {
    status: upstream.status,
    headers: upstream.headers,
    body: upstream.body,
    forwarded: true,
    decision,
  };
}
