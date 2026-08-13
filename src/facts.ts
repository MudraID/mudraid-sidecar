/**
 * Inbound-request → `RequestFacts` extraction for the sidecar.
 *
 * This module ONLY normalizes an inbound HTTP request into the portable facts
 * the control loop consumes; it makes NO policy decision. In particular it does
 * NOT decide which headers are "reserved" or strip anything — it hands the full
 * set of presented header names to the core, which authoritatively filters and
 * reports the stripped set (delegated reserved-header stripping, contract
 * A03-04). Keeping extraction and decision in two separate places, with the
 * decision living solely in `evaluateV2`, is what prevents two divergent policy
 * copies.
 */

import type { JsonShape, RequestFacts } from '@mudraid/adapter-node';

import type { SidecarConfig } from './config.js';

/**
 * A fully-read inbound request. The server reads the body once (bounded) before
 * calling into enforcement; `bodyTooLarge` / `bodyReadable` capture the outcome
 * of that read so the control loop can deny-close on framing violations without
 * this layer re-deciding them.
 */
export interface InboundRequest {
  readonly method: string;
  readonly path: string;
  /** Raw inbound header names → values (single-valued; original case kept). */
  readonly headers: Readonly<Record<string, string | undefined>>;
  /** The already-read request body (empty buffer for bodyless methods). */
  readonly body: Buffer;
  /** True when the body exceeded the bounded framing limit during read. */
  readonly bodyTooLarge: boolean;
  /** False when the body could not be read (aborted / stream error). */
  readonly bodyReadable: boolean;
}

/** Classify the top-level JSON shape of a body, without trusting its contents. */
function classifyJsonShape(body: Buffer): { shape: JsonShape; value: unknown } {
  if (body.length === 0) {
    return { shape: 'not_json', value: undefined };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf-8'));
  } catch {
    return { shape: 'not_json', value: undefined };
  }
  if (Array.isArray(parsed)) {
    return { shape: 'array', value: parsed };
  }
  if (parsed !== null && typeof parsed === 'object') {
    return { shape: 'object', value: parsed };
  }
  return { shape: 'scalar', value: parsed };
}

function readString(obj: Record<string, unknown>, key: string): string | null {
  const v = obj[key];
  return typeof v === 'string' ? v : null;
}

/**
 * Normalize an inbound request into portable {@link RequestFacts}.
 *
 * `protected`, `bundleActive` and the action mapping come from configuration;
 * the framing / JSON-RPC facts come from the request itself. ALL presented
 * header names are forwarded as `reservedHeadersPresented` so the core — not this
 * layer — decides what is reserved and gets stripped.
 */
export function buildFacts(inbound: InboundRequest, config: SidecarConfig): RequestFacts {
  const presentedHeaderNames = Object.keys(inbound.headers);

  // Bodyless / non-JSON framing facts still flow to the core, which owns the
  // deny-closed classification. We only surface what we observed.
  const { shape, value } = classifyJsonShape(inbound.body);

  let jsonrpc: string | null = null;
  let rpcMethod: string | null = null;
  let toolName: string | null = null;
  let actionMapped = false;
  let action: string | null = null;

  if (shape === 'object') {
    const obj = value as Record<string, unknown>;
    jsonrpc = readString(obj, 'jsonrpc');
    rpcMethod = readString(obj, 'method');
    if (rpcMethod === 'tools/call') {
      const params = obj['params'];
      if (params !== null && typeof params === 'object') {
        toolName = readString(params as Record<string, unknown>, 'name');
      }
      if (toolName !== null && Object.prototype.hasOwnProperty.call(config.actionMap, toolName)) {
        actionMapped = true;
        action = config.actionMap[toolName] ?? toolName;
      }
    }
  }

  return {
    protected: config.protectedSurface,
    bundleActive: config.bundleActive,
    method: inbound.method,
    reservedHeadersPresented: presentedHeaderNames,
    bodyReadable: inbound.bodyReadable,
    bodyTooLarge: inbound.bodyTooLarge,
    jsonShape: shape,
    jsonrpc,
    rpcMethod,
    toolName,
    actionMapped,
    action,
  };
}
