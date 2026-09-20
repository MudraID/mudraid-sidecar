/**
 * V2 enforcement control loop — the adapter-decision semantics, natively in TS.
 *
 * This module encodes the portable adapter-decision contract
 * (`mudraid.adapter.decision/1`) directly, so a Node platform reaches the SAME
 * normalized outcome as the Kong `mudraid-enforce` Lua handler, the reference
 * runner in `shared/mudraid_contracts`, and the Python middleware — for the same
 * facts.
 *
 * The decision-tree order mirrors `handler.lua:access` (and the Python
 * `_v2_control_loop.evaluate_v2`) EXACTLY:
 *
 *   1. reserved `x-mudraid-*` headers are stripped FIRST, before any evaluation,
 *      and even on requests that will be denied — trusted context is never
 *      accepted as an input fact;
 *   2. fail CLOSED when no verified signed bundle is active → not_safely_decided;
 *   3. method classification — control verbs pass, non-POST denies;
 *   4. bounded JSON-RPC framing — oversized/unreadable bodies deny, a JSON
 *      *array* (batch) is rejected wholesale, never partially evaluated;
 *   5. exact, case-sensitive canonical action resolution — never fuzzy/prefix;
 *   6. a live `/decide` call, required for every protected tool invocation and
 *      **deny-closed** on timeout/error/unconfigured;
 *   7. allow — and only then is trusted context injected downstream.
 *
 * "not safely decided" (no bundle, `/decide` timeout/error) is deny-closed,
 * never optimistically treated as allow.
 */

import { randomUUID } from 'node:crypto';

import {
  MAX_TOOL_NAME_LEN,
  RESERVED_HEADER_PREFIX,
  type AdapterCode,
  type Decision,
  type DecideClient,
  type Outcome,
  type ReasonTier,
  type RequestFacts,
  type TrustedContextHeader,
} from './types.js';

/** Streamable-HTTP control verbs — carry no JSON-RPC request, cannot invoke a tool. */
const CONTROL_VERBS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS', 'DELETE']);

/**
 * Control/discovery JSON-RPC methods allowed to pass a protected surface without
 * a tool invocation (mirrors the plugin `public_methods` default). Client
 * `notifications/*` are handled by prefix, separately.
 */
// Pre-launch scan SSC-05: `resources/list` and `prompts/list` used to be here
// while the Kong plugin and the Python middleware denied them, so the same
// client got 403 from one deployed adapter and a pass-through from another.
// Enumeration on a protected surface is disclosure; the conservative three
// are the contract, pinned by two corpus fixtures every runner consumes.
const DEFAULT_PUBLIC_METHODS: ReadonlySet<string> = new Set([
  'initialize',
  'ping',
  'tools/list',
]);

/**
 * `/decide` transport-failure mode → normalized not-safely-decided reason. Every
 * one deny-closes; the reason differs by failure mode but the surfaced adapter
 * code is uniformly `ENFORCE_DECIDE_UNAVAILABLE`.
 */
const DECIDE_UNAVAILABLE_REASONS: Readonly<Record<string, string>> = {
  expired: 'deadline_exceeded',
  timeout: 'deadline_exceeded',
  error: 'authority_source_unavailable',
  unreachable: 'authority_source_unavailable',
  unconfigured: 'adapter_config_stale',
  credential_unconfigured: 'adapter_config_stale',
};

/**
 * Reasons that are NOT deny outcomes. A `/decide` response that tries to label a
 * *deny* with one of these cannot leak an allow/soft outcome through the deny
 * path; we fall back to the generic deny reason. This is a self-contained safety
 * guard, deliberately NOT a mirror of the full governed reason-code registry
 * (this SDK takes no dependency on the internal `mudraid_contracts` package),
 * matching the Python middleware's guard. Extend only with reasons whose
 * canonical outcome is provably not "deny".
 */
const NON_DENY_REASONS: ReadonlySet<string> = new Set([
  'authorized', // allow
  'adapter_config_stale', // not_safely_decided
  'deadline_exceeded', // not_safely_decided
  'authority_source_unavailable', // not_safely_decided
]);

const DECIDE_DENY_DEFAULT_REASON = 'policy_rule_denied';

const NO_TRUSTED_CONTEXT: readonly TrustedContextHeader[] = Object.freeze([]);

/**
 * Reserved headers stripped from the request before evaluation (contract A03-04).
 *
 * Case-insensitive prefix match; applied on every protected request regardless
 * of the eventual outcome (original case is preserved for auditability). On an
 * unprotected surface the request passes through untouched, so nothing is
 * stripped.
 */
export function normalizeStrippedHeaders(
  reservedHeadersPresented: readonly string[],
  { protectedSurface }: { readonly protectedSurface: boolean },
): readonly string[] {
  if (!protectedSurface) {
    return [];
  }
  return reservedHeadersPresented.filter((h) =>
    h.toLowerCase().startsWith(RESERVED_HEADER_PREFIX),
  );
}

/** True when a header name is a reserved `x-mudraid-*` context header. */
export function isReservedHeader(name: string): boolean {
  return name.toLowerCase().startsWith(RESERVED_HEADER_PREFIX);
}

/** A usable canonical action name: non-empty, within the byte bound. */
export function validToolName(name: string | null | undefined): name is string {
  if (typeof name !== 'string') {
    return false;
  }
  const byteLen = Buffer.byteLength(name, 'utf-8');
  return byteLen > 0 && byteLen <= MAX_TOOL_NAME_LEN;
}

/** A fresh correlation id for a bound allow, forwarded as trusted context. */
export function newDecisionId(): string {
  return randomUUID();
}

function deny(
  reasonCode: string,
  tier: ReasonTier,
  httpStatus: number,
  adapterCode: AdapterCode,
  message: string,
  stripped: readonly string[],
  outcome: Outcome = 'deny',
): Decision {
  return {
    outcome,
    reasonCode,
    reasonTier: tier,
    httpStatus,
    adapterCode,
    message,
    strippedReservedHeaders: stripped,
    trustedContext: NO_TRUSTED_CONTEXT,
  };
}

function passThrough(reasonCode: string, stripped: readonly string[]): Decision {
  return {
    outcome: 'allow',
    reasonCode,
    reasonTier: 'transport',
    httpStatus: 200,
    adapterCode: null,
    message: '',
    strippedReservedHeaders: stripped,
    trustedContext: NO_TRUSTED_CONTEXT,
  };
}

/** Whether a decision means the request should forward to the wrapped handler. */
export function shouldForward(decision: Decision): boolean {
  return decision.outcome === 'allow';
}

/**
 * Reproduce the reference control loop's outcome for one request.
 *
 * `decide` is invoked EXACTLY at the `/decide` branch (a mapped `tools/call` on
 * an active bundle) and nowhere else, so a control verb, an unmapped action, or
 * a framing rejection never triggers a live call. Any transport error thrown by
 * the injected client is treated as `"error"` and deny-closed. Any "not safely
 * decided" state is deny-closed, never allow.
 */
export async function evaluateV2(facts: RequestFacts, decide: DecideClient): Promise<Decision> {
  const stripped = normalizeStrippedHeaders(facts.reservedHeadersPresented ?? [], {
    protectedSurface: facts.protected,
  });

  // 1. Unprotected surface: pass through untouched (not a bundled surface).
  if (!facts.protected) {
    return passThrough('surface_not_protected', stripped);
  }

  // 2. Fail CLOSED: no verified signed bundle active → not_safely_decided.
  if (!facts.bundleActive) {
    return deny(
      'adapter_config_stale',
      'authorization',
      503,
      'ENFORCE_NO_VALID_BUNDLE',
      'no verified signed bundle is active; request cannot be safely decided',
      stripped,
      'not_safely_decided',
    );
  }

  // 3. Method classification. Control verbs pass; anything neither a control verb
  //    nor POST is denied.
  const method = (facts.method ?? '').toUpperCase();
  if (CONTROL_VERBS.has(method)) {
    return passThrough('control_plane_passthrough', stripped);
  }
  if (method !== 'POST') {
    return deny(
      'method_not_allowed',
      'transport',
      405,
      'ENFORCE_METHOD_NOT_ALLOWED',
      'method not allowed on a protected MCP surface',
      stripped,
    );
  }

  // 4. Bounded framing: oversized/unreadable bodies deny, never partial eval.
  if (facts.bodyTooLarge === true) {
    return deny(
      'body_too_large',
      'transport',
      413,
      'ENFORCE_BODY_TOO_LARGE',
      'request body exceeds the bounded framing limit',
      stripped,
    );
  }
  if (facts.bodyReadable === false) {
    return deny(
      'body_unreadable',
      'transport',
      400,
      'ENFORCE_BODY_UNREADABLE',
      'request body could not be read',
      stripped,
    );
  }

  // 5. Parse exactly once. Non-object bodies (scalar / non-JSON) are malformed;
  //    a JSON *array* is a batch and rejected wholesale.
  const jsonShape = facts.jsonShape ?? 'object';
  if (jsonShape === 'array') {
    return deny(
      'batch_unsupported',
      'transport',
      400,
      'ENFORCE_BATCH_UNSUPPORTED',
      'JSON-RPC batch requests are not supported',
      stripped,
    );
  }
  if (jsonShape !== 'object') {
    return deny(
      'malformed_request',
      'transport',
      400,
      'ENFORCE_MALFORMED_REQUEST',
      'request body is not a single JSON-RPC 2.0 object',
      stripped,
    );
  }
  const rpcMethod = facts.rpcMethod;
  if (facts.jsonrpc !== '2.0' || typeof rpcMethod !== 'string' || rpcMethod === '') {
    return deny(
      'malformed_request',
      'transport',
      400,
      'ENFORCE_MALFORMED_REQUEST',
      'request body is not a single JSON-RPC 2.0 object',
      stripped,
    );
  }

  // 6. Non-tool protocol messages: allowlisted control/discovery + client
  //    notifications pass; everything else on a protected surface denies rather
  //    than slipping through because extraction found no action.
  if (rpcMethod !== 'tools/call') {
    if (rpcMethod.startsWith('notifications/')) {
      return passThrough('notification_passthrough', stripped);
    }
    if (DEFAULT_PUBLIC_METHODS.has(rpcMethod)) {
      return passThrough('control_plane_passthrough', stripped);
    }
    return deny(
      'message_not_allowed',
      'transport',
      403,
      'ENFORCE_MESSAGE_NOT_ALLOWED',
      'JSON-RPC method is not permitted on a protected surface',
      stripped,
    );
  }

  // 7. Exact canonical action resolution — never fuzzy.
  if (!validToolName(facts.toolName)) {
    return deny(
      'malformed_request',
      'transport',
      400,
      'ENFORCE_MALFORMED_REQUEST',
      'tools/call params.name is missing or exceeds the action-name bound',
      stripped,
    );
  }
  if (facts.actionMapped !== true) {
    return deny(
      'action_unmapped',
      'authorization',
      403,
      'ENFORCE_ACTION_UNMAPPED',
      'no exact canonical action is mapped for this tool',
      stripped,
    );
  }

  // 8. Live /decide — required for every protected call; deny-closed on
  //    timeout/error/unconfigured. A thrown transport error is treated as
  //    "error" (deny-closed), never optimistically allowed.
  const action = facts.action ?? facts.toolName;
  let result;
  try {
    result = await decide(action);
  } catch {
    // No error detail is surfaced: a transport exception may carry secrets.
    return deny(
      'authority_source_unavailable',
      'authorization',
      503,
      'ENFORCE_DECIDE_UNAVAILABLE',
      'the authority could not be reached; request cannot be safely decided',
      stripped,
      'not_safely_decided',
    );
  }

  if (result.status === 'allow') {
    const trusted: readonly TrustedContextHeader[] = [
      ['x-mudraid-action-key', action],
      ['x-mudraid-decision-id', result.decisionId ?? newDecisionId()],
    ];
    return {
      outcome: 'allow',
      reasonCode: 'authorized',
      reasonTier: 'authorization',
      httpStatus: 200,
      adapterCode: null,
      message: '',
      strippedReservedHeaders: stripped,
      trustedContext: trusted,
    };
  }

  if (result.status === 'deny') {
    let reason = result.reason ?? DECIDE_DENY_DEFAULT_REASON;
    // A decide-supplied reason that is not provably a deny code cannot leak an
    // allow/soft outcome through the deny path.
    if (NON_DENY_REASONS.has(reason)) {
      reason = DECIDE_DENY_DEFAULT_REASON;
    }
    return deny(
      reason,
      'authorization',
      403,
      'ENFORCE_DECISION_DENY',
      'the authority denied this action',
      stripped,
    );
  }

  if (result.status === 'expired') {
    return deny(
      'deadline_exceeded',
      'authorization',
      503,
      'ENFORCE_DECIDE_UNAVAILABLE',
      'Authorization expired before this request could be forwarded. This attempt was not forwarded. Obtain fresh authorization before retrying; do not automatically retry operations that may already have executed in another attempt.',
      stripped,
      'not_safely_decided',
    );
  }

  // timeout | error | unreachable | unconfigured | credential_unconfigured
  // → deny-closed 503.
  const reason = DECIDE_UNAVAILABLE_REASONS[result.status] ?? 'authority_source_unavailable';
  return deny(
    reason,
    'authorization',
    503,
    'ENFORCE_DECIDE_UNAVAILABLE',
    'the authority could not be reached; request cannot be safely decided',
    stripped,
    'not_safely_decided',
  );
}
