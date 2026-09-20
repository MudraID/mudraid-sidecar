/**
 * Typed decision vocabulary for the MudraID Node server adapter.
 *
 * These types are the TypeScript mirror of the portable adapter-decision
 * contract `mudraid.adapter.decision/1`
 * (`shared/mudraid_contracts/mudraid_contracts/adapters/decision.py`) and of the
 * Python middleware V2 control loop
 * (`sdks/mudraid-middleware-python/src/mudraid_middleware/_v2_control_loop.py`).
 *
 * The whole point of this adapter is EXACT parity: the same facts must produce
 * the same outcome + adapter code as the Kong Lua handler and the Python
 * middleware. So every value here is a closed union — never a bare `string` —
 * so a divergent code is a compile error, not a silent runtime drift.
 */

/** Versioned identifier of the portable contract this adapter reproduces. */
export const ADAPTER_DECISION_CONTRACT_VERSION = 'mudraid.adapter.decision/1' as const;

/** Reserved request-header prefix, stripped before evaluation (contract A03-04). */
export const RESERVED_HEADER_PREFIX = 'x-mudraid-' as const;

/** Bounded canonical action-name length in bytes (matches `MAX_TOOL_NAME_LEN`). */
export const MAX_TOOL_NAME_LEN = 512 as const;

/** Closed outcome vocabulary — byte-identical to the contract's `OUTCOMES`. */
export type Outcome = 'allow' | 'deny' | 'not_safely_decided';

/** Which tier produced the reason: pre-decision framing vs. authorization. */
export type ReasonTier = 'transport' | 'authorization';

/** Shape of the parsed request body, as the fact extractor classifies it. */
export type JsonShape = 'object' | 'array' | 'scalar' | 'not_json';

/**
 * Stable, agent-facing adapter error codes. Identical to the codes the Kong Lua
 * handler and the Python middleware surface, so a Node caller sees the SAME code
 * for the SAME failure. `null` on an allow / pass-through (nothing to surface).
 */
export type AdapterCode =
  | 'ENFORCE_METHOD_NOT_ALLOWED'
  | 'ENFORCE_BODY_TOO_LARGE'
  | 'ENFORCE_BODY_UNREADABLE'
  | 'ENFORCE_MALFORMED_REQUEST'
  | 'ENFORCE_BATCH_UNSUPPORTED'
  | 'ENFORCE_MESSAGE_NOT_ALLOWED'
  | 'ENFORCE_ACTION_UNMAPPED'
  | 'ENFORCE_NO_VALID_BUNDLE'
  | 'ENFORCE_DECISION_DENY'
  | 'ENFORCE_DECIDE_UNAVAILABLE';

/**
 * The failure-aware outcome vocabulary a live `/decide` call reports back to the
 * control loop.
 *
 *  - `allow` / `deny` — an authority decision was reached;
 *  - `expired` — a verified decision arrived after its deadline; do not execute;
 *  - `timeout` / `error` / `unreachable` / `unconfigured` /
 *    `credential_unconfigured` — the call could not be completed; every one is
 *    deny-closed (`not_safely_decided`), never optimistically allowed.
 */
export type DecideStatus =
  | 'allow'
  | 'deny'
  | 'expired'
  | 'timeout'
  | 'error'
  | 'unreachable'
  | 'unconfigured'
  | 'credential_unconfigured';

/** The outcome of one live `/decide` call, as the adapter sees it. */
export interface DecideResult {
  readonly status: DecideStatus;
  /** A `/decide`-supplied deny reason code (only meaningful on `status: 'deny'`). */
  readonly reason?: string;
  /** Correlation id forwarded as trusted context on an allow. */
  readonly decisionId?: string;
}

/**
 * The injectable `/decide` seam. The control loop invokes it EXACTLY at the
 * `/decide` branch (a mapped `tools/call` on an active bundle) and nowhere else.
 * Tests inject a fake so no network is required; the real HTTP client is a
 * deferred remainder of this story.
 */
export type DecideClient = (action: string) => Promise<DecideResult>;

/**
 * The normalized facts a single evaluation consumes. Mirrors the portable
 * contract's decision facts. Fact *extraction* from a live framework request is
 * a deferred remainder; the decision *tree* lives only in `evaluateV2`, so
 * extraction and decision never drift into two competing policy copies.
 */
export interface RequestFacts {
  /** Whether this surface is a bundled (protected) MudraID surface. */
  readonly protected: boolean;
  /** Reserved `x-mudraid-*` headers the client presented (original case kept). */
  readonly reservedHeadersPresented?: readonly string[];
  /** Whether a verified signed bundle is currently active. */
  readonly bundleActive: boolean;
  readonly method: string;
  readonly bodyReadable?: boolean;
  readonly bodyTooLarge?: boolean;
  readonly jsonShape?: JsonShape;
  readonly jsonrpc?: string | null;
  readonly rpcMethod?: string | null;
  readonly toolName?: string | null;
  /** Whether an exact canonical action is mapped for this tool. */
  readonly actionMapped?: boolean;
  /** Resolved canonical action name, if distinct from `toolName`. */
  readonly action?: string | null;
}

/** A trusted-context header injected downstream, only on a bound allow. */
export type TrustedContextHeader = readonly [name: string, value: string];

/** The normalized outcome of one V2 evaluation. */
export interface Decision {
  readonly outcome: Outcome;
  readonly reasonCode: string;
  readonly reasonTier: ReasonTier;
  readonly httpStatus: number;
  readonly adapterCode: AdapterCode | null;
  /** Stable agent-facing message; never contains secrets or token material. */
  readonly message: string;
  /** Reserved headers stripped from the request before evaluation. */
  readonly strippedReservedHeaders: readonly string[];
  /** Injected only on an authorized allow; empty on every pass-through/deny. */
  readonly trustedContext: readonly TrustedContextHeader[];
}
