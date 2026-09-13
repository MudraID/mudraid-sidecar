/**
 * `@mudraid/adapter-node` — framework-neutral TypeScript/Node server adapter for
 * MudraID enforcement (EP-120-US-05, first slice).
 *
 * Public surface: the typed decision vocabulary, the V2 control loop, and the
 * injectable `/decide` seam. The framework hooks (Express/Fastify/MCP), the real
 * HTTP `/decide` client, and live fact extraction are DEFERRED remainders.
 */

export {
  ADAPTER_DECISION_CONTRACT_VERSION,
  MAX_TOOL_NAME_LEN,
  RESERVED_HEADER_PREFIX,
  type AdapterCode,
  type Decision,
  type DecideClient,
  type DecideResult,
  type DecideStatus,
  type JsonShape,
  type Outcome,
  type ReasonTier,
  type RequestFacts,
  type TrustedContextHeader,
} from './types.js';

export {
  evaluateV2,
  isReservedHeader,
  newDecisionId,
  normalizeStrippedHeaders,
  shouldForward,
  validToolName,
} from './controlLoop.js';

export { staticDecideClient, throwingDecideClient } from './decideClient.js';

export { verifyBundle, type BundleBinding, type VerifiedBundle } from './signedBundle.js';
export { HttpAuthority, type AuthorityOptions, type InvocationContext } from './httpAuthority.js';
