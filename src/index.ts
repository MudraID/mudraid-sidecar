/** MudraID MCP enforcing proxy. Shares the adapter decision core.
 * Authenticated configuration and signed decisions are implemented;
 * exact-request binding is implemented. Trusted business facts and deployment
 * qualification remain open.
 */

export { DEFAULT_MAX_BODY_BYTES, type SidecarConfig } from './config.js';
export { buildFacts, type InboundRequest } from './facts.js';
export { enforce, type ProxyDeps, type SidecarResponse } from './proxy.js';
export {
  httpUpstreamForwarder,
  type ForwardedRequest,
  type UpstreamForwarder,
  type UpstreamResponse,
} from './upstream.js';
export { createSidecarServer, main } from './server.js';

// Re-export the decision-core seam so sidecar embedders wire `/decide` and the
// typed vocabulary from one place, against the exact same core the proxy uses.
export {
  HttpAuthority,
  type AuthorityOptions,
  staticDecideClient,
  throwingDecideClient,
  type AdapterCode,
  type Decision,
  type DecideClient,
  type DecideResult,
  type DecideStatus,
  type RequestFacts,
} from '@mudraid/adapter-node';
