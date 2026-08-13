/**
 * `@mudraid/sidecar` — customer-hosted V2-enforcing reverse-proxy sidecar
 * (EP-120-US-06, first slice).
 *
 * The sidecar sits in front of an upstream application and forwards a request
 * ONLY after a bound V2 allow, reusing the `@mudraid/adapter-node` control loop
 * as its decision core (never re-implementing it). Everything else deny-closes.
 *
 * DEFERRED remainders (see README): signed-config distribution + provenance
 * verification; the containment channel; ECS/Kubernetes reference deployments +
 * bypass-resistance topology tests; chaos/soak/resource-limit + network-bypass
 * suites; the real authenticated HTTP `/decide` client (injectable seam + fakes
 * only); cross-language sample apps; multi-arch image publish.
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
  staticDecideClient,
  throwingDecideClient,
  type AdapterCode,
  type Decision,
  type DecideClient,
  type DecideResult,
  type DecideStatus,
  type RequestFacts,
} from '@mudraid/adapter-node';
