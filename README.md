# MudraID enforcing sidecar

A customer-hosted reverse proxy for MCP Streamable HTTP servers. Protected tool calls require an active, verified configuration and a signed live authorization decision before the request is forwarded.

MCP transport/session requests and control messages such as `initialize`, `ping` and `tools/list` do not receive a tool authorization decision. The upstream must enforce its normal HTTP/OAuth authentication for them. For ordinary REST APIs, use the route/scope middleware: this sidecar does not authorize REST GET or DELETE operations.

## Runtime configuration

Run the compiled package with Node 20 or later. No TypeScript runtime, development dependencies or sibling repository is required after installation.

Set all authority values together:

| Setting | Value |
|---|---|
| `MUDRAID_API_URL` | MudraID HTTPS origin |
| `MUDRAID_ADAPTER_TOKEN` | Credential issued for this registered adapter; keep secret |
| `MUDRAID_PLATFORM_ID` | Registered protected surface identifier |
| `MUDRAID_ENVIRONMENT` | That surface's environment |
| `MUDRAID_RESOURCE_URI` | Exact canonical protected resource URI |
| `MUDRAID_UPSTREAM_URL` | Fixed HTTP(S) upstream origin; defaults to local port 8080 |
| `PORT` | Listening port; defaults to 8000 |

The adapter credential identifies the enforcement point. The inbound caller's OAuth token identifies the caller; it cannot substitute for the adapter credential. Partial authority configuration fails startup. Without authority configuration, protected tool calls remain denied. Environment flags cannot activate a bundle.

Configuration refresh checks signed content, platform/environment/resource bindings, desired version/digest and validity. Decisions require a trusted signature, matching request decision identifier, action/configuration binding and an unexpired deadline. Authority failures deny protected calls. Decisions and upstream calls are not automatically retried.

Restrict direct access to the upstream so clients cannot bypass the proxy. A forward attempt is not proof that the application committed a business operation. An observed decision acknowledgement is likewise not an execution receipt.

## Build and test

From the sidecar source directory in the development repository or prepared public mirror:

```sh
npm ci
npm run typecheck
npm test
npm run build
npm start
```

The build bundles the exact adapter source from the same checkout. A public mirror includes that reviewed source under `vendor/adapter-node`; it does not fetch a floating branch. The installed artifact contains compiled JavaScript, the adapter license and `dist/build-inputs.json` with source hashes. That inventory supplements, rather than replaces, signed release provenance.

The release workflow packs once, inspects the tarball and tests an isolated installation on each supported Node release line. Publication still requires the protected environment approval. A successful local build does not establish publication or live qualification.

## Container

From the development repository root:

```sh
docker build -f sdks/mudraid-sidecar/Dockerfile -t mudraid-sidecar sdks/
```

The image uses a build stage and runs compiled code as the unprivileged Node user. Its build context includes the reviewed adapter source. The public npm mirror does not include this repository-specific Docker recipe.

## Qualification still pending

Exact body bytes, caller, HTTP target and action/configuration are now bound to the signed decision, and the sidecar forwards its owned authorized snapshot. Trusted business-fact profiles and policy projection remain unimplemented; the runtime must not be represented as proving independent business-state truth or a committed operation. Standalone installed-package checks also do not establish network bypass resistance, containment-channel convergence, graceful drain, chaos/soak behavior or multi-architecture publication. These require their respective runtime evidence before broader support claims.


### Authorization expires before forwarding

A verified decision that arrives after its deadline is refused with HTTP 503,
`ENFORCE_DECIDE_UNAVAILABLE`, and reason `deadline_exceeded`. The message explains
that authorization expired and this attempt was not forwarded. This differs
from an unreachable authority; it does not mean that permission was denied.
The adapter does not automatically retry. A deliberate retry must obtain a fresh
decision. Use application-level idempotency for operations that could already
have executed in an earlier attempt; this error makes no claim about those
other attempts. Never reuse an expired decision or disable expiry validation.
