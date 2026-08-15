# `@mudraid/sidecar` — customer-hosted enforcing sidecar

A reverse-proxy sidecar that enforces MudraID **V2** in front of an upstream
**MCP server**, so an MCP server on any language stack can be protected
**without embedding a language-specific library**. This is the **first slice**
of EP-120-US-06.

> **What V2 covers. Read this before configuring the sidecar.**
>
> MudraID V2 provides live action authorization for MCP Streamable HTTP tool
> calls. MCP transport and session requests remain subject to the MCP server's
> normal HTTP/OAuth authentication. For ordinary REST APIs, use MudraID's
> route/scope middleware, which enforces the configured HTTP method and
> route—including GET and DELETE.
>
> The V2 control loop treats `GET`/`HEAD`/`OPTIONS` as Streamable-HTTP transport
> and `DELETE` as MCP session control, and calls `/decide` for neither. Fronting
> an ordinary REST API with this sidecar therefore does not authorize its reads
> and deletes. MCP control and discovery messages (`initialize`, `ping`,
> `tools/list`) likewise pass without a `/decide` verdict.

## The non-negotiable property: no bypass

A request reaches the upstream application **only after a bound V2 allow**.
Everything else — no active bundle, `/decide` unavailable, unmapped action, a
framing violation, an explicit deny — **deny-closes** and is never proxied. The
enforcement path is in-line: there is exactly one call site that forwards to the
upstream (`src/proxy.ts`), and it is unconditionally guarded by
`shouldForward(decision)`. The design offers no path around it.

> **A sidecar beside a publicly reachable app is _installed_, not _enforcing_.**
> The topology guarantee is the operator's responsibility: **direct network
> access to the upstream must be restricted to the sidecar** (e.g. the upstream
> binds loopback / a private network namespace; only the sidecar's port is
> exposed). The sidecar enforces in-line; the network must make it the only way
> in.

An **unconfigured** sidecar is safe: with no real `/decide` client wired it runs
a deny-closed `unconfigured` seam and with no active bundle it returns
`ENFORCE_NO_VALID_BUNDLE` — it **denies**, it does not fail open.

## How the adapter-node core is consumed

The V2 decision is **not re-implemented here**. The sidecar reuses the
framework-neutral control loop from the sibling package
`sdks/mudraid-adapter-node` (`evaluateV2`, the `DecideClient` seam, the typed
closed-union vocabulary) as its decision core.

**Consumption method: relative source reference.** `@mudraid/adapter-node` is an
unpublished, private local package, so instead of a real npm dependency +
publish, the specifier `@mudraid/adapter-node` is aliased to that package's
`src/index.ts`:

- **typecheck** — `tsconfig.json` `compilerOptions.paths`;
- **tests / runtime** — `vitest.config.ts` `resolve.alias`, and `tsx` honours the
  same tsconfig `paths`.

This keeps `npm ci && npm test` fully self-contained (no build of the core, no
publish) while exercising the **exact same** decision code — never a copy — so
the two packages cannot drift. The tests also reuse the core's pinned
adapter-decision corpus by relative path (`test/corpus-no-bypass.test.ts`).

## Fail / degrade / restart / drain intent

- **Fail closed.** Any evaluation that is not a bound allow denies; a thrown
  `/decide` transport error is caught and deny-closed with no detail surfaced.
- **Degrade closed.** `/decide` timeout / unreachable / unconfigured →
  `503 ENFORCE_DECIDE_UNAVAILABLE`; a stale / missing bundle →
  `503 ENFORCE_NO_VALID_BUNDLE`. Degradation never opens the upstream.
- **Restart.** The sidecar is stateless per request; on restart it comes up
  deny-closed until configured, so a restart window cannot leak an allow.
- **Drain.** In-flight requests complete through the single guarded path; new
  requests continue to be evaluated. (Graceful-drain wiring / connection
  lifecycle hardening is a later slice.)

## Develop

```bash
npm ci
npm run typecheck
npm test
# run locally (deny-closed until a real /decide client + bundle are configured):
npm start
```

## Build the image

Build context is the **`sdks/` directory** (the parent), because the core is
consumed by relative source reference:

```bash
docker build -f sdks/mudraid-sidecar/Dockerfile -t mudraid-sidecar sdks/
```

## Deferred remainders (NOT in this slice)

- Signed-config distribution + provenance verification; live bundle activation.
- The containment channel.
- ECS / Kubernetes reference deployments + bypass-resistance topology tests.
- Chaos / soak / resource-limit + network-bypass-attack suites.
- The real authenticated HTTP `/decide` client (only the injectable seam +
  in-memory fakes exist today).
- Cross-language sample apps.
- Multi-arch image **publish** (the image is build-valid; publishing is later).
