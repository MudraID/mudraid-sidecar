# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Report it privately to
**security@mudraid.ai**, and we will acknowledge within **2 business days**.

Please include, as far as you can establish it:

- what an attacker can do — the effect, not only the flaw;
- the version you tested, and how you deployed it;
- a reproduction, or the smallest thing that shows the behaviour.

You will get a substantive reply, not only an acknowledgement: what we
reproduced, what we could not, and what we intend to do. If we disagree that
something is a vulnerability we will say so and explain why, rather than letting
the report go quiet.

We will not pursue legal action over good-faith research that stays within your
own accounts and data, does not degrade the service for others, and does not
access or retain anyone else's information.

## What is in scope

This repository — the sidecar's proxying, its enforcement wiring, and the
operator guidance its README gives.

The MudraID service it talks to is a separate system with the same contact
address, and a report about one is welcome under the other; we would rather
route it ourselves than have you guess which it belongs to.

**`@mudraid/adapter-node` is a different package with its own policy.** It is
the decision core this sidecar hosts; a report about the V2 control loop's
decisions themselves belongs there. Both addresses are the same, so a misrouted
report is not a lost one.

## What this package does and does not do

Worth stating plainly, because a report is often about the difference. This is
a **customer-hosted enforcing reverse proxy**: a request reaches the upstream
application only after a bound V2 allow.

- There is exactly one call site that forwards to the upstream, and it is
  unconditionally guarded by `shouldForward(decision)`. **Any request that
  reaches the upstream without a bound V2 allow — an error path that proxies,
  a method or framing shape that skips evaluation, a response served from the
  upstream on a deny — is a vulnerability**, and is the class of report we
  most want.
- An **unconfigured** sidecar denies; it does not fail open. `/decide`
  unavailable, no active bundle, an unmapped action — all deny-close. **A
  configuration state under which it forwards by default is a vulnerability.**
- Reserved trusted-context headers exist so the upstream can trust what the
  sidecar asserted. Caller-supplied values for them are stripped before
  evaluation and before forwarding; **a route by which a caller-controlled
  reserved header reaches the upstream is a vulnerability.**
- It holds the credential it presents to `/decide` and never logs it. **A
  credential or bearer token appearing in any log line is a vulnerability**,
  even when nothing else is exploitable.
- It does **not** implement the topology guarantee, and the README says so: a
  sidecar beside a publicly reachable upstream is installed, not enforcing.
  Restricting direct network access to the upstream is the operator's
  deployment, not this package's code — a report that the upstream was
  reachable *around* the sidecar is a deployment finding unless the sidecar
  itself provided the path.

## Supported versions

Maturity and support for every published version are declared in the MudraID
adapter support matrix (the `support-matrix.json` excerpt shipped beside this
package names this package's rows). Report against the latest published version
where you can, and say which version you tested where you cannot.
