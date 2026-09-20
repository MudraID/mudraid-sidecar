/**
 * Focused sidecar enforcement tests.
 *
 * These pin the security-critical proxy invariants directly, with a spy upstream
 * forwarder so a deny path can be proven to NEVER proxy.
 */

import { describe, expect, it, vi } from 'vitest';

import { staticDecideClient, type DecideClient } from '@mudraid/adapter-node';

import type { SidecarConfig } from '../src/config.js';
import { enforce, type ProxyDeps } from '../src/proxy.js';
import type { InboundRequest } from '../src/facts.js';
import type { ForwardedRequest, UpstreamForwarder, UpstreamResponse } from '../src/upstream.js';

const OK_UPSTREAM: UpstreamResponse = {
  status: 200,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from('{"ok":true}'),
};

/** A spy forwarder recording every call; returns a fixed 200 upstream response. */
function spyForwarder(): {
  forward: UpstreamForwarder;
  calls: ForwardedRequest[];
} {
  const calls: ForwardedRequest[] = [];
  const forward = vi.fn(async (req: ForwardedRequest): Promise<UpstreamResponse> => {
    calls.push(req);
    return OK_UPSTREAM;
  });
  return { forward, calls };
}

/** A forwarder that fails the test if it is ever invoked (must-not-proxy). */
function forbiddenForwarder(): UpstreamForwarder {
  return vi.fn(async (): Promise<UpstreamResponse> => {
    throw new Error('upstream forwarder must NOT be called on a deny path');
  });
}

const baseConfig: SidecarConfig = {
  upstreamBaseUrl: 'http://upstream.internal',
  protectedSurface: true,
  bundleActive: true,
  actionMap: { issue_refund: 'issue_refund' },
  maxBodyBytes: 1_048_576,
};

function toolCallInbound(
  toolName: string,
  extraHeaders: Record<string, string> = {},
): InboundRequest {
  const body = Buffer.from(
    JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: { name: toolName } }),
  );
  return {
    method: 'POST',
    path: '/mcp',
    headers: { 'content-type': 'application/json', ...extraHeaders },
    body,
    bodyTooLarge: false,
    bodyReadable: true,
  };
}

describe('bound allow forwards exactly once with trusted context', () => {
  it('forwards the evaluated snapshot even if the caller mutates input during authorization', async () => {
    const inbound = toolCallInbound('issue_refund', {authorization: 'Bearer original'});
    const originalBody = Buffer.from(inbound.body);
    const {forward, calls} = spyForwarder();
    const result = await enforce(inbound, {
      config: baseConfig,
      decide: async () => {
        inbound.body.fill(32);
        (inbound.headers as Record<string, string>)['authorization'] = 'Bearer changed';
        return {status: 'allow', decisionId: 'snapshot-decision'};
      },
      forwardUpstream: forward,
    });
    expect(result.forwarded).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.body).toEqual(originalBody);
    expect(calls[0]!.headers['authorization']).toBe('Bearer original');
  });
  it('forwards a mapped, authorized tool call to the upstream exactly once', async () => {
    const { forward, calls } = spyForwarder();
    const deps: ProxyDeps = {
      config: baseConfig,
      decide: staticDecideClient({ status: 'allow', decisionId: 'fixed-decision-id' }),
      forwardUpstream: forward,
    };

    const result = await enforce(toolCallInbound('issue_refund'), deps);

    expect(result.forwarded).toBe(true);
    expect(result.status).toBe(200);
    expect(calls).toHaveLength(1);

    // Injected trusted context reaches the upstream on the bound allow.
    const fwd = calls[0]!;
    expect(fwd.headers['x-mudraid-action-key']).toBe('issue_refund');
    expect(fwd.headers['x-mudraid-decision-id']).toBe('fixed-decision-id');
  });

  it('strips client-forged x-mudraid-* headers before forwarding', async () => {
    const { forward, calls } = spyForwarder();
    const deps: ProxyDeps = {
      config: baseConfig,
      decide: staticDecideClient({ status: 'allow', decisionId: 'real-id' }),
      forwardUpstream: forward,
    };

    // Client forges trusted context: an attacker-supplied decision id + action key.
    const inbound = toolCallInbound('issue_refund', {
      'x-mudraid-decision-id': 'FORGED',
      'X-MudraID-Action-Key': 'admin_override',
      authorization: 'Bearer keep-me',
    });

    const result = await enforce(inbound, deps);
    expect(result.forwarded).toBe(true);
    const fwd = calls[0]!;

    // No forged value survives: the decision id is the real one, the action key
    // is the authorized action, and no stray x-mudraid-* header remains.
    expect(fwd.headers['x-mudraid-decision-id']).toBe('real-id');
    expect(fwd.headers['x-mudraid-action-key']).toBe('issue_refund');
    const reservedForwarded = Object.keys(fwd.headers).filter((h) =>
      h.toLowerCase().startsWith('x-mudraid-'),
    );
    expect(reservedForwarded.sort()).toEqual(['x-mudraid-action-key', 'x-mudraid-decision-id']);
    // Non-reserved headers pass through untouched.
    expect(fwd.headers['authorization']).toBe('Bearer keep-me');
  });
});

describe('deny NEVER proxies to the upstream', () => {
  it('explicit /decide deny returns 403 and does not call the forwarder', async () => {
    const forward = forbiddenForwarder();
    const deps: ProxyDeps = {
      config: baseConfig,
      decide: staticDecideClient({ status: 'deny', reason: 'amount_limit_exceeded' }),
      forwardUpstream: forward,
    };

    const result = await enforce(toolCallInbound('issue_refund'), deps);

    expect(result.forwarded).toBe(false);
    expect(result.status).toBe(403);
    expect(result.decision.adapterCode).toBe('ENFORCE_DECISION_DENY');
    expect(forward).not.toHaveBeenCalled();
  });

  it('unmapped action returns 403 and does not call the forwarder', async () => {
    const forward = forbiddenForwarder();
    const deps: ProxyDeps = {
      config: { ...baseConfig, actionMap: {} },
      // A decide seam that would allow — proving the deny happens BEFORE /decide
      // and the allow can never leak to a forward.
      decide: staticDecideClient({ status: 'allow' }),
      forwardUpstream: forward,
    };

    const result = await enforce(toolCallInbound('issue_refund'), deps);

    expect(result.forwarded).toBe(false);
    expect(result.status).toBe(403);
    expect(result.decision.adapterCode).toBe('ENFORCE_ACTION_UNMAPPED');
    expect(forward).not.toHaveBeenCalled();
  });
});

describe('deny-closed paths', () => {
  it('no active bundle → 503 deny-closed, upstream not called', async () => {
    const forward = forbiddenForwarder();
    const deps: ProxyDeps = {
      config: { ...baseConfig, bundleActive: false },
      decide: staticDecideClient({ status: 'allow' }),
      forwardUpstream: forward,
    };

    const result = await enforce(toolCallInbound('issue_refund'), deps);

    expect(result.forwarded).toBe(false);
    expect(result.status).toBe(503);
    expect(result.decision.outcome).toBe('not_safely_decided');
    expect(result.decision.adapterCode).toBe('ENFORCE_NO_VALID_BUNDLE');
    expect(forward).not.toHaveBeenCalled();
  });

  it('/decide unavailable (timeout) → 503 deny-closed, upstream not called', async () => {
    const forward = forbiddenForwarder();
    const deps: ProxyDeps = {
      config: baseConfig,
      decide: staticDecideClient({ status: 'timeout' }),
      forwardUpstream: forward,
    };

    const result = await enforce(toolCallInbound('issue_refund'), deps);

    expect(result.forwarded).toBe(false);
    expect(result.status).toBe(503);
    expect(result.decision.adapterCode).toBe('ENFORCE_DECIDE_UNAVAILABLE');
    expect(forward).not.toHaveBeenCalled();
  });

  it('unconfigured decide seam (default runtime posture) → deny-closed, not proxied', async () => {
    const forward = forbiddenForwarder();
    const decide: DecideClient = staticDecideClient({ status: 'unconfigured' });
    const deps: ProxyDeps = { config: baseConfig, decide, forwardUpstream: forward };

    const result = await enforce(toolCallInbound('issue_refund'), deps);

    expect(result.forwarded).toBe(false);
    expect(result.status).toBe(503);
    expect(forward).not.toHaveBeenCalled();
  });
});

describe('deny response body carries only typed, secret-free fields', () => {
  it('surfaces the adapter code + reason, never internal detail', async () => {
    const deps: ProxyDeps = {
      config: baseConfig,
      decide: staticDecideClient({ status: 'deny', reason: 'amount_limit_exceeded' }),
      forwardUpstream: spyForwarder().forward,
    };
    const result = await enforce(toolCallInbound('issue_refund'), deps);
    const payload = JSON.parse(result.body.toString('utf-8')) as Record<string, unknown>;
    expect(payload['code']).toBe('ENFORCE_DECISION_DENY');
    expect(payload['reason']).toBe('amount_limit_exceeded');
    expect(typeof payload['message']).toBe('string');
  });
});


it('explains expired authorization and never forwards or automatically retries', async () => {
  const forward = forbiddenForwarder();
  const decide = vi.fn(staticDecideClient({status: 'expired'}));
  const result = await enforce(toolCallInbound('issue_refund'), {
    config: baseConfig, decide, forwardUpstream: forward,
  });
  expect(result.status).toBe(503);
  expect(result.forwarded).toBe(false);
  expect(forward).not.toHaveBeenCalled();
  expect(decide).toHaveBeenCalledTimes(1);
  const payload = JSON.parse(result.body.toString('utf-8'));
  expect(payload.code).toBe('ENFORCE_DECIDE_UNAVAILABLE');
  expect(payload.reason).toBe('deadline_exceeded');
  expect(payload.message).toContain('Authorization expired');
  expect(payload.message).toContain('This attempt was not forwarded');
  expect(payload.message).toContain('Obtain fresh authorization');
  expect(payload.message).not.toContain('could not be reached');
});
