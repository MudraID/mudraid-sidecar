import { describe, expect, it, vi } from 'vitest';
import { staticDecideClient } from '@mudraid/adapter-node';
import { DEFAULT_MAX_BODY_BYTES } from '../src/config.js';
import { enforce } from '../src/proxy.js';
import { configFromEnv } from '../src/server.js';

describe('standalone sidecar configuration', () => {
  it('cannot activate an unverified bundle through an environment assertion', async () => {
    const { config } = configFromEnv({ MUDRAID_BUNDLE_ACTIVE: 'true' });
    const forwardUpstream = vi.fn();
    const decide = vi.fn(
      staticDecideClient({ status: 'allow', decisionId: 'test-decision' }),
    );
    const response = await enforce(
      {
        method: 'POST',
        path: '/mcp',
        headers: {},
        bodyTooLarge: false,
        bodyReadable: true,
        body: Buffer.from(
          JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
        ),
      },
      { config, decide, forwardUpstream },
    );
    expect(response.forwarded).toBe(false);
    expect(response.status).toBe(503);
    expect(response.decision.adapterCode).toBe('ENFORCE_NO_VALID_BUNDLE');
    expect(decide).not.toHaveBeenCalled();
    expect(forwardUpstream).not.toHaveBeenCalled();
  });

  it.each(['NaN', 'Infinity', '-1', '0', '', '1.5', '9007199254740992'])(
    'rejects an unsafe body limit %j before accepting traffic',
    (value) => {
      expect(() => configFromEnv({ MUDRAID_MAX_BODY_BYTES: value })).toThrow(
        /MUDRAID_MAX_BODY_BYTES/,
      );
    },
  );

  it.each(['NaN', 'Infinity', '-1', '0', '', '1.5', '65536'])(
    'rejects an invalid port %j at configuration time',
    (value) => {
      expect(() => configFromEnv({ PORT: value })).toThrow(/PORT/);
    },
  );

  it('keeps safe defaults and explicit valid bounds', () => {
    expect(configFromEnv({})).toMatchObject({
      port: 8000,
      maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
      config: { protectedSurface: true, bundleActive: false },
    });
    expect(
      configFromEnv({ PORT: '65535', MUDRAID_MAX_BODY_BYTES: '128' }),
    ).toMatchObject({
      port: 65535,
      maxBodyBytes: 128,
      config: { maxBodyBytes: 128 },
    });
  });
});

it('requires the full authority binding and refuses credential-bearing API URLs', async () => {
  const {authorityFromEnv} = await import('../src/server.js');
  expect(authorityFromEnv({})).toBeUndefined();
  expect(() => authorityFromEnv({MUDRAID_ADAPTER_TOKEN: 'token'})).toThrow(/Incomplete/);
  expect(() => authorityFromEnv({MUDRAID_API_URL: 'http://api.example.com', MUDRAID_ADAPTER_TOKEN: 'token', MUDRAID_PLATFORM_ID: 'p', MUDRAID_ENVIRONMENT: 'staging', MUDRAID_RESOURCE_URI: 'https://resource.example.com'})).toThrow();
});
