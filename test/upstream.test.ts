import { afterEach, describe, expect, it, vi } from 'vitest';
import { httpUpstreamForwarder } from '../src/upstream.js';

const request = {method: 'POST', path: '/mcp', body: Buffer.from('{}'), headers: {host: 'attacker.example', 'content-length': '999', 'content-type': 'application/json'}};
afterEach(() => vi.unstubAllGlobals());

describe('bounded upstream forwarding', () => {
  it('removes headers nominated by Connection in each direction, case insensitively', async () => {
    const fetcher = vi.fn(async () => new Response('ok', {headers: {
      Connection: 'X-Internal, keep-alive', 'X-Internal': 'private', 'X-End-To-End': 'kept',
    }}));
    vi.stubGlobal('fetch', fetcher);
    const result = await httpUpstreamForwarder('http://localhost')({...request, headers: {
      ...request.headers, Connection: ' X-Private , KEEP-ALIVE ', 'X-Private': 'private', 'X-End-To-End': 'kept',
    }});
    const [, init] = fetcher.mock.calls[0] as unknown as [URL, RequestInit];
    expect(init.headers).not.toHaveProperty('Connection');
    expect(init.headers).not.toHaveProperty('X-Private');
    expect(init.headers).toHaveProperty('X-End-To-End', 'kept');
    expect(result.headers).not.toHaveProperty('x-internal');
    expect(result.headers).toHaveProperty('x-end-to-end', 'kept');
  });
  it('forwards once to the configured origin and removes obsolete framing', async () => {
    const fetcher = vi.fn(async () => new Response('ok', {headers: {'content-encoding': 'gzip', 'content-length': '999', 'content-type': 'text/plain'}}));
    vi.stubGlobal('fetch', fetcher);
    const result = await httpUpstreamForwarder('http://127.0.0.1:8080')(request);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = fetcher.mock.calls[0] as unknown as [URL, RequestInit];
    expect(url.origin).toBe('http://127.0.0.1:8080');
    expect(init.redirect).toBe('error');
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.headers).not.toHaveProperty('host');
    expect(init.headers).not.toHaveProperty('content-length');
    expect(result.headers).not.toHaveProperty('content-encoding');
    expect(result.headers).not.toHaveProperty('content-length');
  });
  it('refuses target substitution and embedded upstream credentials', async () => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    expect(() => httpUpstreamForwarder('http://user:pass@localhost')).toThrow();
    for (const path of ['//evil.example/mcp', '/\\evil.example/mcp', 'https://evil.example']) {
      await expect(httpUpstreamForwarder('http://localhost')({...request, path})).rejects.toThrow();
    }
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('refuses oversized responses instead of buffering without limit', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new Uint8Array(8 * 1024 * 1024 + 1))));
    await expect(httpUpstreamForwarder('http://localhost')(request)).rejects.toThrow(/exceeds limit/);
  });
});
