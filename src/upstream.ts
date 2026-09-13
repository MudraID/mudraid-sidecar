/**
 * The upstream forwarder seam.
 *
 * The forwarder is the ONLY thing that can move a request to the wrapped
 * application. It is injectable so tests exercise enforcement with no real
 * network — and, crucially, so a test can assert the forwarder is NEVER invoked
 * on any deny / deny-closed path. The proxy core calls it from exactly one call
 * site, guarded by a bound allow.
 */

export interface ForwardedRequest {
  readonly method: string;
  readonly path: string;
  /** Outgoing headers: client reserved headers already stripped, trusted context injected. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
}

export interface UpstreamResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: Buffer;
}

export type UpstreamForwarder = (req: ForwardedRequest) => Promise<UpstreamResponse>;

/** Forward once to one configured origin, with bounded time and response size. */
export function httpUpstreamForwarder(baseUrl: string): UpstreamForwarder {
  const base = new URL(baseUrl);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash || base.pathname !== '/') {
    throw new Error('Upstream must be an HTTP origin without embedded credentials');
  }
  const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length']);
  const excludedHeaders = (entries: Iterable<[string, string]>): Set<string> => {
    const excluded = new Set(hopHeaders);
    for (const [name, value] of entries) {
      if (name.toLowerCase() === 'connection') {
        for (const token of value.split(',')) excluded.add(token.trim().toLowerCase());
      }
    }
    return excluded;
  };
  return async (req) => {
    // Origin-form only. Never let request syntax replace the configured host.
    if (!req.path.startsWith('/') || req.path.startsWith('//') || req.path.includes('\\')) throw new Error('Invalid upstream path');
    const url = new URL(req.path, base);
    if (url.origin !== base.origin) throw new Error('Upstream origin changed');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const requestExcluded = excludedHeaders(Object.entries(req.headers));
      const requestHeaders = Object.fromEntries(Object.entries(req.headers).filter(([name]) => !requestExcluded.has(name.toLowerCase())));
      const init: RequestInit = {method: req.method, headers: requestHeaders, redirect: 'error', signal: controller.signal};
      if (req.method !== 'GET' && req.method !== 'HEAD' && req.body.length > 0) init.body = new Uint8Array(req.body);
      const resp = await fetch(url, init);
      const chunks: Uint8Array[] = [];
      let total = 0;
      if (resp.body) {
        const reader = resp.body.getReader();
        try {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            total += chunk.value.byteLength;
            if (total > 8 * 1024 * 1024) throw new Error('Upstream response exceeds limit');
            chunks.push(chunk.value);
          }
        } finally { await reader.cancel(); }
      }
      const headers: Record<string, string> = {};
      const responseExcluded = excludedHeaders(resp.headers.entries());
      resp.headers.forEach((value, key) => {
        // fetch decompresses bodies; do not forward stale compressed framing.
        if (!responseExcluded.has(key.toLowerCase()) && key.toLowerCase() !== 'content-encoding') headers[key] = value;
      });
      return {status: resp.status, headers, body: Buffer.concat(chunks)};
    } finally { clearTimeout(timer); }
  };
}
