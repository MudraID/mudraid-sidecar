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

/**
 * A real `fetch`-based forwarder to a configured upstream base URL. Provided for
 * the runtime server; every test injects a fake instead. A production-grade
 * forwarder (streaming, retries, connection pooling, timeouts) is a later slice.
 */
export function httpUpstreamForwarder(baseUrl: string): UpstreamForwarder {
  const base = baseUrl.replace(/\/+$/, '');
  return async (req) => {
    const url = `${base}${req.path.startsWith('/') ? req.path : `/${req.path}`}`;
    const init: RequestInit = {
      method: req.method,
      headers: { ...req.headers },
    };
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.body.length > 0) {
      // Uint8Array is an accepted BodyInit; avoids a Buffer/ArrayBuffer cast.
      init.body = new Uint8Array(req.body);
    }
    const resp = await fetch(url, init);
    const bodyBuf = Buffer.from(await resp.arrayBuffer());
    const headers: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      headers[key] = value;
    });
    return { status: resp.status, headers, body: bodyBuf };
  };
}
