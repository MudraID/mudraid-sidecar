/** Authenticated, bounded authority transport. No decision or upstream retries. */
import { randomUUID } from 'node:crypto';
import { instant, object, verifyBundle, verifyClaims, type BundleBinding, type JsonObject, type VerifiedBundle } from './signedBundle.js';
import type { DecideResult } from './types.js';

import {bindExecution, type ExecutionContext} from './executionBinding.js';
export type InvocationContext = ExecutionContext;
export interface AuthorityOptions {
  readonly apiBase: string;
  readonly adapterToken: string;
  readonly binding: BundleBinding;
  readonly timeoutMs?: number;
  readonly adapterType?: 'node_server_adapter' | 'node_sidecar';
  readonly fetch?: typeof fetch;
}

function keyMap(entries: unknown): Record<string, string> {
  if (!Array.isArray(entries)) throw new Error('Invalid verification key set');
  const keys: Record<string, string> = Object.create(null);
  for (const entry of entries) {
    const row = object(entry);
    if (typeof row['key_id'] !== 'string' || typeof row['public_key_pem'] !== 'string' || Object.hasOwn(keys, row['key_id'])) throw new Error('Invalid verification key');
    keys[row['key_id']] = row['public_key_pem'];
  }
  return keys;
}

export class HttpAuthority {
  private readonly base: URL;
  private readonly token: string;
  private readonly binding: BundleBinding;
  private readonly timeout: number;
  private readonly adapterType: 'node_server_adapter' | 'node_sidecar';
  private readonly fetcher: typeof fetch;
  private current: VerifiedBundle | undefined;
  private lastAccepted: VerifiedBundle | undefined;
  private decisionKeys: Record<string, string> = Object.create(null);
  private refreshPending: Promise<boolean> | undefined;
  private observed: {version: number; digest: string; at: string} | undefined;

  constructor(options: AuthorityOptions) {
    this.base = new URL(options.apiBase);
    if (this.base.protocol !== 'https:' || this.base.username || this.base.password || this.base.search || this.base.hash || this.base.pathname !== '/') throw new Error('Authority must be an HTTPS origin');
    if (!options.adapterToken || options.adapterToken.length > 256 || /\s/.test(options.adapterToken)) throw new Error('Invalid adapter credential');
    this.token = options.adapterToken;
    this.adapterType = options.adapterType ?? 'node_server_adapter';
    this.binding = Object.freeze({...options.binding});
    this.timeout = options.timeoutMs ?? 5000;
    if (!Number.isSafeInteger(this.timeout) || this.timeout < 1 || this.timeout > 30000) throw new Error('Invalid authority timeout');
    this.fetcher = options.fetch ?? globalThis.fetch;
  }

  get bundle(): VerifiedBundle | undefined {
    return this.current && this.current.expiresAt > Date.now() ? this.current : undefined;
  }

  private async request(path: string, method: string, body?: unknown, authenticated = true): Promise<JsonObject> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      const response = await this.fetcher(new URL(`/api/v1/adapter/enforcement/${path}`, this.base), {
        method, redirect: 'error', signal: controller.signal,
        headers: {Accept: 'application/json', ...(authenticated ? {Authorization: `Bearer ${this.token}`} : {}), ...(body === undefined ? {} : {'Content-Type': 'application/json'})},
        ...(body === undefined ? {} : {body: JSON.stringify(body)}),
      });
      if (!response.ok || !response.body) throw new Error('Authority unavailable');
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const item = await reader.read();
          if (item.done) break;
          size += item.value.byteLength;
          if (size > 2 * 1024 * 1024) throw new Error('Authority response too large');
          chunks.push(item.value);
        }
      } finally {
        await reader.cancel();
      }
      return object(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    } finally {
      clearTimeout(timer);
    }
  }

  /** Single-flight refresh. A failed refresh never activates unverified data. */
  refresh(): Promise<boolean> {
    if (!this.refreshPending) this.refreshPending = this.refreshOnce().finally(() => { this.refreshPending = undefined; });
    return this.refreshPending;
  }

  private async refreshOnce(): Promise<boolean> {
    try {
      const heartbeat = await this.request('heartbeat', 'POST');
      if (heartbeat['platform_id'] !== this.binding.platformId) {
        this.current = undefined;
        return false;
      }
      const keyResponse = await this.request('keys', 'GET', undefined, false);
      const bundleKeys = keyMap(keyResponse['keys']);
      this.decisionKeys = Object.create(null);
      if (Array.isArray(keyResponse['key_sets'])) {
        for (const item of keyResponse['key_sets']) {
          const set = object(item);
          if (set['purpose'] === 'enforcement_decision_signing') this.decisionKeys = keyMap(set['keys']);
        }
      }
      const served = await this.request('bundle', 'GET');
      const verified = verifyBundle(served, bundleKeys, this.binding, this.lastAccepted);
      // Heartbeat attribution is authoritative; a stale advertised bundle is not active.
      if (heartbeat['desired_bundle_version'] !== verified.version || heartbeat['desired_payload_digest'] !== verified.digest) throw new Error('Desired bundle mismatch');
      this.current = verified;
      this.lastAccepted = verified;
      const now = new Date().toISOString();
      const observedAt = this.observed?.version === verified.version && this.observed.digest === verified.digest
        ? this.observed.at : undefined;
      await this.request('acknowledgements', 'POST', {
        report_id: randomUUID(), received_version: verified.version, received_at: now,
        validated_version: verified.version, validated_at: now, active_version: verified.version,
        active_at: now, bundle_digest: verified.digest,
        ...(observedAt === undefined ? {} : {first_observed_decision_at: observedAt}),
      });
      return true;
    } catch {
      // Fail closed until the next verified refresh; do not hide key revocation
      // behind a cached bundle after an authoritative key-set replacement.
      this.current = undefined;
      return false;
    }
  }

  async decide(toolName: string, context: InvocationContext, snapshot = this.bundle): Promise<DecideResult> {
    if (!snapshot || snapshot !== this.bundle) return {status: 'unconfigured'};
    const mapped = snapshot.actions[toolName];
    if (!mapped) return {status: 'deny', reason: 'action_unmapped'};
    if (!context.presentedAuthorization || context.presentedAuthorization.length > 8192) return {status: 'deny', reason: 'credential_missing'};
    const decisionId = randomUUID();
    const action = mapped['action_key'];
    try {
      const bound = bindExecution(snapshot, mapped, context);
      const response = await this.request('decide', 'POST', {
        schema_version: 'mudraid.enforce.decide-request/1', decision_id: decisionId,
        adapter: {type: this.adapterType, version: '1.1.0'},
        bundle: {version: snapshot.version, payload_digest: snapshot.digest},
        surface: snapshot.surface, action: mapped,
        request: {transport: 'mcp_streamable_http', http_method: context.httpMethod, path: context.path},
        presented_authorization: context.presentedAuthorization, execution: bound.execution,
      });
      if (response['schema_version'] !== '2.0' || response['decision_id'] !== decisionId) throw new Error('Unbound decision');
      const now = Date.now();
      const decidedAt = instant(response['decided_at']);
      if (decidedAt > now + 30000 || now - decidedAt > 60000) throw new Error('Stale decision');
      if (instant(response['deadline_at']) <= now) throw new Error('Expired decision');
      // This new runtime always requires signed decisions; there is no downgrade toggle.
      const signature = object(response['signature']);
      const claims = object(signature['claims']);
      const keyId = signature['key_id'];
      const profile = 'mudraid.decision.signature/1';
      if (typeof keyId !== 'string' || !Object.hasOwn(this.decisionKeys, keyId) || signature['profile'] !== profile || signature['algorithm'] !== 'RS256' || claims['profile'] !== profile || claims['algorithm'] !== 'RS256' || claims['key_id'] !== keyId) throw new Error('Invalid decision signature');
      verifyClaims(claims, signature['signature'], this.decisionKeys[keyId]);
      if (claims['execution_request_digest'] !== bound.digest) throw new Error('Execution binding mismatch');
      for (const field of ['decision_id', 'decision', 'outcome', 'decided_at', 'deadline_at']) {
        if ((claims[field] ?? null) !== (response[field] ?? null)) throw new Error('Altered decision');
      }
      const reason = object(response['reason']);
      if (claims['reason_primary'] !== reason['primary']) throw new Error('Altered reason');
      for (const [field, expected] of Object.entries({platform_id: this.binding.platformId, environment: this.binding.environment, resource: this.binding.resource, action_key: action, bundle_version: snapshot.version})) {
        if (claims[field] !== expected) throw new Error('Decision binding mismatch');
      }
      if (instant(claims['not_before']) > now + 30000 || instant(claims['expires_at']) <= now) throw new Error('Invalid decision window');
      if (snapshot !== this.bundle) throw new Error('Bundle changed during decision');
      if (response['decision'] !== 'allow' && response['decision'] !== 'deny') throw new Error('Invalid decision outcome');
      // Observation is a verified decision, not proof that the application
      // executed it. Report on the next refresh without delaying execution or
      // replaying a decision. Keep at most one bundle's observation in memory.
      if (this.observed?.version !== snapshot.version || this.observed.digest !== snapshot.digest) {
        this.observed = {version: snapshot.version, digest: snapshot.digest, at: new Date(now).toISOString()};
      }
      return {status: response['decision'], decisionId, ...(typeof reason['primary'] === 'string' ? {reason: reason['primary']} : {})};
    } catch {
      return {status: 'error'};
    }
  }
}
