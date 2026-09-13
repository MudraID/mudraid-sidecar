/** Public-key-only verification of the control plane's signed bundle contract. */
import { createHash, createPublicKey, verify } from 'node:crypto';

export type JsonObject = Record<string, unknown>;
export interface BundleBinding {
  readonly platformId: string;
  readonly environment: string;
  readonly resource: string;
}
export interface VerifiedBundle {
  readonly version: number;
  readonly digest: string;
  readonly expiresAt: number;
  readonly surface: Readonly<JsonObject>;
  readonly actions: Readonly<Record<string, Readonly<JsonObject>>>;
}

export function object(value: unknown): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid object');
  return value as JsonObject;
}

/** Python sort_keys/ensure_ascii canonicalization used by the authority. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('Unsupported canonical number');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = object(value);
  // Python compares Unicode code points; JavaScript's default compares UTF-16.
  const compare = (a: string, b: string): number => {
    const aa = Array.from(a, c => c.codePointAt(0)!);
    const bb = Array.from(b, c => c.codePointAt(0)!);
    for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
      if (aa[i] !== bb[i]) return aa[i]! - bb[i]!;
    }
    return aa.length - bb.length;
  };
  return `{${Object.keys(record).sort(compare).map(k => `${canonicalJson(k)}:${canonicalJson(record[k])}`).join(',')}}`;
}

export function instant(value: unknown): number {
  if (typeof value !== 'string' || !/(Z|[+-]\d{2}:\d{2})$/.test(value)) throw new Error('Invalid timestamp');
  const time = Date.parse(value);
  if (!Number.isFinite(time)) throw new Error('Invalid timestamp');
  return time;
}

export function verifyClaims(claims: JsonObject, encoded: unknown, pem: unknown): void {
  if (typeof encoded !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded) || !encoded) throw new Error('Invalid signature');
  if (typeof pem !== 'string') throw new Error('Unknown signing key');
  const key = createPublicKey(pem);
  if (key.asymmetricKeyType !== 'rsa' || (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('Invalid signing key');
  if (!verify('RSA-SHA256', Buffer.from(canonicalJson(claims)), key, Buffer.from(encoded, 'base64'))) throw new Error('Invalid signature');
}

function equal(actual: unknown, expected: unknown): void {
  if (actual !== expected) throw new Error('Bundle binding mismatch');
}

function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Verify signatures, content, exact tenant binding, time and rollback fencing. */
export function verifyBundle(
  input: unknown, keys: Readonly<Record<string, string>>, binding: BundleBinding,
  active?: VerifiedBundle, now = Date.now(),
): VerifiedBundle {
  const envelope = object(input);
  const payload = object(envelope['payload']);
  const claims = object(envelope['signature_claims']);
  const version = envelope['bundle_version'];
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) throw new Error('Invalid bundle version');
  equal(envelope['schema_version'], '1.0');
  equal(payload['schema_version'], '1.0');
  equal(payload['bundle_version'], version);
  const digest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  equal(envelope['payload_digest'], digest);
  const keyId = envelope['signature_key_id'];
  if (typeof keyId !== 'string' || !Object.hasOwn(keys, keyId)) throw new Error('Unknown signing key');
  const profile = 'mudraid.bundle.signature/1';
  equal(envelope['signature_profile'], profile);
  equal(envelope['signature_algorithm'], 'RS256');
  equal(claims['profile'], profile);
  equal(claims['algorithm'], 'RS256');
  equal(claims['key_id'], keyId);
  verifyClaims(claims, envelope['signature_value'], keys[keyId]);
  equal(claims['payload_digest'], digest);
  equal(claims['bundle_version'], version);
  const content = object(payload['content']);
  const surface = object(content['surface']);
  for (const [field, expected] of [
    ['platform_id', binding.platformId], ['environment', binding.environment],
    ['canonical_resource_uri', binding.resource],
  ] as const) {
    if (!expected.trim()) throw new Error('Unbound surface');
    equal(surface[field], expected);
    equal(claims[field], expected);
  }
  const starts = instant(claims['not_before']);
  const expires = instant(claims['expires_at']);
  if (starts > now || expires <= now || expires <= starts) throw new Error('Bundle outside validity window');
  const evaluation = object(content['evaluation']);
  for (const [field, expected] of Object.entries({mode: 'live', on_timeout: 'deny', on_error: 'deny', on_unmapped_action: 'deny', on_stale_bundle: 'deny', forward: 'once', decide_required: true, retry_forwarded_request: false})) equal(evaluation[field], expected);
  const matcher = object(content['matcher']);
  equal(matcher['kind'], 'mcp_tool_exact');
  const entries = matcher['actions'];
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 10000) throw new Error('Invalid action map');
  const actions: Record<string, Readonly<JsonObject>> = Object.create(null);
  for (const entry of entries) {
    const action = object(entry);
    const tool = action['tool_name'];
    const actionKey = action['action_key'];
    if (typeof tool !== 'string' || !tool || Buffer.byteLength(tool) > 512 || Object.hasOwn(actions, tool)) throw new Error('Invalid or ambiguous tool');
    if (typeof actionKey !== 'string' || !actionKey || Buffer.byteLength(actionKey) > 512) throw new Error('Invalid action');
    actions[tool] = JSON.parse(JSON.stringify(action)) as JsonObject;
  }
  if (active && (version < active.version || (version === active.version && digest !== active.digest))) throw new Error('Bundle rollback or conflict');
  return freeze({version, digest, expiresAt: expires, surface: JSON.parse(JSON.stringify(surface)) as JsonObject, actions});
}
