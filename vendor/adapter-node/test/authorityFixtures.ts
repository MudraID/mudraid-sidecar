import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { HttpAuthority } from '../src/httpAuthority.js';
import { canonicalJson } from '../src/signedBundle.js';
import { bundle, keys, binding } from './bundleFixtures.js';

const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
export function harness(mode = 'allow', onDecide?: () => void, withArguments = false) {
  const calls: {path: string; body: any; auth: string | null}[] = [];
  const served = bundle(1, Date.now(), withArguments);
  const fetcher: typeof fetch = async (url, init) => {
    const path = new URL(String(url)).pathname.split('/').at(-1)!;
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({path, body, auth: new Headers(init?.headers).get('Authorization')});
    if (mode === 'unreachable') throw new Error('transport failure with sensitive endpoint');
    if (path === 'heartbeat') return Response.json({platform_id: binding.platformId, desired_bundle_version: 1, desired_payload_digest: served.payload_digest});
    if (path === 'keys') return Response.json({keys: [{key_id: 'key1', public_key_pem: keys.key1}], key_sets: [{purpose: 'enforcement_decision_signing', keys: [{key_id: 'decision1', public_key_pem: publicKey.export({type: 'spki', format: 'pem'}).toString()}]}]});
    if (path === 'bundle') return Response.json(mode === 'tampered' ? {...served, payload_digest: '0'.repeat(64)} : served);
    if (path === 'acknowledgements') return Response.json({accepted: true}, {status: 201});
    onDecide?.();
    const decidedAt = new Date().toISOString();
    const deadlineAt = mode === 'missing_deadline' ? null : new Date(Date.now() + (mode === 'expired_deadline' ? -1 : 1000)).toISOString();
    const decision = mode === 'deny' ? 'deny' : 'allow';
    const response: any = {schema_version: '2.0', decision_id: body.decision_id, decision, outcome: decision, decided_at: decidedAt, deadline_at: deadlineAt, reason: {primary: 'test_reason'}};
    const execution = body.execution;
    const executionDigest = createHash('sha256').update(canonicalJson({
      profile: execution.profile, body_sha256: execution.body_sha256, content_type: execution.content_type,
      http_method: body.request.http_method, path: body.request.path,
      caller_token_sha256: createHash('sha256').update(body.presented_authorization.replace(/^Bearer /i, '').trim()).digest('hex'),
      platform_id: body.surface.platform_id, environment: body.surface.environment, resource: body.surface.canonical_resource_uri,
      action_key: body.action.action_key, action_version: body.action.action_version,
      mapping_id: body.action.mapping_id, mapping_version: body.action.mapping_revision,
      bundle_version: body.bundle.version, bundle_payload_digest: body.bundle.payload_digest,
      required_scopes: [...body.action.required_scopes].sort(),
    })).digest('hex');
    const claims = {execution_request_digest: mode === 'missing_execution' ? null : mode === 'foreign_body' ? '0'.repeat(64) : executionDigest, profile: 'mudraid.decision.signature/1', algorithm: 'RS256', key_id: 'decision1', decision_id: body.decision_id,
      decision, outcome: decision, decided_at: decidedAt, deadline_at: deadlineAt, reason_primary: 'test_reason',
      platform_id: binding.platformId, environment: binding.environment, resource: binding.resource,
      action_key: mode === 'foreign_action' ? 'other' : 'tasks:read', bundle_version: 1,
      not_before: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 5000).toISOString()};
    if (mode !== 'unsigned') response.signature = {profile: claims.profile, algorithm: 'RS256', key_id: 'decision1', claims, signature: sign('RSA-SHA256', Buffer.from(canonicalJson(claims)), privateKey).toString('base64')};
    if (mode === 'replayed') response.decision_id = 'a-different-request';
    if (mode === 'altered') response.decision = 'deny';
    return Response.json(response);
  };
  const options = {apiBase: 'https://api.example.com', adapterToken: 'adapter-credential', binding, fetch: fetcher};
  return {calls, options, authority: new HttpAuthority(options)};
}
