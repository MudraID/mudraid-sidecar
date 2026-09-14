import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { canonicalJson } from '../src/signedBundle.js';
import argumentFixture from './fixtures/action-arguments.json';

const {privateKey, publicKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
export const keys = {key1: publicKey.export({type: 'spki', format: 'pem'}).toString()};
export const binding = {platformId: 'platform', environment: 'staging', resource: 'https://example.com/mcp'};
export const now = Date.parse('2026-09-12T00:00:00Z');
export function bundle(version = 1, moment = now, withArguments = false) {
  const payload = {schema_version: '1.0', bundle_version: version, content: {
    surface: {domain: 'example.com', platform_id: binding.platformId, environment: binding.environment, canonical_resource_uri: binding.resource},
    evaluation: {mode: 'live', on_timeout: 'deny', on_error: 'deny', on_unmapped_action: 'deny', on_stale_bundle: 'deny', forward: 'once', decide_required: true, retry_forwarded_request: false},
    matcher: {kind: 'mcp_tool_exact', actions: [{tool_name: 'read', action_key: 'tasks:read', action_version: 1, mapping_id: 'mapping-1', mapping_revision: 1, required_scopes: ['tasks:read'], ...(withArguments ? {argument_profile: argumentFixture.profile} : {})}]},
  }};
  const digest = createHash('sha256').update(canonicalJson(payload)).digest('hex');
  const claims = {profile: 'mudraid.bundle.signature/1', algorithm: 'RS256', key_id: 'key1', payload_digest: digest, bundle_version: version,
    ...payload.content.surface, not_before: new Date(moment - 86400000).toISOString(), expires_at: new Date(moment + 86400000).toISOString()};
  return {schema_version: '1.0', bundle_version: version, payload, payload_digest: digest,
    signature_profile: claims.profile, signature_algorithm: 'RS256', signature_key_id: 'key1', signature_claims: claims,
    signature_value: sign('RSA-SHA256', Buffer.from(canonicalJson(claims)), privateKey).toString('base64')};
}

