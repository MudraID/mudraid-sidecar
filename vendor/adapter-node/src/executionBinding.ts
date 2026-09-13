/** Exact request binding; supplied business values are not independent facts. */
import {createHash} from 'node:crypto';
import {canonicalJson, type JsonObject, type VerifiedBundle} from './signedBundle.js';

export interface ExecutionContext {
  readonly presentedAuthorization: string;
  readonly httpMethod: string;
  readonly path: string;
  readonly contentType: string;
  readonly body: Uint8Array;
}

export const sha256 = (bytes: string | Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

export function bindExecution(snapshot: VerifiedBundle, action: Readonly<JsonObject>, context: ExecutionContext): {digest: string; execution: JsonObject} {
  if (!(context.body instanceof Uint8Array) || context.body.byteLength > 8 * 1024 * 1024) throw new Error('Invalid request body');
  if (!context.contentType || context.contentType.length > 256 || /[\r\n]/.test(context.contentType)) throw new Error('Invalid content type');
  let token = context.presentedAuthorization.trim();
  if (token.toLowerCase().startsWith('bearer ')) token = token.slice(7).trim();
  if (!token) throw new Error('Missing caller');
  const scopes = action['required_scopes'];
  if (!Array.isArray(scopes) || scopes.some(scope => typeof scope !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope))) throw new Error('Invalid action scopes');
  const material: JsonObject = {
    profile: 'mudraid.execution.request/1', body_sha256: sha256(context.body),
    content_type: context.contentType, http_method: context.httpMethod, path: context.path,
    caller_token_sha256: sha256(token), platform_id: snapshot.surface['platform_id'],
    environment: snapshot.surface['environment'], resource: snapshot.surface['canonical_resource_uri'],
    action_key: action['action_key'], action_version: action['action_version'],
    mapping_id: action['mapping_id'], mapping_version: action['mapping_revision'],
    bundle_version: snapshot.version, bundle_payload_digest: snapshot.digest,
    required_scopes: [...new Set(scopes)].sort(),
  };
  if (Object.values(material).some(value => value === undefined || value === null || value === '')) throw new Error('Incomplete execution binding');
  return {digest: sha256(canonicalJson(material)), execution: {
    profile: material['profile'], body_sha256: material['body_sha256'], content_type: material['content_type'],
    ...(action['argument_profile'] == null ? {} : {body_base64: boundedArgumentBody(context.body)}),
  }};
}

function boundedArgumentBody(body: Uint8Array): string {
  if (body.byteLength === 0 || body.byteLength > 65536) throw new Error('Argument body exceeds bounds');
  return Buffer.from(body).toString('base64');
}
