import {describe, expect, it, vi} from 'vitest';
import {staticDecideClient} from '@mudraid/adapter-node';
import {harness} from '@mudraid/test-authority';
import {enforce} from '../src/proxy.js';

describe('verified authority through the proxy', () => {
  it.each(['allow', 'deny', 'unsigned', 'replayed', 'altered', 'foreign_action', 'forged_expired_deadline', 'expired_deadline', 'missing_deadline', 'foreign_body', 'missing_execution', 'unreachable', 'tampered'])(
    'forwards exactly once only for a verified allow: %s', async mode => {
      const {authority, calls} = harness(mode);
      await authority.refresh();
      const body = Buffer.from(JSON.stringify({jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'read', arguments: {record: 'example'}}}));
      const forward = vi.fn(async () => ({status: 200, headers: {}, body: Buffer.from('ok')}));
      const result = await enforce({
        method: 'POST', path: '/mcp', body, bodyReadable: true, bodyTooLarge: false,
        headers: {'content-type': 'application/json', authorization: 'Bearer caller-credential', 'x-mudraid-decision-id': 'forged'},
      }, {
        config: {upstreamBaseUrl: 'http://localhost', protectedSurface: true, bundleActive: false, actionMap: {}, maxBodyBytes: 1048576},
        authority,
        // A permissive embedded seam must never replace the configured authority.
        decide: staticDecideClient({status: 'allow', decisionId: 'wrong-source'}),
        forwardUpstream: forward,
      });
      expect(result.forwarded).toBe(mode === 'allow');
      if (mode === 'expired_deadline') {
        const payload = JSON.parse(result.body.toString('utf-8'));
        expect(result.status).toBe(503);
        expect(payload.reason).toBe('deadline_exceeded');
        expect(payload.message).toContain('Authorization expired');
        expect(payload.message).toContain('This attempt was not forwarded');
        expect(calls.filter(c => c.path === 'decide')).toHaveLength(1);
      }
      if (mode === 'forged_expired_deadline') {
        expect(JSON.parse(result.body.toString('utf-8')).message).not.toContain('Authorization expired');
      }

      expect(forward).toHaveBeenCalledTimes(mode === 'allow' ? 1 : 0);
      expect(calls.filter(c => c.path === 'decide').length).toBeLessThanOrEqual(1);
      if (mode === 'allow') {
        expect(forward).toHaveBeenCalledWith(expect.objectContaining({
          body,
          headers: expect.objectContaining({'x-mudraid-action-key': 'tasks:read', 'x-mudraid-decision-id': calls.find(c => c.path === 'decide')?.body.decision_id}),
        }));
      }
    },
  );
});


describe('signed execution snapshot', () => {
  it('forwards only the signed original bytes when caller storage changes during the decision', async () => {
    const body = Buffer.from(JSON.stringify({jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'read', arguments: {amount_minor: 100, recipient: 'approved'}}}));
    const original = Buffer.from(body);
    const headers = {'content-type': 'application/json', authorization: 'Bearer original-caller'};
    const {authority, calls} = harness('allow', () => { body.fill(32); headers.authorization = 'Bearer another-caller'; });
    await authority.refresh();
    const forward = vi.fn(async () => ({status: 200, headers: {}, body: Buffer.from('ok')}));
    const result = await enforce({method: 'POST', path: '/mcp', body, headers, bodyReadable: true, bodyTooLarge: false}, {
      config: {upstreamBaseUrl: 'http://localhost', protectedSurface: true, bundleActive: false, actionMap: {}, maxBodyBytes: 1048576},
      authority, decide: staticDecideClient({status: 'allow', decisionId: 'untrusted'}), forwardUpstream: forward,
    });
    expect(result.forwarded).toBe(true);
    expect(forward).toHaveBeenCalledTimes(1);
    expect(forward).toHaveBeenCalledWith(expect.objectContaining({body: original, headers: expect.objectContaining({authorization: 'Bearer original-caller'})}));
    expect(calls.filter(call => call.path === 'decide')).toHaveLength(1);
  });
});
