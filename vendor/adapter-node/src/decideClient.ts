/**
 * `/decide` seam helpers.
 *
 * The REAL HTTP `/decide` client (authenticated call to the MudraID authority,
 * with timeout/retry) is a DEFERRED remainder of EP-120-US-05. This module
 * provides only the injectable seam and in-memory fakes, so the control loop can
 * be exercised — and proven deny-closed — with no network.
 */

import type { DecideClient, DecideResult } from './types.js';

/** A seam that always returns the same fixed `/decide` result. */
export function staticDecideClient(result: DecideResult): DecideClient {
  return async () => result;
}

/**
 * A seam that rejects (simulating a transport exception). The control loop
 * catches this and deny-closes as `ENFORCE_DECIDE_UNAVAILABLE`.
 */
export function throwingDecideClient(error?: unknown): DecideClient {
  return async () => {
    throw error ?? new Error('decide transport failure');
  };
}
