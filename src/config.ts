/**
 * Sidecar runtime configuration.
 *
 * FIRST-SLICE SCOPE: the fields that feed the V2 decision facts are plain,
 * injectable configuration. Everything about how this config is *distributed and
 * verified* — signed config distribution, provenance verification, and live
 * bundle activation from a verified signed bundle — is a DEFERRED remainder of
 * this story. Here `bundleActive` is a static flag: an unconfigured / no-bundle
 * sidecar therefore deny-closes every protected request (installed, not
 * enforcing == denies, never bypasses).
 */

export interface SidecarConfig {
  /** Upstream application the sidecar sits in front of (reverse-proxy target). */
  readonly upstreamBaseUrl: string;
  /**
   * Whether the surface the sidecar guards is a protected MudraID surface. When
   * false the control loop passes traffic through untouched (not a bundled
   * surface); a real deployment guarding an app sets this true.
   */
  readonly protectedSurface: boolean;
  /**
   * Whether a verified signed bundle is currently active. DEFERRED: real bundle
   * verification / activation. Until then this is a static flag; false ⇒ every
   * protected request deny-closes (`ENFORCE_NO_VALID_BUNDLE`).
   */
  readonly bundleActive: boolean;
  /**
   * Exact, case-sensitive tool-name → canonical-action map. A tool absent from
   * this map is unmapped and denied (`ENFORCE_ACTION_UNMAPPED`); never fuzzy.
   */
  readonly actionMap: Readonly<Record<string, string>>;
  /** Bounded request-body limit in bytes; a larger body deny-closes (413). */
  readonly maxBodyBytes: number;
}

/** Bounded framing default, mirrors the adapter/Kong body limit intent. */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576 as const;
