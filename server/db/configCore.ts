/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Core Database Config Primitives, Validation & URL/Secret Masking
 * Zero circular dependencies; used across config.ts, store.ts, client.ts, and migrator.ts.
 */

import crypto from 'crypto';

export type DatabaseProvider = 'supabase';
export type DatabaseEnvironment = 'Production' | 'Staging' | 'Development';
export type ServerDbAuthMode = 'service_role' | 'anon_env' | 'unconfigured';
export type ConnectionHealthStatus =
  | 'connected'
  | 'degraded'
  | 'unconfigured'
  | 'switched'
  | 'error';

export type MigrationLifecycleStatus =
  | 'Draft'
  | 'Validating'
  | 'Ready'
  | 'Running'
  | 'Completed'
  | 'Failed'
  | 'Cutover Pending'
  | 'Active'
  | 'Rolled Back'
  | 'Cancelled';

export function isValidHttpUrl(raw: string): boolean {
  if (!raw) return false;
  try {
    const parsed = new URL(raw.trim());
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * Validates candidate database URLs entered by Super Admin, blocking metadata IPs and malformed schemes.
 */
export function validateCandidateSupabaseUrl(raw: string): {
  valid: boolean;
  normalizedUrl: string;
  error?: string;
} {
  const trimmed = String(raw || '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    return { valid: false, normalizedUrl: '', error: 'Database Project URL is required.' };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, normalizedUrl: '', error: 'Invalid URL format. Use https://<project>.supabase.co.' };
  }

  const host = parsed.hostname.toLowerCase();
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '::1';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocal)) {
    return {
      valid: false,
      normalizedUrl: '',
      error: 'Database URL must use HTTPS (HTTP is only allowed for localhost test endpoints).',
    };
  }

  if (
    host === '169.254.169.254' ||
    host === 'metadata.google.internal' ||
    host === '0.0.0.0'
  ) {
    return {
      valid: false,
      normalizedUrl: '',
      error: 'Blocked disallowed internal metadata host.',
    };
  }

  return {
    valid: true,
    normalizedUrl: `${parsed.protocol}//${parsed.host}`,
  };
}

export function computeProjectFingerprint(url: string): string | null {
  if (!url) return null;
  return crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex').slice(0, 12);
}

/**
 * Returns a redacted display URL (never exposing full project ref in API summaries).
 */
export function maskDatabaseUrl(url: string): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url.trim());
    const host = parsed.hostname;
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
      return `${parsed.protocol}//${host}:${parsed.port || (parsed.protocol === 'https:' ? '443' : '80')}`;
    }
    const parts = host.split('.');
    const sub = parts[0] || '';
    const maskedSub =
      sub.length <= 6
        ? `${sub.slice(0, 2)}****`
        : `${sub.slice(0, 3)}****${sub.slice(-3)}`;
    return `${parsed.protocol}//${[maskedSub, ...parts.slice(1)].join('.')}`;
  } catch {
    return '[MASKED_DB_URL]';
  }
}

export function computeSecretFingerprint(secret: string): string | null {
  if (!secret) return null;
  return crypto.createHash('sha256').update(secret).digest('hex').slice(0, 10);
}

/**
 * Inspects unverified JWT role claim (if key is a JWT) solely to detect accidental anon-key entry.
 */
export function inspectSupabaseKeyRoleHint(key: string): {
  format: 'jwt' | 'sb_secret' | 'opaque';
  jwtRole: string | null;
  looksLikeAnonKey: boolean;
} {
  const trimmed = String(key || '').trim();
  if (trimmed.startsWith('sb_secret_')) {
    return { format: 'sb_secret', jwtRole: null, looksLikeAnonKey: false };
  }
  if (trimmed.startsWith('sb_publishable_')) {
    return { format: 'opaque', jwtRole: 'anon', looksLikeAnonKey: true };
  }
  const parts = trimmed.split('.');
  if (parts.length === 3 && parts[0].startsWith('eyJ')) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
      const role = typeof payload?.role === 'string' ? payload.role : null;
      return {
        format: 'jwt',
        jwtRole: role,
        looksLikeAnonKey: role === 'anon' || role === 'authenticated',
      };
    } catch {
      return { format: 'opaque', jwtRole: null, looksLikeAnonKey: false };
    }
  }
  return { format: 'opaque', jwtRole: null, looksLikeAnonKey: false };
}

export function normalizeDatabaseEnvironment(raw?: unknown): DatabaseEnvironment {
  const s = String(raw || '').trim().toLowerCase();
  if (s === 'staging' || s === 'stage') return 'Staging';
  if (s === 'development' || s === 'dev' || s === 'local') return 'Development';
  return 'Production';
}

let cachedEphemeralSessionSecret: string | null = null;
let warnedMissingSecret = false;
let warnedWeakSecret = false;

export function getResolvedSessionSecret(): {
  secret: string;
  explicit: boolean;
  strong: boolean;
} {
  const explicit = (process.env.ERP_SESSION_SECRET || '').trim();
  if (!explicit && !cachedEphemeralSessionSecret) {
    cachedEphemeralSessionSecret = crypto.randomBytes(32).toString('hex');
    if (!warnedMissingSecret) {
      warnedMissingSecret = true;
      console.warn(
        '[Security] ERP_SESSION_SECRET is not set. Using an ephemeral per-process 256-bit session secret; set a 64+ hex char ERP_SESSION_SECRET in server environment variables for persistent sessions and encrypted config persistence.'
      );
    }
  } else if (explicit && explicit.length < 32 && !warnedWeakSecret) {
    warnedWeakSecret = true;
    console.warn(
      '[Security] ERP_SESSION_SECRET is shorter than 32 characters. Use at least 32-64 random characters for strong HMAC-SHA256 signing.'
    );
  }
  const secret = explicit || (cachedEphemeralSessionSecret as string);
  return {
    secret,
    explicit: Boolean(explicit),
    strong: secret.length >= 32,
  };
}

export function getConfigMasterKey(): { key: Buffer; persistentAcrossRestarts: boolean } {
  const explicitKey = (
    process.env.ERP_DB_CONFIG_KEY ||
    process.env.ERP_SESSION_SECRET ||
    ''
  ).trim();
  if (explicitKey) {
    const key = crypto
      .createHash('sha256')
      .update(`ensec-erp-phase4-master:${explicitKey}`)
      .digest();
    return { key, persistentAcrossRestarts: true };
  }
  const session = getResolvedSessionSecret();
  const key = crypto
    .createHash('sha256')
    .update(`ensec-erp-phase4-ephemeral:${session.secret}`)
    .digest();
  return { key, persistentAcrossRestarts: false };
}

export function redactSensitiveText(input: string): string {
  return String(input || '')
    .replace(/postgres(?:ql)?:\/\/[^\s'"]+/gi, '[REDACTED_CONNECTION_URI]')
    .replace(/https?:\/\/[a-z0-9.-]+\.supabase\.co[^\s'"]*/gi, '[REDACTED_SUPABASE_URL]')
    .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_JWT]')
    .replace(/sb_(?:secret|publishable)_[A-Za-z0-9_-]+/g, '[REDACTED_API_KEY]')
    .trim();
}
