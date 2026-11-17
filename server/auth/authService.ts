import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import type express from 'express';
import {
  getServerDbConfig,
  getServerSupabase,
  recordDbAuditEvent,
  sanitizeDatabaseError,
} from '../db/index.ts';
import { getDefaultPermissionsForRole, resolveUserPermissions, type Role } from '../../src/types/erp.ts';

export const SESSION_COOKIE_NAME = 'ensec_erp_session';
export const CSRF_COOKIE_NAME = 'ensec_csrf_token';
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const BCRYPT_SALT_ROUNDS = 10;

export interface AuthenticatedErpUser {
  id: string;
  userId: string;
  name: string;
  email: string;
  phone?: string;
  role: string;
  designation?: string;
  department?: string;
  region?: string;
  area?: string;
  territory?: string;
  isSalesman?: boolean;
  salesmanCode?: string;
  monthlySalesTargetBDT?: number;
  status: string;
  avatar?: string;
  permissions: any;
  createdAt?: string;
}

interface ActiveSessionRecord {
  user: AuthenticatedErpUser;
  createdAt: number;
  expiresAt: number;
}

const erpActiveSessions = new Map<string, ActiveSessionRecord>();
const revokedSessionTokens = new Set<string>();
const serverUsersCache = new Map<string, AuthenticatedErpUser & { _passwordHash?: string }>();

const DEFAULT_ROOT_PASSWORD_HASH = bcrypt.hashSync('ensec2026', BCRYPT_SALT_ROUNDS);

export function getDefaultRootAdminRecord(): AuthenticatedErpUser & { _passwordHash: string } {
  return {
    id: 'u-admin-root',
    userId: 'ADMIN',
    name: 'Super Admin',
    email: 'admin@ensecbd.com',
    phone: '',
    role: 'Super Admin',
    designation: 'Managing Director / System Administrator',
    department: 'Management',
    status: 'Active',
    permissions: getDefaultPermissionsForRole('Super Admin'),
    _passwordHash: DEFAULT_ROOT_PASSWORD_HASH,
  };
}

export function isBcryptHash(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return /^\$2[aby]\$\d{2}\$/.test(value);
}

export async function hashPassword(plainPassword: string): Promise<string> {
  return bcrypt.hash(String(plainPassword), BCRYPT_SALT_ROUNDS);
}

export function sanitizeUserForClient<T extends Record<string, any> | null | undefined>(
  user: T
): Omit<NonNullable<T>, 'password' | 'password_hash' | 'passwordHash' | '_passwordHash'> | null {
  if (!user || typeof user !== 'object') return null;
  const {
    password: _p,
    password_hash: _ph,
    passwordHash: _phCamel,
    _passwordHash: _internalPh,
    ...safe
  } = user as Record<string, any>;
  return safe as any;
}

export function mapSupabaseUserRowSafe(row: any): AuthenticatedErpUser {
  let parsedPermissions = row.permissions;
  if (typeof parsedPermissions === 'string') {
    try {
      parsedPermissions = JSON.parse(parsedPermissions);
    } catch {
      parsedPermissions = null;
    }
  }
  const role = (row.role as Role) || 'Field Force';
  const status =
    row.status === 'Inactive'
      ? 'Inactive'
      : row.status === 'Blocked'
      ? 'Blocked'
      : 'Active';

  return {
    id: row.uid ? String(row.uid) : `u-sb-${row.id}`,
    userId:
      row.user_id ||
      row.uid ||
      (row.email ? String(row.email).split('@')[0].toUpperCase() : `EMP-${row.id}`),
    name: row.name || 'Staff User',
    email: row.email || '',
    phone: row.phone || '',
    role,
    designation: row.designation || '',
    department: row.department || '',
    region: row.region || '',
    area: row.area || '',
    territory: row.territory || '',
    isSalesman: row.is_salesman,
    salesmanCode: row.salesman_code || row.salesmancode || undefined,
    monthlySalesTargetBDT: row.monthly_target_bdt || row.monthlysalestargetbdt,
    status,
    avatar: row.avatar || undefined,
    permissions: resolveUserPermissions({
      role,
      permissions: parsedPermissions,
    }),
    createdAt: row.created_at || undefined,
  };
}

export function indexUserInAuthCache(user: any, passwordHash?: string) {
  if (!user || typeof user !== 'object') return;
  const safe = sanitizeUserForClient(user) as AuthenticatedErpUser | null;
  if (!safe) return;
  const existingHash =
    (safe.id && serverUsersCache.get(String(safe.id).toLowerCase())?._passwordHash) ||
    (safe.userId && serverUsersCache.get(String(safe.userId).toLowerCase())?._passwordHash) ||
    (safe.email && serverUsersCache.get(String(safe.email).toLowerCase())?._passwordHash) ||
    undefined;
  const resolvedHash = passwordHash || existingHash;
  const entry = {
    ...safe,
    ...(resolvedHash ? { _passwordHash: resolvedHash } : {}),
  };
  if (safe.id) serverUsersCache.set(String(safe.id).toLowerCase(), entry);
  if (safe.userId) serverUsersCache.set(String(safe.userId).toLowerCase(), entry);
  if (safe.salesmanCode) serverUsersCache.set(String(safe.salesmanCode).toLowerCase(), entry);
  if (safe.email) serverUsersCache.set(String(safe.email).toLowerCase(), entry);
}

export function clearUserLookupCache() {
  serverUsersCache.clear();
}

export function clearAuthCacheForTest() {
  serverUsersCache.clear();
  erpActiveSessions.clear();
  revokedSessionTokens.clear();
}

export function getCachedServerUsers(): AuthenticatedErpUser[] {
  const unique = new Map<string, AuthenticatedErpUser>();
  for (const u of serverUsersCache.values()) {
    const key = String(u.id || u.userId || u.email).toLowerCase();
    if (!unique.has(key)) {
      const sanitized = sanitizeUserForClient(u);
      if (sanitized) unique.set(key, sanitized);
    }
  }
  return Array.from(unique.values());
}

export function parseCookies(cookieHeader?: string): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx <= 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      try {
        result[key] = decodeURIComponent(val);
      } catch {
        result[key] = val;
      }
    }
  }
  return result;
}

export function extractSessionToken(req: express.Request): string {
  const cookies = parseCookies(req.headers.cookie);
  const cookieToken = cookies[SESSION_COOKIE_NAME] || '';
  const authHeader = String(req.headers['authorization'] || '').trim();
  const bearerToken = authHeader.toLowerCase().startsWith('bearer ')
    ? authHeader.slice(7).trim()
    : '';
  const headerToken = String(req.headers['x-erp-session-token'] || '').trim();
  return String(cookieToken || headerToken || bearerToken || '').trim();
}

function isRequestSecure(req: express.Request): boolean {
  const xfProto = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0]
    ?.trim()
    .toLowerCase();
  const origin = String(req.headers['origin'] || '').trim().toLowerCase();
  const referer = String(req.headers['referer'] || '').trim().toLowerCase();
  return Boolean(
    req.secure ||
    req.protocol === 'https' ||
    xfProto === 'https' ||
    origin.startsWith('https://') ||
    referer.startsWith('https://')
  );
}

export function setSessionCookie(
  res: express.Response,
  req: express.Request,
  token: string,
  ttlMs: number = SESSION_TTL_MS
): string {
  const maxAgeSeconds = Math.max(1, Math.floor(ttlMs / 1000));
  const isSecure = isRequestSecure(req);
  const cookieAttrs = isSecure
    ? `SameSite=None; Max-Age=${maxAgeSeconds}; Secure; Partitioned`
    : `SameSite=Lax; Max-Age=${maxAgeSeconds}`;
  const sessionCookie = `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; ${cookieAttrs}`;
  const csrfToken = crypto.randomBytes(24).toString('hex');
  const csrfCookie = `${CSRF_COOKIE_NAME}=${encodeURIComponent(csrfToken)}; Path=/; ${cookieAttrs}`;
  res.setHeader('Set-Cookie', [sessionCookie, csrfCookie]);
  return csrfToken;
}

export function clearSessionCookie(res: express.Response, req: express.Request) {
  const isSecure = isRequestSecure(req);
  const cookieAttrs = isSecure
    ? 'SameSite=None; Max-Age=0; Secure; Partitioned'
    : 'SameSite=Lax; Max-Age=0';
  res.setHeader('Set-Cookie', [
    `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; ${cookieAttrs}`,
    `${CSRF_COOKIE_NAME}=; Path=/; ${cookieAttrs}`,
  ]);
}

export function signErpSessionToken(user: AuthenticatedErpUser, ttlMs: number = SESSION_TTL_MS): string {
  const secret = getServerDbConfig().sessionSecret;
  const now = Date.now();
  const payload = {
    uid: String(user.id),
    code: String(user.userId || ''),
    email: String(user.email || ''),
    iat: now,
    exp: now + ttlMs,
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

export function verifyErpSessionToken(
  token?: string | null
): { uid: string; code: string; email: string; exp: number } | null {
  if (!token || revokedSessionTokens.has(token)) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  const secret = getServerDbConfig().sessionSecret;
  const expectedSig = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
  try {
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!parsed || !parsed.uid || (parsed.exp && Date.now() > Number(parsed.exp))) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function createSessionForUser(
  user: AuthenticatedErpUser,
  previousTokenToRotate?: string | null,
  ttlMs: number = SESSION_TTL_MS
): { token: string; expiresAt: number } {
  // Session fixation protection: revoke any prior token presented during login
  if (previousTokenToRotate) {
    revokeSessionToken(previousTokenToRotate);
  }
  const safeUser = sanitizeUserForClient(user) as AuthenticatedErpUser;
  const token = signErpSessionToken(safeUser, ttlMs);
  const now = Date.now();
  const expiresAt = now + ttlMs;
  erpActiveSessions.set(token, {
    user: safeUser,
    createdAt: now,
    expiresAt,
  });
  return { token, expiresAt };
}

export function revokeSessionToken(token?: string | null) {
  if (!token) return;
  erpActiveSessions.delete(token);
  revokedSessionTokens.add(token);
}

export function revokeAllSessionsForUser(
  identifiers: Array<string | undefined | null>,
  exceptToken?: string | null
) {
  const keys = new Set(
    identifiers
      .map((s) => String(s || '').trim().toLowerCase())
      .filter(Boolean)
  );
  if (keys.size === 0) return;

  for (const [tok, rec] of erpActiveSessions.entries()) {
    if (exceptToken && tok === exceptToken) continue;
    const u = rec.user;
    const matches = [u.id, u.userId, u.email]
      .map((v) => String(v || '').trim().toLowerCase())
      .some((v) => v && keys.has(v));
    if (matches) {
      erpActiveSessions.delete(tok);
      revokedSessionTokens.add(tok);
    }
  }
}

export interface UserLookupResult {
  rawRow: any | null;
  user: AuthenticatedErpUser | null;
  storedPassword: string | null;
  lookupStatus: 'found' | 'not_found' | 'db_unconfigured' | 'db_error' | 'db_empty';
  lookupError?: string;
}

function phoneDigitsMatch(storedPhone: unknown, cleanDigits: string): boolean {
  if (cleanDigits.length < 6) return false;
  const rPhone = String(storedPhone || '').replace(/[^0-9]/g, '');
  if (!rPhone) return false;
  if (rPhone === cleanDigits) return true;
  if (cleanDigits.length >= 10 && rPhone.length >= 10) {
    return rPhone.slice(-10) === cleanDigits.slice(-10);
  }
  return false;
}

export async function findRawUserRecordByIdentifier(
  identifier: string
): Promise<UserLookupResult> {
  const cleanId = String(identifier || '').trim();
  const cleanIdLower = cleanId.toLowerCase();
  if (!cleanId) {
    return { rawRow: null, user: null, storedPassword: null, lookupStatus: 'not_found' };
  }

  const db = getServerSupabase();
  const cfg = getServerDbConfig();
  let dbErrorReason: string | null = null;
  let dbEmpty = false;

  if (db) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        // Query users safely by user_id, email, uid, phone, or salesman_code
        const { data: rows, error } = await db.from('users').select('*').limit(5000);
        if (!error && Array.isArray(rows)) {
          const cleanDigits = cleanIdLower.replace(/[^0-9]/g, '');
          let matchedRow: any | null = null;

          for (const r of rows) {
            const mappedRow = mapSupabaseUserRowSafe(r);
            const rowPwd =
              r.password !== undefined && r.password !== null && String(r.password) !== ''
                ? String(r.password)
                : undefined;
            indexUserInAuthCache(mappedRow, rowPwd);

            if (!matchedRow) {
              const rUid = String(r.uid || '').trim().toLowerCase();
              const rUserId = String(r.user_id || '').trim().toLowerCase();
              const rEmail = String(r.email || '').trim().toLowerCase();
              const rSalesmanCode = String(r.salesman_code || r.salesmancode || '')
                .trim()
                .toLowerCase();
              if (
                rUserId === cleanIdLower ||
                rEmail === cleanIdLower ||
                rUid === cleanIdLower ||
                rSalesmanCode === cleanIdLower ||
                phoneDigitsMatch(r.phone, cleanDigits)
              ) {
                matchedRow = r;
              }
            }
          }

          if (matchedRow) {
            const mapped = mapSupabaseUserRowSafe(matchedRow);
            return {
              rawRow: matchedRow,
              user: mapped,
              storedPassword:
                matchedRow.password !== undefined &&
                matchedRow.password !== null &&
                String(matchedRow.password) !== ''
                  ? String(matchedRow.password)
                  : null,
              lookupStatus: 'found',
            };
          }

          // Database responded and has rows, user genuinely not found
          if (rows.length > 0) {
            return { rawRow: null, user: null, storedPassword: null, lookupStatus: 'not_found' };
          }

          // Empty rows when using anon_env is typically Phase 3 RLS blocking anon reads
          if (cfg.authMode !== 'service_role') {
            dbErrorReason =
              'SUPABASE_SERVICE_ROLE_KEY is required on the server because database RLS blocks anonymous user reads.';
          } else {
            dbEmpty = true;
          }
          break;
        }

        if (error) {
          dbErrorReason = sanitizeDatabaseError(error.message || 'Database query failed');
        }
      } catch (err: any) {
        dbErrorReason = sanitizeDatabaseError(err?.message || 'Database connection failed');
      }

      if (attempt === 0) {
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
    }
  }

  // Fallback to server cache (used in test/offline mode without Supabase .env or during transient DB blips)
  const cached = serverUsersCache.get(cleanIdLower);
  if (cached) {
    return {
      rawRow: null,
      user: sanitizeUserForClient(cached) as AuthenticatedErpUser,
      storedPassword: cached._passwordHash || null,
      lookupStatus: 'found',
    };
  }

  // Emergency root ADMIN fallback ONLY when directory is completely unseeded (zero users)
  if (
    serverUsersCache.size === 0 &&
    (cleanIdLower === 'admin' || cleanIdLower === 'admin@ensecbd.com')
  ) {
    const rootAdmin = getDefaultRootAdminRecord();
    indexUserInAuthCache(rootAdmin, rootAdmin._passwordHash);
    return {
      rawRow: null,
      user: sanitizeUserForClient(rootAdmin) as AuthenticatedErpUser,
      storedPassword: rootAdmin._passwordHash,
      lookupStatus: 'found',
    };
  }

  if (dbErrorReason) {
    return {
      rawRow: null,
      user: null,
      storedPassword: null,
      lookupStatus: 'db_error',
      lookupError: dbErrorReason,
    };
  }
  if (!db) {
    return {
      rawRow: null,
      user: null,
      storedPassword: null,
      lookupStatus: 'db_unconfigured',
    };
  }
  if (dbEmpty) {
    return {
      rawRow: null,
      user: null,
      storedPassword: null,
      lookupStatus: 'db_empty',
    };
  }

  return { rawRow: null, user: null, storedPassword: null, lookupStatus: 'not_found' };
}

export async function verifyPasswordAndMigrateHash(params: {
  inputPassword: string;
  storedPassword: string | null;
  rawRow: any | null;
  user: AuthenticatedErpUser;
}): Promise<{ valid: boolean; migratedToBcrypt: boolean }> {
  const { inputPassword, storedPassword, rawRow, user } = params;
  if (!inputPassword || !storedPassword) {
    return { valid: false, migratedToBcrypt: false };
  }

  if (isBcryptHash(storedPassword)) {
    const match = await bcrypt.compare(inputPassword, storedPassword);
    return { valid: match, migratedToBcrypt: false };
  }

  // Legacy plaintext password comparison using constant-time byte check when lengths match
  const a = Buffer.from(inputPassword, 'utf8');
  const b = Buffer.from(storedPassword, 'utf8');
  const plainMatch = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!plainMatch) {
    return { valid: false, migratedToBcrypt: false };
  }

  // Controlled automatic migration: upgrade plaintext password in Supabase to bcrypt hash
  let migrated = false;
  try {
    const newHash = await hashPassword(inputPassword);
    indexUserInAuthCache(user, newHash);
    const db = getServerSupabase();
    if (db && rawRow) {
      const updateQuery = rawRow.id
        ? db.from('users').update({ password: newHash, updated_at: new Date().toISOString() }).eq('id', rawRow.id)
        : rawRow.email
        ? db.from('users').update({ password: newHash, updated_at: new Date().toISOString() }).ilike('email', rawRow.email)
        : null;
      if (updateQuery) {
        const { error } = await updateQuery;
        if (!error) {
          migrated = true;
          recordDbAuditEvent({
            eventType: 'PASSWORD_HASH_MIGRATED',
            actorId: user.id,
            actorName: user.name,
            actorRole: user.role,
            outcome: 'success',
            details: `Upgraded legacy credential storage to bcrypt hash for account ${user.userId}.`,
          });
        }
      }
    }
  } catch {
    // Non-fatal: login still succeeds while migration retries next login
  }

  return { valid: true, migratedToBcrypt: migrated };
}

export async function lookupAuthoritativeUser(
  hdrId: string,
  hdrCode: string,
  hdrEmail: string
): Promise<AuthenticatedErpUser | null> {
  const db = getServerSupabase();
  if (db) {
    try {
      if (hdrEmail) {
        const { data } = await db
          .from('users')
          .select('*')
          .ilike('email', hdrEmail)
          .limit(1)
          .maybeSingle();
        if (data) {
          const mapped = mapSupabaseUserRowSafe(data);
          indexUserInAuthCache(mapped);
          return mapped;
        }
      }
      const lookupUid = hdrCode || hdrId;
      if (lookupUid) {
        const { data } = await db
          .from('users')
          .select('*')
          .eq('uid', lookupUid)
          .limit(1)
          .maybeSingle();
        if (data) {
          const mapped = mapSupabaseUserRowSafe(data);
          indexUserInAuthCache(mapped);
          return mapped;
        }
      }
      if (/^u-sb-(\d+)$/i.test(hdrId)) {
        const numId = Number(hdrId.replace(/^u-sb-/i, ''));
        const { data } = await db
          .from('users')
          .select('*')
          .eq('id', numId)
          .limit(1)
          .maybeSingle();
        if (data) {
          const mapped = mapSupabaseUserRowSafe(data);
          indexUserInAuthCache(mapped);
          return mapped;
        }
      }
    } catch {
      // Fallback to cache below
    }
  }

  const candidates = [hdrId, hdrCode, hdrEmail]
    .map((s) => String(s || '').toLowerCase())
    .filter(Boolean);
  for (const key of candidates) {
    const hit = serverUsersCache.get(key);
    if (hit) {
      return sanitizeUserForClient(hit) as AuthenticatedErpUser;
    }
  }

  return null;
}

/**
 * Strictly resolves the authenticated ERP user from a signed, non-revoked,
 * non-expired session token (HttpOnly cookie, Bearer token, or x-erp-session-token).
 * NEVER trusts raw x-user-id / x-user-code / x-user-email headers or query params.
 */
export async function resolveRequestUser(req: express.Request): Promise<AuthenticatedErpUser | null> {
  const sessionToken = extractSessionToken(req);
  if (!sessionToken || revokedSessionTokens.has(sessionToken)) {
    return null;
  }

  const tokenClaims = verifyErpSessionToken(sessionToken);
  if (!tokenClaims) {
    return null;
  }

  const storedSession = erpActiveSessions.get(sessionToken);
  if (storedSession && Date.now() > storedSession.expiresAt) {
    erpActiveSessions.delete(sessionToken);
    return null;
  }

  const freshUser =
    (await lookupAuthoritativeUser(tokenClaims.uid, tokenClaims.code, tokenClaims.email)) ||
    storedSession?.user ||
    null;

  if (!freshUser || freshUser.status === 'Blocked' || freshUser.status === 'Inactive') {
    return null;
  }

  return sanitizeUserForClient(freshUser) as AuthenticatedErpUser;
}
