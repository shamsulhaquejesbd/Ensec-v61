/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Server-Side Supabase Client & Atomic Switch Manager
 * Ensures all backend modules share one centralized database client instance,
 * provides isolated non-singleton clients for target validation/migration, and
 * atomically resets clients + operational server caches upon Cutover or Rollback.
 */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { getServerDbConfig } from './config.ts';
import { redactSensitiveText } from './configCore.ts';

export class DatabaseNotConfiguredError extends Error {
  public readonly statusCode = 503;

  constructor(message = 'Centralized database service is not configured on the server.') {
    super(message);
    this.name = 'DatabaseNotConfiguredError';
  }
}

let cachedServerClient: SupabaseClient | null = null;
let cachedSignature = '';
const cacheResetHooks: Array<() => void> = [];

/**
 * Registers a server-side operational cache reset callback invoked whenever
 * the active database switches (Cutover or Rollback).
 */
export function registerDbSwitchCacheResetHook(hook: () => void): () => void {
  cacheResetHooks.push(hook);
  return () => {
    const idx = cacheResetHooks.indexOf(hook);
    if (idx >= 0) cacheResetHooks.splice(idx, 1);
  };
}

/**
 * Creates a standalone, non-cached Supabase client for validating or migrating
 * a target/rollback database without touching the active singleton client.
 */
export function createIsolatedSupabaseClient(url: string, serviceRoleKey: string): SupabaseClient {
  const cleanUrl = String(url || '').trim().replace(/\/+$/, '');
  const cleanKey = String(serviceRoleKey || '').trim();
  return createClient(cleanUrl, cleanKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
    global: {
      headers: {
        'x-ensec-client': 'ensec-erp-phase4-migrator',
      },
    },
  });
}

/**
 * Returns the single reusable server-side Supabase client singleton,
 * or null if server-only DB configuration is not present.
 */
export function getServerSupabase(): SupabaseClient | null {
  const cfg = getServerDbConfig();
  if (!cfg.isConfigured) {
    cachedServerClient = null;
    cachedSignature = '';
    return null;
  }

  const nextSignature = `${cfg.configVersion}:${cfg.projectFingerprint}:${cfg.authMode}:${cfg.supabaseKey.length}`;
  if (cachedServerClient && cachedSignature === nextSignature) {
    return cachedServerClient;
  }

  try {
    cachedServerClient = createClient(cfg.supabaseUrl, cfg.supabaseKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
      global: {
        headers: {
          'x-ensec-client': 'ensec-erp-server',
        },
      },
    });
    cachedSignature = nextSignature;
    return cachedServerClient;
  } catch (err) {
    console.error('[DB Client] Failed to initialize server database client:', sanitizeDatabaseError(err));
    cachedServerClient = null;
    cachedSignature = '';
    return null;
  }
}

/**
 * Returns the active Supabase server client or throws a sanitized 503 error.
 */
export function requireServerSupabase(): SupabaseClient {
  const client = getServerSupabase();
  if (!client) {
    throw new DatabaseNotConfiguredError();
  }
  return client;
}

/**
 * Clears the cached server client instance so subsequent calls re-read active config.
 */
export function resetServerSupabaseClient(): void {
  cachedServerClient = null;
  cachedSignature = '';
}

/**
 * Atomically resets the singleton database client AND clears registered operational
 * server caches after Cutover or Rollback, returning the newly initialized client.
 */
export function switchActiveDatabaseClient(): SupabaseClient | null {
  resetServerSupabaseClient();
  for (const hook of cacheResetHooks) {
    try {
      hook();
    } catch (err) {
      console.warn('[DB Switch] Cache reset hook error:', sanitizeDatabaseError(err));
    }
  }
  return getServerSupabase();
}

/**
 * Redacts URLs, JWTs, API keys, and Postgres connection strings before logging or responding.
 */
export function sanitizeDatabaseError(error: unknown): string {
  const raw =
    typeof error === 'string'
      ? error
      : error && typeof error === 'object' && 'message' in error
        ? String((error as { message?: unknown }).message || 'Database operation failed')
        : 'Database operation failed';

  return redactSensitiveText(raw);
}
