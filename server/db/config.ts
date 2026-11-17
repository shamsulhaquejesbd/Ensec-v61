/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Server-Side Database Configuration
 * Combines server-only environment baseline with encrypted server-side active
 * configuration overrides managed by Super Admin Cutover / Rollback operations.
 * Zero credentials or secrets are ever exposed to frontend responses or logs.
 */

import {
  computeProjectFingerprint,
  getConfigMasterKey,
  getResolvedSessionSecret,
  isValidHttpUrl,
  maskDatabaseUrl,
  normalizeDatabaseEnvironment,
  type ConnectionHealthStatus,
  type DatabaseEnvironment,
  type DatabaseProvider,
  type ServerDbAuthMode,
} from './configCore.ts';
import { getActiveDbMetadata, getActiveDbOverride } from './store.ts';

export type {
  ConnectionHealthStatus,
  DatabaseEnvironment,
  DatabaseProvider,
  ServerDbAuthMode,
};
export { computeProjectFingerprint, maskDatabaseUrl };

export interface ServerDatabaseConfig {
  readonly provider: DatabaseProvider;
  readonly environment: DatabaseEnvironment;
  readonly supabaseUrl: string;
  readonly supabaseKey: string;
  readonly authMode: ServerDbAuthMode;
  readonly isConfigured: boolean;
  readonly configVersion: number;
  readonly configSource: 'env_baseline' | 'switched_control_plane';
  readonly projectFingerprint: string | null;
  readonly maskedUrl: string | null;
  readonly sessionSecret: string;
  readonly hasExplicitSessionSecret: boolean;
  readonly sessionSecretStrong: boolean;
}

export interface PublicSafeDatabaseSummary {
  configured: boolean;
  provider: DatabaseProvider;
  environment: DatabaseEnvironment;
  hasUrl: boolean;
  hasServiceRoleKey: boolean;
  authMode: ServerDbAuthMode;
  configVersion: number;
  configSource: 'env_baseline' | 'switched_control_plane';
  connectionStatus: ConnectionHealthStatus;
  maskedUrl: string | null;
  projectFingerprint: string | null;
  lastHealthCheckAt: string | null;
  lastHealthLatencyMs: number | null;
  lastMigrationAt: string | null;
  schemaCompatibilityStatus: string | null;
  schemaCompatibilityCheckedAt: string | null;
  sessionSecretConfigured: boolean;
  sessionSecretStrong: boolean;
  persistenceMode: 'encrypted_store_persistent' | 'encrypted_store_ephemeral_key';
  multiInstanceNote: string;
}

let warnedLegacyAnonKey = false;

export function getServerDbConfig(): ServerDatabaseConfig {
  const sessionInfo = getResolvedSessionSecret();
  const override = getActiveDbOverride();

  if (override && isValidHttpUrl(override.supabaseUrl) && override.serviceRoleKey) {
    return {
      provider: override.provider || 'supabase',
      environment: override.environment || 'Production',
      supabaseUrl: override.supabaseUrl.trim().replace(/\/+$/, ''),
      supabaseKey: override.serviceRoleKey.trim(),
      authMode: override.authMode || 'service_role',
      isConfigured: true,
      configVersion: Number(override.configVersion) || 2,
      configSource: 'switched_control_plane',
      projectFingerprint: computeProjectFingerprint(override.supabaseUrl),
      maskedUrl: maskDatabaseUrl(override.supabaseUrl),
      sessionSecret: sessionInfo.secret,
      hasExplicitSessionSecret: sessionInfo.explicit,
      sessionSecretStrong: sessionInfo.strong,
    };
  }

  const rawUrl = (process.env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const validUrl = isValidHttpUrl(rawUrl) ? rawUrl : '';
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  const anonEnvKey = (process.env.SUPABASE_ANON_KEY || '').trim();
  const environment = normalizeDatabaseEnvironment(
    process.env.ERP_DB_ENV || (process.env.NODE_ENV === 'production' ? 'Production' : 'Development')
  );

  let supabaseKey = '';
  let authMode: ServerDbAuthMode = 'unconfigured';

  if (validUrl && serviceRoleKey) {
    supabaseKey = serviceRoleKey;
    authMode = 'service_role';
  } else if (validUrl && anonEnvKey) {
    supabaseKey = anonEnvKey;
    authMode = 'anon_env';
    if (!warnedLegacyAnonKey) {
      warnedLegacyAnonKey = true;
      console.warn(
        '[DB Config] SUPABASE_SERVICE_ROLE_KEY is not set; using server-only SUPABASE_ANON_KEY. Configure SUPABASE_SERVICE_ROLE_KEY for full backend privileges and strict Phase 3 RLS enforcement.'
      );
    }
  }

  return {
    provider: 'supabase',
    environment,
    supabaseUrl: validUrl,
    supabaseKey,
    authMode,
    isConfigured: Boolean(validUrl && supabaseKey),
    configVersion: 1,
    configSource: 'env_baseline',
    projectFingerprint: validUrl ? computeProjectFingerprint(validUrl) : null,
    maskedUrl: validUrl ? maskDatabaseUrl(validUrl) : null,
    sessionSecret: sessionInfo.secret,
    hasExplicitSessionSecret: sessionInfo.explicit,
    sessionSecretStrong: sessionInfo.strong,
  };
}

export function getPublicSafeDatabaseSummary(): PublicSafeDatabaseSummary {
  const cfg = getServerDbConfig();
  const meta = getActiveDbMetadata();
  const masterKey = getConfigMasterKey();

  const defaultStatus: ConnectionHealthStatus = !cfg.isConfigured
    ? 'unconfigured'
    : cfg.configSource === 'switched_control_plane'
      ? meta.connectionStatus || 'switched'
      : meta.connectionStatus || 'connected';

  return {
    configured: cfg.isConfigured,
    provider: cfg.provider,
    environment: meta.environment || cfg.environment,
    hasUrl: Boolean(cfg.supabaseUrl),
    hasServiceRoleKey: cfg.authMode === 'service_role',
    authMode: cfg.authMode,
    configVersion: cfg.configVersion,
    configSource: cfg.configSource,
    connectionStatus: defaultStatus,
    maskedUrl: cfg.maskedUrl,
    projectFingerprint: cfg.projectFingerprint,
    lastHealthCheckAt: meta.lastHealthCheckAt ?? null,
    lastHealthLatencyMs: meta.lastHealthLatencyMs ?? null,
    lastMigrationAt: meta.lastMigrationAt ?? null,
    schemaCompatibilityStatus: meta.schemaCompatibilityStatus ?? null,
    schemaCompatibilityCheckedAt: meta.schemaCompatibilityCheckedAt ?? null,
    sessionSecretConfigured: cfg.hasExplicitSessionSecret,
    sessionSecretStrong: cfg.sessionSecretStrong,
    persistenceMode: masterKey.persistentAcrossRestarts
      ? 'encrypted_store_persistent'
      : 'encrypted_store_ephemeral_key',
    multiInstanceNote:
      cfg.configSource === 'switched_control_plane'
        ? 'Active DB overridden via encrypted server control store. For stateless multi-instance restarts, update SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY environment secrets.'
        : 'Using server environment baseline. Runtime cutover updates the encrypted server control store immediately without frontend code changes.',
  };
}
