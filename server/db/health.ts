/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Server Database Status, Schema Verification & Audit Trail
 */

import { getPublicSafeDatabaseSummary, PublicSafeDatabaseSummary } from './config.ts';
import { getServerSupabase, sanitizeDatabaseError } from './client.ts';
import { EXPECTED_ERP_TABLES } from './schemaRegistry.ts';
import { updateActiveDbMetadata } from './store.ts';

export type DbAuditEventType =
  | 'DB_STATUS_CHECK'
  | 'DB_SCHEMA_VERIFY'
  | 'DB_CONFIG_LOADED'
  | 'DB_TARGET_SAVED'
  | 'DB_TARGET_TESTED'
  | 'DB_SCHEMA_COMPARED'
  | 'DB_PREFLIGHT_RUN'
  | 'DB_MIGRATION_STARTED'
  | 'DB_MIGRATION_COMPLETED'
  | 'DB_MIGRATION_FAILED'
  | 'DB_MIGRATION_CANCELLED'
  | 'DB_CUTOVER_EXECUTED'
  | 'DB_ROLLBACK_EXECUTED'
  | 'AUTH_LOGIN_SUCCESS'
  | 'AUTH_LOGIN_FAILED'
  | 'AUTH_LOGOUT'
  | 'PASSWORD_HASH_MIGRATED'
  | 'PASSWORD_CHANGED'
  | 'USER_PASSWORD_UPDATED';

export interface DbAuditEvent {
  id: string;
  timestamp: string;
  eventType: DbAuditEventType;
  actorId: string;
  actorName: string;
  actorRole: string;
  projectFingerprint: string | null;
  outcome: 'success' | 'warning' | 'error';
  details: string;
}

const MAX_DB_AUDIT_EVENTS = 150;
const dbAuditTrail: DbAuditEvent[] = [];

export function recordDbAuditEvent(
  event: Omit<DbAuditEvent, 'id' | 'timestamp' | 'projectFingerprint'>
): DbAuditEvent {
  const summary = getPublicSafeDatabaseSummary();
  const entry: DbAuditEvent = {
    id: `dba-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    projectFingerprint: summary.projectFingerprint,
    ...event,
    details: sanitizeDatabaseError(event.details),
  };
  dbAuditTrail.unshift(entry);
  if (dbAuditTrail.length > MAX_DB_AUDIT_EVENTS) {
    dbAuditTrail.length = MAX_DB_AUDIT_EVENTS;
  }
  return entry;
}

export function getDbAuditEvents(limit = 50): DbAuditEvent[] {
  return dbAuditTrail.slice(0, Math.max(1, Math.min(limit, MAX_DB_AUDIT_EVENTS)));
}

export interface ServerDatabaseStatusResult {
  ok: boolean;
  configured: boolean;
  reachable: boolean;
  latencyMs: number | null;
  checkedAt: string;
  summary: PublicSafeDatabaseSummary;
  message: string;
}

export async function checkServerDatabaseStatus(actor?: {
  id?: string;
  name?: string;
  role?: string;
}): Promise<ServerDatabaseStatusResult> {
  const checkedAt = new Date().toISOString();
  const initialSummary = getPublicSafeDatabaseSummary();
  const db = getServerSupabase();

  if (!db || !initialSummary.configured) {
    updateActiveDbMetadata({
      lastHealthCheckAt: checkedAt,
      lastHealthLatencyMs: null,
      connectionStatus: 'unconfigured',
    });
    const result: ServerDatabaseStatusResult = {
      ok: false,
      configured: false,
      reachable: false,
      latencyMs: null,
      checkedAt,
      summary: getPublicSafeDatabaseSummary(),
      message: 'Server-side database environment variables (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY) are not configured.',
    };
    if (actor) {
      recordDbAuditEvent({
        eventType: 'DB_STATUS_CHECK',
        actorId: String(actor.id || 'system'),
        actorName: String(actor.name || 'System'),
        actorRole: String(actor.role || 'System'),
        outcome: 'warning',
        details: 'Database status check ran while server DB environment variables were unconfigured.',
      });
    }
    return result;
  }

  const startedAt = Date.now();
  try {
    const { error } = await db.from('users').select('id', { count: 'exact' }).limit(1);
    const latencyMs = Date.now() - startedAt;

    if (error) {
      const safeError = sanitizeDatabaseError(error);
      updateActiveDbMetadata({
        lastHealthCheckAt: checkedAt,
        lastHealthLatencyMs: latencyMs,
        connectionStatus: 'error',
      });
      if (actor) {
        recordDbAuditEvent({
          eventType: 'DB_STATUS_CHECK',
          actorId: String(actor.id || 'system'),
          actorName: String(actor.name || 'System'),
          actorRole: String(actor.role || 'System'),
          outcome: 'error',
          details: `Connectivity check returned database error (${safeError}).`,
        });
      }
      return {
        ok: false,
        configured: true,
        reachable: false,
        latencyMs,
        checkedAt,
        summary: getPublicSafeDatabaseSummary(),
        message: `Database reachable check failed: ${safeError}`,
      };
    }

    updateActiveDbMetadata({
      lastHealthCheckAt: checkedAt,
      lastHealthLatencyMs: latencyMs,
      connectionStatus: 'connected',
    });

    if (actor) {
      recordDbAuditEvent({
        eventType: 'DB_STATUS_CHECK',
        actorId: String(actor.id || 'system'),
        actorName: String(actor.name || 'System'),
        actorRole: String(actor.role || 'System'),
        outcome: 'success',
        details: `Centralized database reachable in ${latencyMs}ms (authMode=${initialSummary.authMode}).`,
      });
    }

    return {
      ok: true,
      configured: true,
      reachable: true,
      latencyMs,
      checkedAt,
      summary: getPublicSafeDatabaseSummary(),
      message: 'Centralized server database connection is healthy.',
    };
  } catch (err) {
    const latencyMs = Date.now() - startedAt;
    const safeError = sanitizeDatabaseError(err);
    updateActiveDbMetadata({
      lastHealthCheckAt: checkedAt,
      lastHealthLatencyMs: latencyMs,
      connectionStatus: 'error',
    });
    if (actor) {
      recordDbAuditEvent({
        eventType: 'DB_STATUS_CHECK',
        actorId: String(actor.id || 'system'),
        actorName: String(actor.name || 'System'),
        actorRole: String(actor.role || 'System'),
        outcome: 'error',
        details: `Database status exception: ${safeError}`,
      });
    }
    return {
      ok: false,
      configured: true,
      reachable: false,
      latencyMs,
      checkedAt,
      summary: getPublicSafeDatabaseSummary(),
      message: `Database connection error: ${safeError}`,
    };
  }
}

export interface TableSchemaCheckResult {
  table: string;
  domain: string;
  critical: boolean;
  exists: boolean;
  rowCount: number | null;
  error?: string;
}

export interface SchemaVerificationResult {
  ok: boolean;
  configured: boolean;
  checkedAt: string;
  projectFingerprint: string | null;
  totalExpectedTables: number;
  verifiedTablesCount: number;
  missingOrInaccessibleCount: number;
  criticalTablesReady: boolean;
  missingTables: string[];
  results: TableSchemaCheckResult[];
}

export async function verifyDatabaseSchema(actor?: {
  id?: string;
  name?: string;
  role?: string;
}): Promise<SchemaVerificationResult> {
  const checkedAt = new Date().toISOString();
  const summary = getPublicSafeDatabaseSummary();
  const db = getServerSupabase();

  if (!db || !summary.configured) {
    if (actor) {
      recordDbAuditEvent({
        eventType: 'DB_SCHEMA_VERIFY',
        actorId: String(actor.id || 'system'),
        actorName: String(actor.name || 'System'),
        actorRole: String(actor.role || 'System'),
        outcome: 'warning',
        details: 'Schema verification skipped: server database environment variables are not configured.',
      });
    }
    return {
      ok: false,
      configured: false,
      checkedAt,
      projectFingerprint: summary.projectFingerprint,
      totalExpectedTables: EXPECTED_ERP_TABLES.length,
      verifiedTablesCount: 0,
      missingOrInaccessibleCount: EXPECTED_ERP_TABLES.length,
      criticalTablesReady: false,
      missingTables: EXPECTED_ERP_TABLES.map((t) => t.name),
      results: [],
    };
  }

  // Check tables in bounded batches of 15 to avoid overwhelming PostgREST
  const results: TableSchemaCheckResult[] = [];
  const BATCH_SIZE = 15;

  for (let i = 0; i < EXPECTED_ERP_TABLES.length; i += BATCH_SIZE) {
    const batch = EXPECTED_ERP_TABLES.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(async (spec): Promise<TableSchemaCheckResult> => {
        try {
          const { count, error } = await db
            .from(spec.name)
            .select('id', { count: 'exact' })
            .limit(0);
          if (error) {
            return {
              table: spec.name,
              domain: spec.domain,
              critical: Boolean(spec.critical),
              exists: false,
              rowCount: null,
              error: sanitizeDatabaseError(error),
            };
          }
          return {
            table: spec.name,
            domain: spec.domain,
            critical: Boolean(spec.critical),
            exists: true,
            rowCount: typeof count === 'number' ? count : 0,
          };
        } catch (err) {
          return {
            table: spec.name,
            domain: spec.domain,
            critical: Boolean(spec.critical),
            exists: false,
            rowCount: null,
            error: sanitizeDatabaseError(err),
          };
        }
      })
    );
    results.push(...batchResults);
  }

  const missingTables = results.filter((r) => !r.exists).map((r) => r.table);
  const verifiedTablesCount = results.length - missingTables.length;
  const criticalTablesReady = results.every((r) => !r.critical || r.exists);
  const ok = missingTables.length === 0;

  updateActiveDbMetadata({
    schemaCompatibilityStatus: ok
      ? `Compatible (${verifiedTablesCount}/${EXPECTED_ERP_TABLES.length})`
      : `Requires Attention (${missingTables.length} missing)`,
    schemaCompatibilityCheckedAt: checkedAt,
  });

  if (actor) {
    recordDbAuditEvent({
      eventType: 'DB_SCHEMA_VERIFY',
      actorId: String(actor.id || 'system'),
      actorName: String(actor.name || 'System'),
      actorRole: String(actor.role || 'System'),
      outcome: ok ? 'success' : 'warning',
      details: `Verified ${verifiedTablesCount}/${EXPECTED_ERP_TABLES.length} ERP tables (missing/inaccessible: ${missingTables.length}).`,
    });
  }

  return {
    ok,
    configured: true,
    checkedAt,
    projectFingerprint: summary.projectFingerprint,
    totalExpectedTables: EXPECTED_ERP_TABLES.length,
    verifiedTablesCount,
    missingOrInaccessibleCount: missingTables.length,
    criticalTablesReady,
    missingTables,
    results,
  };
}
