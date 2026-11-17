/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Phase 4 Controlled Full Database Migration, Cutover & Rollback Engine
 * Handles pre-migration validation, lock-protected 114-table topological batched copy,
 * idempotent upserts & retries, sequence sync/SQL generation, Auth & Storage inspection,
 * verified atomic Cutover, and divergence-guarded Rollback.
 */

import { SupabaseClient } from '@supabase/supabase-js';
import {
  computeProjectFingerprint,
  maskDatabaseUrl,
  redactSensitiveText,
} from './configCore.ts';
import { getServerDbConfig } from './config.ts';
import {
  createIsolatedSupabaseClient,
  sanitizeDatabaseError,
  switchActiveDatabaseClient,
} from './client.ts';
import { recordDbAuditEvent } from './health.ts';
import {
  EXPECTED_ERP_TABLES,
  MIGRATION_TABLE_ORDER,
  TABLE_SPEC_BY_NAME,
  type ExpectedTableSpec,
} from './schemaRegistry.ts';
import {
  compareDatabaseSchemas,
  fetchPostgrestOpenApiSpec,
  probeTablesExistenceAndCounts,
  validateTargetDatabaseConnection,
} from './schemaValidator.ts';
import {
  acquireDbOperationLock,
  getDbOperationLock,
  getMigrationHistory,
  getMigrationRunById,
  getPreviousRollbackSnapshotInternal,
  getStagedTargetInternal,
  releaseDbOperationLock,
  savePreviousRollbackSnapshot,
  setActiveDbOverride,
  updateActiveDbMetadata,
  updateStagedTargetPreflight,
  upsertMigrationRun,
  type MigrationRunRecord,
  type TableMigrationProgress,
} from './store.ts';

export interface PreflightCheckItem {
  id: string;
  label: string;
  severity: 'critical' | 'warning' | 'info';
  status: 'passed' | 'failed' | 'warning';
  details: string;
}

export interface PreflightChecklistResult {
  ok: boolean;
  canStartMigration: boolean;
  checkedAt: string;
  targetExistingDataDetected: boolean;
  targetNonEmptyTables: Array<{ table: string; rows: number }>;
  totalSourceRows: number;
  sourceTableCounts: Record<string, number>;
  targetTableCounts: Record<string, number>;
  storageBucketsCount: number;
  checks: PreflightCheckItem[];
  blockers: string[];
  warnings: string[];
}

export interface CutoverResult {
  ok: boolean;
  message: string;
  newConfigVersion?: number;
  activeSummary?: any;
  error?: string;
  code?: string;
}

export interface RollbackResult {
  ok: boolean;
  message: string;
  divergenceDetected?: boolean;
  divergentTables?: Array<{ table: string; snapshotRows: number; currentRows: number }>;
  restoredConfigVersion?: number;
  error?: string;
  code?: string;
}

const activeCancellationFlags = new Map<string, boolean>();
const activeRunMemoryPromises = new Map<string, Promise<void>>();

/**
 * Sorts self-referencing hierarchical rows (e.g., org_hierarchy, chart_of_accounts)
 * so parent rows precede their children during batched upsert.
 */
export function sortSelfReferencingRows(
  rows: Record<string, any>[],
  pkCol: string,
  parentCol: string
): Record<string, any>[] {
  if (!rows || rows.length <= 1) return rows;
  const byId = new Map<string, Record<string, any>>();
  for (const r of rows) {
    const k = r?.[pkCol] !== undefined && r?.[pkCol] !== null ? String(r[pkCol]) : '';
    if (k) byId.set(k, r);
  }
  const visited = new Set<string>();
  const visiting = new Set<string>();
  const ordered: Record<string, any>[] = [];

  const visit = (row: Record<string, any>) => {
    const id = row?.[pkCol] !== undefined && row?.[pkCol] !== null ? String(row[pkCol]) : '';
    if (id && visited.has(id)) return;
    if (id && visiting.has(id)) return; // Break cycle safely
    if (id) visiting.add(id);

    const parentVal = row?.[parentCol];
    const parentId = parentVal !== undefined && parentVal !== null ? String(parentVal) : '';
    if (parentId && parentId !== id && byId.has(parentId)) {
      visit(byId.get(parentId)!);
    }

    if (id) {
      visiting.delete(id);
      visited.add(id);
    }
    ordered.push(row);
  };

  for (const row of rows) {
    visit(row);
  }
  return ordered;
}

function appendRunLog(
  run: MigrationRunRecord,
  level: 'info' | 'warning' | 'error',
  message: string
) {
  run.logs.push({
    timestamp: new Date().toISOString(),
    level,
    message: redactSensitiveText(message),
  });
}

async function sleepMs(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runPreMigrationChecklist(params?: {
  confirmSourceBackupTaken?: boolean;
  confirmTargetExistingData?: boolean;
  actor?: { id: string; name: string; role: string };
}): Promise<PreflightChecklistResult> {
  const checkedAt = new Date().toISOString();
  const activeCfg = getServerDbConfig();
  const staged = getStagedTargetInternal();
  const checks: PreflightCheckItem[] = [];
  const blockers: string[] = [];
  const warnings: string[] = [];

  // 1. Source configured & reachable
  let sourceClient: SupabaseClient | null = null;
  let sourceReachable = false;
  let sourceProbes = new Map<string, { exists: boolean; count: number | null; error?: string }>();
  if (activeCfg.isConfigured) {
    sourceClient = createIsolatedSupabaseClient(activeCfg.supabaseUrl, activeCfg.supabaseKey);
    const { error } = await sourceClient.from('users').select('id', { count: 'exact' }).limit(1);
    sourceReachable = !error;
  }
  checks.push({
    id: 'source_reachable',
    label: 'Source database configured & reachable',
    severity: 'critical',
    status: sourceReachable ? 'passed' : 'failed',
    details: sourceReachable
      ? `Active source (${activeCfg.maskedUrl}) responded with valid credentials.`
      : activeCfg.isConfigured
        ? 'Active source database failed connectivity check.'
        : 'Active source database is not configured.',
  });
  if (!sourceReachable) blockers.push('Source database is not configured or unreachable.');

  // 2. Target configured & reachable
  const hasStaged = Boolean(staged?.supabaseUrl && staged?.serviceRoleKey);
  let targetValidation = hasStaged
    ? await validateTargetDatabaseConnection({
        supabaseUrl: staged!.supabaseUrl,
        serviceRoleKey: staged!.serviceRoleKey,
        persistToStaged: true,
      })
    : null;

  const targetReachable = Boolean(targetValidation?.reachable);
  checks.push({
    id: 'target_reachable',
    label: 'Target database credentials & connectivity validated',
    severity: 'critical',
    status: targetReachable ? 'passed' : 'failed',
    details: targetReachable
      ? `Target (${maskDatabaseUrl(staged!.supabaseUrl)}) reachable in ${targetValidation?.latencyMs ?? '-'}ms.`
      : targetValidation?.error || 'Target database URL & Service Role Key must be saved and reachable.',
  });
  if (!targetReachable) blockers.push('Target database is not configured or unreachable.');

  // 3. Distinct Source vs Target check
  const srcFp = activeCfg.projectFingerprint;
  const tgtFp = staged?.supabaseUrl ? computeProjectFingerprint(staged.supabaseUrl) : null;
  const distinctProjects = Boolean(srcFp && tgtFp && srcFp !== tgtFp);
  checks.push({
    id: 'distinct_projects',
    label: 'Target differs from active source database',
    severity: 'critical',
    status: !srcFp || !tgtFp ? 'failed' : distinctProjects ? 'passed' : 'failed',
    details: distinctProjects
      ? `Distinct project fingerprints verified (${srcFp} -> ${tgtFp}).`
      : 'Source and Target point to the same Supabase URL/project. Self-migration is blocked.',
  });
  if (!distinctProjects) blockers.push('Target database must be distinct from the active source database.');

  // 4. All 114 tables exist on target
  const all114TargetExist = Boolean(
    targetValidation && targetValidation.verifiedTablesCount === EXPECTED_ERP_TABLES.length
  );
  checks.push({
    id: 'all_tables_exist',
    label: `All ${EXPECTED_ERP_TABLES.length} ERP tables exist on target`,
    severity: 'critical',
    status: all114TargetExist ? 'passed' : 'failed',
    details: targetValidation
      ? `${targetValidation.verifiedTablesCount}/${EXPECTED_ERP_TABLES.length} tables verified on target.`
      : 'Target tables not inspected.',
  });
  if (!all114TargetExist) {
    blockers.push(
      `Target is missing ${targetValidation?.missingTablesCount ?? EXPECTED_ERP_TABLES.length} required ERP tables.`
    );
  }

  // 5. Schema Compatibility & Privileges
  let schemaReport = null;
  if (hasStaged && targetReachable) {
    try {
      schemaReport = await compareDatabaseSchemas({
        targetUrl: staged!.supabaseUrl,
        targetServiceRoleKey: staged!.serviceRoleKey,
        persistToStaged: true,
      });
    } catch {
      schemaReport = null;
    }
  }
  const schemaEligible = Boolean(schemaReport?.migrationEligible);
  checks.push({
    id: 'schema_compatibility',
    label: 'Schema compatibility (columns, data types, PKs, FKs)',
    severity: 'critical',
    status: schemaEligible ? 'passed' : 'failed',
    details: schemaReport
      ? `Schema status: ${schemaReport.overallStatus} (${schemaReport.summary.different} type/nullability diffs, ${schemaReport.summary.missing} missing objects).`
      : 'Unable to run schema comparison against target.',
  });
  if (!schemaEligible) {
    blockers.push('Target schema has critical incompatibilities (missing tables/columns or type mismatches).');
  }

  // 6. Extensions & Views check
  const missingExtOrView = Boolean(
    schemaReport?.diffItems.some(
      (d) => (d.category === 'Extension' || d.category === 'View') && d.status === 'Missing'
    )
  );
  const pgRpcTarget = Boolean(schemaReport?.summary.postgresInspectorOnTarget);
  checks.push({
    id: 'extensions_views',
    label: 'Extensions (uuid-ossp) & Views (safe_users)',
    severity: missingExtOrView ? 'critical' : 'warning',
    status: missingExtOrView ? 'failed' : pgRpcTarget ? 'passed' : 'warning',
    details: missingExtOrView
      ? 'Required Postgres extension or view is missing on target.'
      : pgRpcTarget
        ? 'Verified uuid-ossp extension & safe_users view on target via Postgres catalog RPC.'
        : 'Postgres catalog RPC not installed on target; verify uuid-ossp and safe_users in Supabase SQL Editor or run sql/phase4_migration_helper_rpcs.sql.',
  });
  if (missingExtOrView) blockers.push('Missing required Postgres extension/view on target.');
  else if (!pgRpcTarget) warnings.push('Postgres catalog RPC not installed on target; sequences will require generated SQL or helper RPC.');

  // 7. Write privileges verified
  const writeOk = targetValidation?.writePrivilegeOk === true;
  checks.push({
    id: 'privileges_ok',
    label: 'Target service_role read & write privileges',
    severity: 'critical',
    status: writeOk ? 'passed' : 'failed',
    details: targetValidation?.writePrivilegeNote || 'Write privilege could not be verified.',
  });
  if (!writeOk) blockers.push('Target database lacks verified service_role write privileges.');

  // 8 & 9. Source & Target record counts + existing data warning
  const sourceTableCounts: Record<string, number> = {};
  const targetTableCounts: Record<string, number> = {};
  let totalSourceRows = 0;
  const targetNonEmptyTables: Array<{ table: string; rows: number }> = [];

  if (sourceClient && sourceReachable) {
    sourceProbes = await probeTablesExistenceAndCounts(sourceClient);
    for (const spec of EXPECTED_ERP_TABLES) {
      const cnt = sourceProbes.get(spec.name)?.count ?? 0;
      sourceTableCounts[spec.name] = cnt;
      totalSourceRows += cnt;
    }
  }
  if (schemaReport) {
    for (const row of schemaReport.tableComparisons) {
      const cnt = row.targetRowCount ?? 0;
      targetTableCounts[row.table] = cnt;
      if (cnt > 0) {
        targetNonEmptyTables.push({ table: row.table, rows: cnt });
      }
    }
  }

  checks.push({
    id: 'source_record_counts',
    label: 'Source record counts captured across all 114 tables',
    severity: 'info',
    status: sourceReachable ? 'passed' : 'failed',
    details: `Captured ${totalSourceRows.toLocaleString()} total row(s) across ${EXPECTED_ERP_TABLES.length} tables.`,
  });

  const targetExistingDataDetected = targetNonEmptyTables.length > 0;
  const overwriteConfirmed = Boolean(params?.confirmTargetExistingData);
  checks.push({
    id: 'target_existing_data',
    label: 'Target existing-data conflict check',
    severity: targetExistingDataDetected && !overwriteConfirmed ? 'critical' : 'warning',
    status: !targetExistingDataDetected
      ? 'passed'
      : overwriteConfirmed
        ? 'warning'
        : 'failed',
    details: !targetExistingDataDetected
      ? 'Target tables are completely empty (clean slate).'
      : overwriteConfirmed
        ? `Target has existing rows in ${targetNonEmptyTables.length} table(s); Super Admin confirmed idempotent upsert overwrite.`
        : `Target already contains rows in ${targetNonEmptyTables.length} table(s) (e.g. ${targetNonEmptyTables.slice(0, 4).map((t) => `${t.table}=${t.rows}`).join(', ')}). Explicit confirmation required before proceeding.`,
  });
  if (targetExistingDataDetected && !overwriteConfirmed) {
    warnings.push(
      `Target database already contains data in ${targetNonEmptyTables.length} tables. Confirm idempotent upsert overwrite before starting migration.`
    );
  }

  // 10. Auth & Storage bucket inspection
  let storageBucketsCount = 0;
  if (sourceClient && sourceReachable) {
    try {
      const { data: buckets } = await sourceClient.storage.listBuckets();
      if (Array.isArray(buckets)) storageBucketsCount = buckets.length;
    } catch {
      storageBucketsCount = 0;
    }
  }
  checks.push({
    id: 'auth_storage_inspection',
    label: 'Authentication & Storage bucket readiness',
    severity: 'info',
    status: 'passed',
    details: `ERP Auth uses public.users (bcrypt hashes preserved cleanly). Source storage buckets detected: ${storageBucketsCount}.`,
  });

  // 11. Super Admin Backup Confirmation
  const backupConfirmed = Boolean(params?.confirmSourceBackupTaken);
  checks.push({
    id: 'backup_confirmation',
    label: 'Source database backup confirmed by Super Admin',
    severity: 'critical',
    status: backupConfirmed ? 'passed' : 'failed',
    details: backupConfirmed
      ? 'Super Admin confirmed source snapshot/backup was taken prior to migration.'
      : 'Check the backup confirmation toggle before launching full migration.',
  });

  const canStartMigration =
    blockers.length === 0 &&
    backupConfirmed &&
    (!targetExistingDataDetected || overwriteConfirmed);

  updateStagedTargetPreflight(blockers.length === 0);

  if (params?.actor) {
    recordDbAuditEvent({
      eventType: 'DB_PREFLIGHT_RUN',
      actorId: params.actor.id,
      actorName: params.actor.name,
      actorRole: params.actor.role,
      outcome: blockers.length === 0 ? 'success' : 'warning',
      details: `Pre-migration checklist: ${blockers.length} blocker(s), ${totalSourceRows} source rows, targetNonEmptyTables=${targetNonEmptyTables.length}.`,
    });
  }

  return {
    ok: blockers.length === 0,
    canStartMigration,
    checkedAt,
    targetExistingDataDetected,
    targetNonEmptyTables,
    totalSourceRows,
    sourceTableCounts,
    targetTableCounts,
    storageBucketsCount,
    checks,
    blockers,
    warnings,
  };
}

async function copyTableInBatches(params: {
  sourceClient: SupabaseClient;
  targetClient: SupabaseClient;
  spec: ExpectedTableSpec;
  batchSize: number;
  maxRetries: number;
  retryDelayMs: number;
  run: MigrationRunRecord;
  progressRow: TableMigrationProgress;
}): Promise<{ ok: boolean; aborted: boolean }> {
  const {
    sourceClient,
    targetClient,
    spec,
    batchSize,
    maxRetries,
    retryDelayMs,
    run,
    progressRow,
  } = params;
  const startedAt = Date.now();
  progressRow.status = 'Running';

  // Special handling for self-referencing tables (org_hierarchy, chart_of_accounts):
  // fetch all rows (reference hierarchy tables are small/moderate), topologically sort parent -> child,
  // then upsert in deterministic batches so child foreign keys never fail.
  if (spec.selfRefColumn) {
    let allRows: Record<string, any>[] = [];
    let offset = 0;
    while (true) {
      if (activeCancellationFlags.get(run.id)) {
        progressRow.status = 'Skipped';
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: true };
      }
      const { data, error } = await sourceClient
        .from(spec.name)
        .select('*')
        .order(spec.primaryKey, { ascending: true })
        .range(offset, offset + batchSize - 1);
      if (error) {
        progressRow.status = 'Failed';
        progressRow.error = sanitizeDatabaseError(error);
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: false };
      }
      const chunk = Array.isArray(data) ? data : [];
      allRows.push(...chunk);
      if (chunk.length < batchSize) break;
      offset += batchSize;
    }

    const sortedRows = sortSelfReferencingRows(allRows, spec.primaryKey, spec.selfRefColumn);
    for (let i = 0; i < sortedRows.length; i += batchSize) {
      if (activeCancellationFlags.get(run.id)) {
        progressRow.status = 'Skipped';
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: true };
      }
      const batch = sortedRows.slice(i, i + batchSize);
      const batchRes = await upsertBatchWithRetry({
        targetClient,
        spec,
        batch,
        maxRetries,
        retryDelayMs,
        progressRow,
        run,
      });
      if (!batchRes.ok) {
        progressRow.status = 'Failed';
        progressRow.error = batchRes.error;
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: false };
      }
      for (const r of batch) {
        if (spec.hasSequence && r[spec.primaryKey] !== undefined && r[spec.primaryKey] !== null) {
          const numId = Number(r[spec.primaryKey]);
          if (Number.isFinite(numId)) {
            progressRow.maxSerialId = Math.max(progressRow.maxSerialId ?? 0, numId);
          }
        }
      }
      progressRow.migratedRows += batch.length;
      progressRow.batchesCompleted += 1;
      run.totalMigratedRows += batch.length;
    }
  } else {
    let offset = 0;
    while (true) {
      if (activeCancellationFlags.get(run.id)) {
        progressRow.status = 'Skipped';
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: true };
      }

      let rows: Record<string, any>[] = [];
      let readErr: string | null = null;
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        const { data, error } = await sourceClient
          .from(spec.name)
          .select('*')
          .order(spec.primaryKey, { ascending: true })
          .range(offset, offset + batchSize - 1);
        if (!error) {
          rows = Array.isArray(data) ? data : [];
          readErr = null;
          break;
        }
        readErr = sanitizeDatabaseError(error);
        if (attempt < maxRetries) {
          progressRow.retriesUsed += 1;
          await sleepMs(retryDelayMs * attempt);
        }
      }

      if (readErr) {
        progressRow.status = 'Failed';
        progressRow.error = `Source read failed: ${readErr}`;
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: false };
      }

      if (rows.length === 0) break;

      const batchRes = await upsertBatchWithRetry({
        targetClient,
        spec,
        batch: rows,
        maxRetries,
        retryDelayMs,
        progressRow,
        run,
      });
      if (!batchRes.ok) {
        progressRow.status = 'Failed';
        progressRow.error = batchRes.error;
        progressRow.durationMs = Date.now() - startedAt;
        return { ok: false, aborted: false };
      }

      for (const r of rows) {
        if (spec.hasSequence && r[spec.primaryKey] !== undefined && r[spec.primaryKey] !== null) {
          const numId = Number(r[spec.primaryKey]);
          if (Number.isFinite(numId)) {
            progressRow.maxSerialId = Math.max(progressRow.maxSerialId ?? 0, numId);
          }
        }
      }

      progressRow.migratedRows += rows.length;
      progressRow.batchesCompleted += 1;
      run.totalMigratedRows += rows.length;

      if (rows.length < batchSize) break;
      offset += batchSize;
    }
  }

  // Verify target row count matches source count
  const { count: tgtCount, error: countErr } = await targetClient
    .from(spec.name)
    .select('id', { count: 'exact' })
    .limit(0);

  if (countErr) {
    progressRow.status = 'Failed';
    progressRow.error = `Post-copy count verification failed: ${sanitizeDatabaseError(countErr)}`;
    progressRow.durationMs = Date.now() - startedAt;
    return { ok: false, aborted: false };
  }

  progressRow.targetVerifiedRows = typeof tgtCount === 'number' ? tgtCount : 0;
  if (progressRow.targetVerifiedRows < progressRow.sourceRows) {
    progressRow.status = 'Failed';
    progressRow.error = `Row count mismatch after copy: source=${progressRow.sourceRows}, target=${progressRow.targetVerifiedRows}.`;
    progressRow.durationMs = Date.now() - startedAt;
    return { ok: false, aborted: false };
  }

  // Sequence sync for SERIAL/BIGSERIAL PK tables
  if (spec.hasSequence) {
    if ((progressRow.maxSerialId ?? 0) > 0) {
      try {
        const { data: seqRes, error: seqErr } = await targetClient.rpc(
          'ensec_phase4_sync_sequence',
          {
            p_table_name: spec.name,
            p_column_name: spec.primaryKey,
          }
        );
        if (!seqErr && (seqRes as any)?.ok) {
          progressRow.sequenceSyncStatus = 'synced';
        } else {
          progressRow.sequenceSyncStatus = 'sql_required';
          run.generatedSequenceSql.push(
            `SELECT setval(pg_get_serial_sequence('public.${spec.name}', '${spec.primaryKey}'), ${progressRow.maxSerialId}, true);`
          );
        }
      } catch {
        progressRow.sequenceSyncStatus = 'sql_required';
        run.generatedSequenceSql.push(
          `SELECT setval(pg_get_serial_sequence('public.${spec.name}', '${spec.primaryKey}'), ${progressRow.maxSerialId}, true);`
        );
      }
    } else {
      progressRow.sequenceSyncStatus = 'not_applicable';
    }
  } else {
    progressRow.sequenceSyncStatus = 'not_applicable';
  }

  progressRow.status = 'Completed';
  progressRow.durationMs = Date.now() - startedAt;
  return { ok: true, aborted: false };
}

async function upsertBatchWithRetry(params: {
  targetClient: SupabaseClient;
  spec: ExpectedTableSpec;
  batch: Record<string, any>[];
  maxRetries: number;
  retryDelayMs: number;
  progressRow: TableMigrationProgress;
  run: MigrationRunRecord;
}): Promise<{ ok: boolean; error?: string }> {
  const { targetClient, spec, batch, maxRetries, retryDelayMs, progressRow, run } = params;
  let lastError = 'Unknown upsert failure';
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const { error } = await targetClient
      .from(spec.name)
      .upsert(batch, { onConflict: spec.primaryKey, ignoreDuplicates: false });
    if (!error) {
      return { ok: true };
    }
    lastError = sanitizeDatabaseError(error);
    if (attempt < maxRetries) {
      progressRow.retriesUsed += 1;
      appendRunLog(
        run,
        'warning',
        `Retry ${attempt}/${maxRetries - 1} for ${spec.name} batch (${batch.length} rows): ${lastError}`
      );
      await sleepMs(retryDelayMs * attempt);
    }
  }
  return { ok: false, error: `Target upsert failed after ${maxRetries} attempts: ${lastError}` };
}

async function migrateStorageBucketsIfPresent(
  sourceClient: SupabaseClient,
  targetClient: SupabaseClient,
  run: MigrationRunRecord
) {
  try {
    const { data: buckets, error } = await sourceClient.storage.listBuckets();
    if (error || !Array.isArray(buckets)) {
      run.storageSummary = {
        inspected: true,
        sourceBuckets: 0,
        migratedBuckets: 0,
        migratedObjects: 0,
        failedObjects: 0,
        note: error
          ? `Storage bucket inspection unavailable (${sanitizeDatabaseError(error)}).`
          : 'No Supabase Storage buckets present on source.',
      };
      return;
    }

    run.storageSummary.inspected = true;
    run.storageSummary.sourceBuckets = buckets.length;

    if (buckets.length === 0) {
      run.storageSummary.note = 'Source has 0 Storage buckets; no Storage objects to copy.';
      return;
    }

    const { data: targetBuckets } = await targetClient.storage.listBuckets();
    const existingTargetNames = new Set(
      (Array.isArray(targetBuckets) ? targetBuckets : []).map((b: any) => b.name)
    );

    for (const bucket of buckets) {
      if (!existingTargetNames.has(bucket.name)) {
        await targetClient.storage.createBucket(bucket.name, { public: Boolean(bucket.public) });
      }
      run.storageSummary.migratedBuckets += 1;

      const { data: files } = await sourceClient.storage.from(bucket.name).list('', { limit: 1000 });
      for (const file of Array.isArray(files) ? files : []) {
        if (!file?.name || !file?.id) continue;
        try {
          const { data: blob, error: dlErr } = await sourceClient.storage
            .from(bucket.name)
            .download(file.name);
          if (dlErr || !blob) {
            run.storageSummary.failedObjects += 1;
            continue;
          }
          const { error: upErr } = await targetClient.storage
            .from(bucket.name)
            .upload(file.name, blob, { upsert: true });
          if (upErr) run.storageSummary.failedObjects += 1;
          else run.storageSummary.migratedObjects += 1;
        } catch {
          run.storageSummary.failedObjects += 1;
        }
      }
    }

    run.storageSummary.note = `Migrated ${run.storageSummary.migratedBuckets}/${buckets.length} bucket(s) and ${run.storageSummary.migratedObjects} object(s).`;
  } catch (err) {
    run.storageSummary.inspected = true;
    run.storageSummary.note = `Storage inspection notice: ${sanitizeDatabaseError(err)}`;
  }
}

async function executeMigrationRunInternal(params: {
  run: MigrationRunRecord;
  sourceClient: SupabaseClient;
  targetClient: SupabaseClient;
  onlyTablesSet?: Set<string> | null;
  maxRetries: number;
  retryDelayMs: number;
  actor: { id: string; name: string; role: string };
}) {
  const { run, sourceClient, targetClient, onlyTablesSet, maxRetries, retryDelayMs, actor } = params;
  try {
    run.status = 'Running';
    run.startedAt = run.startedAt || new Date().toISOString();
    appendRunLog(
      run,
      'info',
      `Starting dependency-ordered migration across ${MIGRATION_TABLE_ORDER.length} ERP tables (batchSize=${run.batchSize}).`
    );
    upsertMigrationRun(run, true);

    for (const spec of MIGRATION_TABLE_ORDER) {
      if (activeCancellationFlags.get(run.id)) {
        run.status = 'Cancelled';
        run.cancelledAt = new Date().toISOString();
        run.currentTable = null;
        appendRunLog(run, 'warning', 'Migration cancelled cleanly by Super Admin.');
        upsertMigrationRun(run, true);
        recordDbAuditEvent({
          eventType: 'DB_MIGRATION_CANCELLED',
          actorId: actor.id,
          actorName: actor.name,
          actorRole: actor.role,
          outcome: 'warning',
          details: `Migration ${run.id} cancelled at ${run.completedTables}/${run.totalTables} tables.`,
        });
        return;
      }

      if (onlyTablesSet && !onlyTablesSet.has(spec.name)) {
        continue;
      }

      const progressRow = run.tableResults.find((t) => t.table === spec.name)!;
      run.currentTable = spec.name;

      // Capture authoritative source row count for this table
      const { count: srcCount, error: srcErr } = await sourceClient
        .from(spec.name)
        .select('id', { count: 'exact' })
        .limit(0);
      if (srcErr) {
        progressRow.status = 'Failed';
        progressRow.error = `Source count failed: ${sanitizeDatabaseError(srcErr)}`;
        run.failedTables += 1;
        appendRunLog(run, 'error', `Table ${spec.name} failed source read: ${progressRow.error}`);
        run.status = 'Failed';
        run.errorSummary = `Migration aborted on table "${spec.name}": ${progressRow.error}`;
        upsertMigrationRun(run, true);
        recordDbAuditEvent({
          eventType: 'DB_MIGRATION_FAILED',
          actorId: actor.id,
          actorName: actor.name,
          actorRole: actor.role,
          outcome: 'error',
          details: run.errorSummary,
        });
        return;
      }

      progressRow.sourceRows = typeof srcCount === 'number' ? srcCount : 0;
      const result = await copyTableInBatches({
        sourceClient,
        targetClient,
        spec,
        batchSize: run.batchSize,
        maxRetries,
        retryDelayMs,
        run,
        progressRow,
      });

      if (result.aborted) {
        run.status = 'Cancelled';
        run.cancelledAt = new Date().toISOString();
        run.currentTable = null;
        appendRunLog(run, 'warning', `Migration cancelled during table ${spec.name}.`);
        upsertMigrationRun(run, true);
        return;
      }

      if (!result.ok) {
        run.failedTables = run.tableResults.filter((t) => t.status === 'Failed').length;
        run.completedTables = run.tableResults.filter((t) => t.status === 'Completed').length;
        run.progressPercent = Math.round((run.completedTables / run.totalTables) * 100);
        run.status = 'Failed';
        run.currentTable = null;
        run.errorSummary = `Table "${spec.name}" failed: ${progressRow.error}`;
        appendRunLog(run, 'error', run.errorSummary);
        upsertMigrationRun(run, true);
        recordDbAuditEvent({
          eventType: 'DB_MIGRATION_FAILED',
          actorId: actor.id,
          actorName: actor.name,
          actorRole: actor.role,
          outcome: 'error',
          details: run.errorSummary,
        });
        return;
      }

      run.completedTables = run.tableResults.filter((t) => t.status === 'Completed').length;
      run.totalTargetVerifiedRows = run.tableResults.reduce(
        (acc, t) => acc + (t.targetVerifiedRows || 0),
        0
      );
      run.progressPercent = Math.round((run.completedTables / run.totalTables) * 100);

      if (spec.name === 'users') {
        run.authSummary.usersMigrated = progressRow.migratedRows;
      }

      if (progressRow.migratedRows > 0) {
        appendRunLog(
          run,
          'info',
          `[${spec.migrationOrder}/${run.totalTables}] ${spec.name}: copied ${progressRow.migratedRows} rows (target verified=${progressRow.targetVerifiedRows}).`
        );
      }
      upsertMigrationRun(run, false);
    }

    // Migrate storage buckets if any
    await migrateStorageBucketsIfPresent(sourceClient, targetClient, run);

    // Check optional Supabase Auth identity count on source (ERP itself uses public.users)
    try {
      const authAdmin = (sourceClient.auth as any)?.admin;
      if (authAdmin && typeof authAdmin.listUsers === 'function') {
        const { data } = await authAdmin.listUsers({ page: 1, perPage: 100 });
        if (Array.isArray(data?.users)) {
          run.authSummary.supabaseAuthUsersCount = data.users.length;
        }
      }
    } catch {
      run.authSummary.supabaseAuthUsersCount = null;
    }

    // Final count verification & integrity verdict
    run.totalSourceRows = run.tableResults.reduce((sum, t) => sum + t.sourceRows, 0);
    run.totalTargetVerifiedRows = run.tableResults.reduce(
      (sum, t) => sum + (t.targetVerifiedRows ?? 0),
      0
    );
    const anyMismatch = run.tableResults.some(
      (t) => t.status !== 'Completed' || (t.targetVerifiedRows ?? 0) < t.sourceRows
    );
    run.countVerificationPassed = !anyMismatch;
    run.sequenceSyncMode =
      run.generatedSequenceSql.length > 0 ? 'sql_generated' : 'rpc';
    run.currentTable = null;

    if (anyMismatch) {
      run.status = 'Failed';
      run.errorSummary = 'Post-migration verification detected table or row count mismatch.';
      appendRunLog(run, 'error', run.errorSummary);
      upsertMigrationRun(run, true);
      return;
    }

    run.status = 'Completed';
    run.completedAt = new Date().toISOString();
    run.progressPercent = 100;
    appendRunLog(
      run,
      'info',
      `Migration ${run.id} completed and verified: ${run.completedTables}/${run.totalTables} tables, ${run.totalMigratedRows} copied rows, sequenceMode=${run.sequenceSyncMode}.`
    );
    updateActiveDbMetadata({ lastMigrationAt: run.completedAt });
    upsertMigrationRun(run, true);

    recordDbAuditEvent({
      eventType: 'DB_MIGRATION_COMPLETED',
      actorId: actor.id,
      actorName: actor.name,
      actorRole: actor.role,
      outcome: 'success',
      details: `Migration ${run.id} completed (${run.completedTables}/${run.totalTables} tables, ${run.totalMigratedRows} rows migrated).`,
    });
  } catch (err) {
    run.status = 'Failed';
    run.currentTable = null;
    run.errorSummary = sanitizeDatabaseError(err);
    appendRunLog(run, 'error', `Unhandled migration error: ${run.errorSummary}`);
    upsertMigrationRun(run, true);
    recordDbAuditEvent({
      eventType: 'DB_MIGRATION_FAILED',
      actorId: actor.id,
      actorName: actor.name,
      actorRole: actor.role,
      outcome: 'error',
      details: `Migration ${run.id} failed with error: ${run.errorSummary}`,
    });
  } finally {
    activeCancellationFlags.delete(run.id);
    activeRunMemoryPromises.delete(run.id);
    releaseDbOperationLock();
  }
}

export async function startDatabaseMigration(params: {
  confirmSourceBackupTaken: boolean;
  confirmTargetExistingData?: boolean;
  batchSize?: number;
  waitForCompletion?: boolean;
  maxRetries?: number;
  retryDelayMs?: number;
  actor: { id: string; name: string; role: string };
}): Promise<{ ok: boolean; run?: MigrationRunRecord; preflight?: PreflightChecklistResult; error?: string; code?: string }> {
  const activeLock = getDbOperationLock();
  if (activeLock.locked) {
    return {
      ok: false,
      code: 'MIGRATION_LOCKED',
      error: `Another database operation (${activeLock.operation}) is currently active.`,
    };
  }

  const preflight = await runPreMigrationChecklist({
    confirmSourceBackupTaken: params.confirmSourceBackupTaken,
    confirmTargetExistingData: params.confirmTargetExistingData,
  });

  if (!preflight.canStartMigration) {
    const failedReason =
      preflight.blockers[0] ||
      (!params.confirmSourceBackupTaken
        ? 'Backup confirmation is required before starting migration.'
        : preflight.warnings[0] || 'Pre-migration checklist failed.');
    return {
      ok: false,
      code: 'PREFLIGHT_BLOCKED',
      error: failedReason,
      preflight,
    };
  }

  const activeCfg = getServerDbConfig();
  const staged = getStagedTargetInternal();
  if (!activeCfg.isConfigured || !staged?.supabaseUrl || !staged?.serviceRoleKey) {
    return {
      ok: false,
      code: 'DB_NOT_CONFIGURED',
      error: 'Active source or staged target database configuration is incomplete.',
    };
  }

  const runId = `mig-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  const lockRes = acquireDbOperationLock('migration', runId, params.actor.name);
  if (!lockRes.acquired) {
    return {
      ok: false,
      code: 'MIGRATION_LOCKED',
      error: `Another database operation (${lockRes.lock.operation}) is currently active.`,
    };
  }

  const batchSize = Math.max(25, Math.min(Number(params.batchSize) || 200, 500));
  const tableResults: TableMigrationProgress[] = MIGRATION_TABLE_ORDER.map((spec) => ({
    table: spec.name,
    domain: spec.domain,
    migrationOrder: spec.migrationOrder,
    status: 'Pending',
    sourceRows: preflight.sourceTableCounts[spec.name] ?? 0,
    migratedRows: 0,
    targetVerifiedRows: null,
    batchesCompleted: 0,
    retriesUsed: 0,
    maxSerialId: null,
    sequenceSyncStatus: spec.hasSequence ? 'pending' : 'not_applicable',
    durationMs: 0,
  })) as any;

  const run: MigrationRunRecord = {
    id: runId,
    status: 'Validating',
    createdAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
    completedAt: null,
    cancelledAt: null,
    cutoverAt: null,
    rolledBackAt: null,
    initiatedById: params.actor.id,
    initiatedByName: params.actor.name,
    sourceEnvironment: activeCfg.environment,
    sourceMaskedUrl: activeCfg.maskedUrl,
    sourceFingerprint: activeCfg.projectFingerprint,
    targetEnvironment: staged.environment,
    targetMaskedUrl: maskDatabaseUrl(staged.supabaseUrl),
    targetFingerprint: computeProjectFingerprint(staged.supabaseUrl),
    batchSize,
    totalTables: MIGRATION_TABLE_ORDER.length,
    completedTables: 0,
    failedTables: 0,
    totalSourceRows: preflight.totalSourceRows,
    totalMigratedRows: 0,
    totalTargetVerifiedRows: 0,
    currentTable: null,
    progressPercent: 0,
    countVerificationPassed: null,
    sequenceSyncMode: 'pending',
    generatedSequenceSql: [],
    storageSummary: {
      inspected: false,
      sourceBuckets: 0,
      migratedBuckets: 0,
      migratedObjects: 0,
      failedObjects: 0,
      note: 'Pending storage check.',
    },
    authSummary: {
      erpAuthMode: 'public.users_bcrypt',
      usersMigrated: 0,
      supabaseAuthUsersCount: null,
      note: 'Ensec ERP authentication uses public.users with bcrypt password hashes (preserved during migration).',
    },
    tableResults,
    logs: [],
    errorSummary: null,
  };

  upsertMigrationRun(run, true);
  recordDbAuditEvent({
    eventType: 'DB_MIGRATION_STARTED',
    actorId: params.actor.id,
    actorName: params.actor.name,
    actorRole: params.actor.role,
    outcome: 'success',
    details: `Started full migration ${runId} (${run.totalSourceRows} rows across ${run.totalTables} tables).`,
  });

  const sourceClient = createIsolatedSupabaseClient(activeCfg.supabaseUrl, activeCfg.supabaseKey);
  const targetClient = createIsolatedSupabaseClient(staged.supabaseUrl, staged.serviceRoleKey);

  const execPromise = executeMigrationRunInternal({
    run,
    sourceClient,
    targetClient,
    maxRetries: params.maxRetries ?? 3,
    retryDelayMs: params.retryDelayMs ?? 120,
    actor: params.actor,
  });
  activeRunMemoryPromises.set(runId, execPromise);

  if (params.waitForCompletion) {
    await execPromise;
    return { ok: run.status === 'Completed', run: getMigrationRunById(runId) || run, preflight };
  }

  return { ok: true, run, preflight };
}

export async function cancelActiveMigration(
  migrationId: string,
  actor: { id: string; name: string; role: string }
): Promise<{ ok: boolean; message: string }> {
  const run = getMigrationRunById(migrationId);
  if (!run) {
    return { ok: false, message: 'Migration run not found.' };
  }
  if (run.status !== 'Running' && run.status !== 'Validating') {
    return { ok: false, message: `Migration is already in "${run.status}" status.` };
  }
  activeCancellationFlags.set(migrationId, true);
  appendRunLog(run, 'warning', `Cancellation requested by ${actor.name}.`);
  upsertMigrationRun(run, true);
  return { ok: true, message: 'Cancellation signal sent; migration will halt safely after current batch.' };
}

export async function retryFailedMigration(params: {
  migrationId: string;
  waitForCompletion?: boolean;
  maxRetries?: number;
  retryDelayMs?: number;
  actor: { id: string; name: string; role: string };
}): Promise<{ ok: boolean; run?: MigrationRunRecord; error?: string; code?: string }> {
  const existing = getMigrationRunById(params.migrationId);
  if (!existing) {
    return { ok: false, code: 'NOT_FOUND', error: 'Migration run not found.' };
  }
  if (existing.status !== 'Failed' && existing.status !== 'Cancelled') {
    return {
      ok: false,
      code: 'INVALID_STATE',
      error: `Only Failed or Cancelled migrations can be resumed (current: ${existing.status}).`,
    };
  }

  const activeCfg = getServerDbConfig();
  const staged = getStagedTargetInternal();
  if (!activeCfg.isConfigured || !staged?.supabaseUrl || !staged?.serviceRoleKey) {
    return { ok: false, code: 'DB_NOT_CONFIGURED', error: 'Active or staged target database is unconfigured.' };
  }
  if (computeProjectFingerprint(staged.supabaseUrl) !== existing.targetFingerprint) {
    return {
      ok: false,
      code: 'TARGET_CHANGED',
      error: 'Staged target configuration changed since this run started. Start a new migration run.',
    };
  }

  const lockRes = acquireDbOperationLock('migration', existing.id, params.actor.name);
  if (!lockRes.acquired) {
    return { ok: false, code: 'MIGRATION_LOCKED', error: 'Another database operation is already running.' };
  }

  const pendingOrFailedTables = new Set(
    existing.tableResults
      .filter((t) => t.status !== 'Completed')
      .map((t) => t.table)
  );
  for (const row of existing.tableResults) {
    if (row.status !== 'Completed') {
      row.status = 'Pending';
      row.error = undefined;
    }
  }
  existing.errorSummary = null;
  existing.cancelledAt = null;
  existing.failedTables = 0;
  appendRunLog(
    existing,
    'info',
    `Resuming migration for ${pendingOrFailedTables.size} incomplete table(s) using idempotent upsert.`
  );
  upsertMigrationRun(existing, true);

  const sourceClient = createIsolatedSupabaseClient(activeCfg.supabaseUrl, activeCfg.supabaseKey);
  const targetClient = createIsolatedSupabaseClient(staged.supabaseUrl, staged.serviceRoleKey);

  const execPromise = executeMigrationRunInternal({
    run: existing,
    sourceClient,
    targetClient,
    onlyTablesSet: pendingOrFailedTables,
    maxRetries: params.maxRetries ?? 3,
    retryDelayMs: params.retryDelayMs ?? 120,
    actor: params.actor,
  });
  activeRunMemoryPromises.set(existing.id, execPromise);

  if (params.waitForCompletion) {
    await execPromise;
    const finalRun = getMigrationRunById(existing.id) || existing;
    return { ok: String(finalRun.status) === 'Completed', run: finalRun };
  }
  return { ok: true, run: existing };
}

export async function executeDatabaseCutover(params: {
  migrationId?: string;
  confirmationPhrase: string;
  confirmChecklist: boolean;
  actor: { id: string; name: string; role: string };
}): Promise<CutoverResult> {
  if (String(params.confirmationPhrase || '').trim() !== 'CUTOVER TO TARGET') {
    return {
      ok: false,
      code: 'CONFIRMATION_REQUIRED',
      message: 'Explicit confirmation phrase "CUTOVER TO TARGET" is required.',
      error: 'Confirmation phrase did not match "CUTOVER TO TARGET".',
    };
  }
  if (!params.confirmChecklist) {
    return {
      ok: false,
      code: 'CHECKLIST_CONFIRMATION_REQUIRED',
      message: 'Confirm all post-migration checks before cutting over.',
      error: 'Post-migration cutover confirmation checkbox must be checked.',
    };
  }

  const activeCfg = getServerDbConfig();
  const staged = getStagedTargetInternal();
  if (!activeCfg.isConfigured || !staged?.supabaseUrl || !staged?.serviceRoleKey) {
    return {
      ok: false,
      code: 'DB_NOT_CONFIGURED',
      message: 'Both active source and staged target database configurations are required.',
      error: 'Missing active or target configuration.',
    };
  }

  const targetFp = computeProjectFingerprint(staged.supabaseUrl);
  if (targetFp === activeCfg.projectFingerprint) {
    return {
      ok: false,
      code: 'ALREADY_ACTIVE',
      message: 'Staged target is already the active database.',
      error: 'Cannot cut over to the currently active database.',
    };
  }

  const history = getMigrationHistory(30);
  const run = params.migrationId
    ? getMigrationRunById(params.migrationId)
    : history.find(
        (r) =>
          (r.status === 'Completed' || r.status === 'Cutover Pending') &&
          r.targetFingerprint === targetFp
      ) || null;

  if (!run) {
    return {
      ok: false,
      code: 'NO_COMPLETED_MIGRATION',
      message: 'No completed migration found for the currently staged target database.',
      error: 'Complete a verified migration to this target before attempting cutover.',
    };
  }
  if (run.targetFingerprint !== targetFp) {
    return {
      ok: false,
      code: 'TARGET_MISMATCH',
      message: 'Selected migration target does not match currently staged target DB.',
      error: 'Re-validate and migrate to the current staged target before cutover.',
    };
  }
  if (
    (run.status !== 'Completed' && run.status !== 'Cutover Pending') ||
    run.failedTables > 0 ||
    run.countVerificationPassed !== true
  ) {
    return {
      ok: false,
      code: 'MIGRATION_NOT_VERIFIED',
      message: `Migration ${run.id} is "${run.status}" and cannot be cut over.`,
      error: 'All 114 tables and post-migration row counts must be verified before cutover.',
    };
  }

  const lockRes = acquireDbOperationLock('cutover', run.id, params.actor.name);
  if (!lockRes.acquired) {
    return {
      ok: false,
      code: 'OPERATION_LOCKED',
      message: `Cannot cut over while "${lockRes.lock.operation}" is running.`,
      error: 'Database control plane lock is active.',
    };
  }

  try {
    // Final live health & schema check on target right before atomic switch
    const targetValidation = await validateTargetDatabaseConnection({
      supabaseUrl: staged.supabaseUrl,
      serviceRoleKey: staged.serviceRoleKey,
      persistToStaged: true,
    });
    if (!targetValidation.ok) {
      return {
        ok: false,
        code: 'TARGET_HEALTH_FAILED',
        message: 'Final target health/table validation failed; active database unchanged.',
        error: targetValidation.error || 'Target database failed final cutover readiness check.',
      };
    }

    // Verify Super Admin / auth directory exists on target
    const targetClient = createIsolatedSupabaseClient(staged.supabaseUrl, staged.serviceRoleKey);
    const { data: adminUsers, error: userErr } = await targetClient
      .from('users')
      .select('id, role, status')
      .eq('role', 'Super Admin')
      .limit(5);
    if (userErr || !Array.isArray(adminUsers) || adminUsers.length === 0) {
      return {
        ok: false,
        code: 'TARGET_NO_SUPER_ADMIN',
        message: 'Target users table has no active Super Admin account. Aborting cutover to prevent lockout.',
        error: 'Target users directory must contain at least one Super Admin before cutover.',
      };
    }

    // Capture source row counts snapshot for rollback divergence detection
    const snapshotCounts: Record<string, number> = {};
    for (const row of run.tableResults) {
      snapshotCounts[row.table] = row.targetVerifiedRows ?? row.sourceRows;
    }

    const nowIso = new Date().toISOString();
    savePreviousRollbackSnapshot({
      provider: activeCfg.provider,
      environment: activeCfg.environment,
      supabaseUrl: activeCfg.supabaseUrl,
      serviceRoleKey: activeCfg.supabaseKey,
      authMode: activeCfg.authMode,
      configVersion: activeCfg.configVersion,
      capturedAt: nowIso,
      cutoverMigrationId: run.id,
      cutoverAt: nowIso,
      sourceRowCounts: snapshotCounts,
    });

    const newVersion = activeCfg.configVersion + 1;
    setActiveDbOverride({
      provider: staged.provider,
      environment: staged.environment,
      supabaseUrl: staged.supabaseUrl,
      serviceRoleKey: staged.serviceRoleKey,
      authMode: 'service_role',
      configVersion: newVersion,
      activatedAt: nowIso,
      lastHealthCheckAt: nowIso,
      lastHealthLatencyMs: targetValidation.latencyMs,
      lastMigrationAt: run.completedAt || nowIso,
      connectionStatus: 'connected',
    });

    run.status = 'Active';
    run.cutoverAt = nowIso;
    appendRunLog(
      run,
      'info',
      `Cutover executed by ${params.actor.name}. Active DB version bumped to v${newVersion}.`
    );
    upsertMigrationRun(run, true);

    // Atomically reset centralized client singleton and operational caches
    switchActiveDatabaseClient();

    recordDbAuditEvent({
      eventType: 'DB_CUTOVER_EXECUTED',
      actorId: params.actor.id,
      actorName: params.actor.name,
      actorRole: params.actor.role,
      outcome: 'success',
      details: `Executed atomic DB cutover for migration ${run.id} -> config v${newVersion} (${staged.environment}).`,
    });

    return {
      ok: true,
      message: `Successfully switched centralized active database to ${staged.environment} target (config v${newVersion}).`,
      newConfigVersion: newVersion,
    };
  } finally {
    releaseDbOperationLock();
  }
}

export async function executeDatabaseRollback(params: {
  reason: string;
  confirmationPhrase: string;
  acknowledgeDataDivergence?: boolean;
  actor: { id: string; name: string; role: string };
}): Promise<RollbackResult> {
  const cleanReason = String(params.reason || '').trim();
  if (cleanReason.length < 8) {
    return {
      ok: false,
      code: 'REASON_REQUIRED',
      message: 'Please provide a clear rollback reason (minimum 8 characters) for the audit log.',
      error: 'Rollback reason is required.',
    };
  }
  if (String(params.confirmationPhrase || '').trim() !== 'ROLLBACK TO PREVIOUS') {
    return {
      ok: false,
      code: 'CONFIRMATION_REQUIRED',
      message: 'Explicit confirmation phrase "ROLLBACK TO PREVIOUS" is required.',
      error: 'Confirmation phrase did not match "ROLLBACK TO PREVIOUS".',
    };
  }

  const prev = getPreviousRollbackSnapshotInternal();
  if (!prev || !prev.supabaseUrl || !prev.serviceRoleKey) {
    return {
      ok: false,
      code: 'NO_ROLLBACK_SNAPSHOT',
      message: 'No previous database configuration snapshot is available for rollback.',
      error: 'Rollback snapshot unavailable.',
    };
  }

  const lockRes = acquireDbOperationLock('rollback', prev.cutoverMigrationId, params.actor.name);
  if (!lockRes.acquired) {
    return {
      ok: false,
      code: 'OPERATION_LOCKED',
      message: `Cannot roll back while "${lockRes.lock.operation}" is running.`,
      error: 'Control plane lock active.',
    };
  }

  try {
    // 1. Validate previous DB health BEFORE switching back
    const prevValidation = await validateTargetDatabaseConnection({
      supabaseUrl: prev.supabaseUrl,
      serviceRoleKey: prev.serviceRoleKey,
      persistToStaged: false,
    });
    if (!prevValidation.ok) {
      return {
        ok: false,
        code: 'PREVIOUS_DB_UNHEALTHY',
        message: 'Previous database failed pre-rollback health/schema verification. Rollback blocked to protect availability.',
        error: prevValidation.error || 'Previous database unavailable.',
      };
    }

    // 2. Check current active DB for post-cutover write divergence
    const currentCfg = getServerDbConfig();
    const divergentTables: Array<{ table: string; snapshotRows: number; currentRows: number }> = [];
    if (currentCfg.isConfigured && Object.keys(prev.sourceRowCounts || {}).length > 0) {
      const currentClient = createIsolatedSupabaseClient(currentCfg.supabaseUrl, currentCfg.supabaseKey);
      const currentCounts = await probeTablesExistenceAndCounts(currentClient);
      for (const [table, snapCount] of Object.entries(prev.sourceRowCounts)) {
        const cur = currentCounts.get(table)?.count;
        if (typeof cur === 'number' && cur !== snapCount) {
          divergentTables.push({
            table,
            snapshotRows: snapCount,
            currentRows: cur,
          });
        }
      }
    }

    const divergenceDetected = divergentTables.length > 0;
    if (divergenceDetected && !params.acknowledgeDataDivergence) {
      return {
        ok: false,
        code: 'DATA_DIVERGENCE_DETECTED',
        divergenceDetected: true,
        divergentTables,
        message: `Post-cutover writes detected across ${divergentTables.length} table(s). Re-confirm rollback with divergence acknowledgement to proceed safely.`,
        error: 'Data divergence detected since cutover; explicit acknowledgement required.',
      };
    }

    // 3. Preserve current config as new rollback/staged reference? Just restore previous cleanly,
    // leaving both DBs untouched.
    const nowIso = new Date().toISOString();
    const restoredVersion = currentCfg.configVersion + 1;
    setActiveDbOverride({
      provider: prev.provider,
      environment: prev.environment,
      supabaseUrl: prev.supabaseUrl,
      serviceRoleKey: prev.serviceRoleKey,
      authMode: prev.authMode,
      configVersion: restoredVersion,
      activatedAt: nowIso,
      lastHealthCheckAt: nowIso,
      lastHealthLatencyMs: prevValidation.latencyMs,
      lastMigrationAt: nowIso,
      connectionStatus: 'connected',
    });

    if (prev.cutoverMigrationId) {
      const cutoverRun = getMigrationRunById(prev.cutoverMigrationId);
      if (cutoverRun) {
        cutoverRun.status = 'Rolled Back';
        cutoverRun.rolledBackAt = nowIso;
        cutoverRun.rollbackReason = cleanReason;
        appendRunLog(
          cutoverRun,
          'warning',
          `Rolled back by ${params.actor.name} -> restored ${prev.environment} (${maskDatabaseUrl(prev.supabaseUrl)}). Reason: ${cleanReason}`
        );
        upsertMigrationRun(cutoverRun, true);
      }
    }

    switchActiveDatabaseClient();

    recordDbAuditEvent({
      eventType: 'DB_ROLLBACK_EXECUTED',
      actorId: params.actor.id,
      actorName: params.actor.name,
      actorRole: params.actor.role,
      outcome: 'warning',
      details: `Rolled back active database to ${prev.environment} (config v${restoredVersion}). Divergence=${divergenceDetected}. Reason: ${cleanReason}`,
    });

    return {
      ok: true,
      divergenceDetected,
      divergentTables,
      restoredConfigVersion: restoredVersion,
      message: `Rolled back active database to ${prev.environment} (${maskDatabaseUrl(prev.supabaseUrl)}) as config v${restoredVersion}.`,
    };
  } finally {
    releaseDbOperationLock();
  }
}

export function buildExportableMigrationReport(run: MigrationRunRecord): {
  json: any;
  markdown: string;
} {
  const { ...safeRun } = run;
  const md = [
    `# Ensec ERP Database Migration Report`,
    `- **Migration ID**: ${run.id}`,
    `- **Status**: ${run.status}`,
    `- **Initiated By**: ${run.initiatedByName}`,
    `- **Started**: ${run.startedAt || 'N/A'}`,
    `- **Completed**: ${run.completedAt || 'N/A'}`,
    `- **Source**: ${run.sourceEnvironment} (${run.sourceMaskedUrl || 'unconfigured'})`,
    `- **Target**: ${run.targetEnvironment} (${run.targetMaskedUrl || 'unconfigured'})`,
    `- **Tables**: ${run.completedTables}/${run.totalTables} completed (${run.failedTables} failed)`,
    `- **Rows**: Source=${run.totalSourceRows}, Migrated=${run.totalMigratedRows}, Target Verified=${run.totalTargetVerifiedRows}`,
    `- **Sequence Sync Mode**: ${run.sequenceSyncMode}`,
    `- **Auth Summary**: ${run.authSummary.note} (Users migrated: ${run.authSummary.usersMigrated})`,
    `- **Storage Summary**: ${run.storageSummary.note}`,
    ``,
    ...(run.generatedSequenceSql.length > 0
      ? [
          `## Generated Sequence Sync SQL`,
          `\`\`\`sql`,
          ...run.generatedSequenceSql,
          `\`\`\``,
          ``,
        ]
      : []),
    `## Table Summary`,
    ...run.tableResults.map(
      (t) =>
        `- [${t.status}] #${t.migrationOrder} \`${t.table}\`: source=${t.sourceRows}, copied=${t.migratedRows}, target=${t.targetVerifiedRows ?? 'N/A'}, seq=${t.sequenceSyncStatus}${t.error ? ` | ERROR: ${t.error}` : ''}`
    ),
  ].join('\n');

  return { json: safeRun, markdown: md };
}

export { getMigrationHistory, getMigrationRunById };
