/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Encrypted Server-Side Database Control & Migration Store
 * Persists active override config, staged target credentials (AES-256-GCM encrypted),
 * previous rollback snapshot, migration run history, concurrency locks, and audit events.
 * Credentials are strictly isolated server-side and never serialized to public/UI objects.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  computeProjectFingerprint,
  computeSecretFingerprint,
  getConfigMasterKey,
  maskDatabaseUrl,
  redactSensitiveText,
  type ConnectionHealthStatus,
  type DatabaseEnvironment,
  type DatabaseProvider,
  type MigrationLifecycleStatus,
  type ServerDbAuthMode,
} from './configCore.ts';

export interface StoredDbCredentials {
  provider: DatabaseProvider;
  environment: DatabaseEnvironment;
  supabaseUrl: string;
  serviceRoleKey: string;
  authMode: ServerDbAuthMode;
  configVersion: number;
  activatedAt?: string;
  lastHealthCheckAt?: string | null;
  lastHealthLatencyMs?: number | null;
  lastMigrationAt?: string | null;
  connectionStatus?: ConnectionHealthStatus;
}

export interface TargetValidationSummary {
  ok: boolean;
  checkedAt: string;
  latencyMs: number | null;
  reachable: boolean;
  schemaAccessible: boolean;
  totalExpectedTables: number;
  verifiedTablesCount: number;
  missingTablesCount: number;
  missingTables: string[];
  criticalTablesReady: boolean;
  readPrivilegeOk: boolean;
  writePrivilegeOk: boolean | null;
  writePrivilegeNote: string;
  postgresInspectorRpcAvailable: boolean;
  error?: string;
}

export interface StagedTargetSummary {
  configured: boolean;
  provider: DatabaseProvider;
  environment: DatabaseEnvironment;
  maskedUrl: string | null;
  projectFingerprint: string | null;
  hasServiceRoleKey: boolean;
  keyFingerprint: string | null;
  savedAt: string | null;
  savedBy: string | null;
  lastValidation: TargetValidationSummary | null;
  lastSchemaComparisonAt: string | null;
  lastSchemaCompatibilityStatus: string | null;
  lastPreflightOk: boolean | null;
}

export interface PreviousRollbackSnapshotSummary {
  available: boolean;
  provider: DatabaseProvider;
  environment: DatabaseEnvironment;
  maskedUrl: string | null;
  projectFingerprint: string | null;
  configVersion: number;
  capturedAt: string;
  cutoverMigrationId: string | null;
  cutoverAt: string;
  sourceRowCounts: Record<string, number>;
}

export interface TableMigrationProgress {
  table: string;
  domain: string;
  migrationOrder: number;
  status: 'Pending' | 'Running' | 'Completed' | 'Failed' | 'Skipped';
  sourceRows: number;
  migratedRows: number;
  targetVerifiedRows: number | null;
  batchesCompleted: number;
  retriesUsed: number;
  maxSerialId: number | null;
  sequenceSyncStatus: 'synced' | 'sql_required' | 'not_applicable' | 'failed';
  durationMs: number;
  error?: string;
}

export interface MigrationRunRecord {
  id: string;
  status: MigrationLifecycleStatus;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  cancelledAt: string | null;
  cutoverAt: string | null;
  rolledBackAt: string | null;
  initiatedById: string;
  initiatedByName: string;
  sourceEnvironment: DatabaseEnvironment;
  sourceMaskedUrl: string | null;
  sourceFingerprint: string | null;
  targetEnvironment: DatabaseEnvironment;
  targetMaskedUrl: string | null;
  targetFingerprint: string | null;
  batchSize: number;
  totalTables: number;
  completedTables: number;
  failedTables: number;
  totalSourceRows: number;
  totalMigratedRows: number;
  totalTargetVerifiedRows: number;
  currentTable: string | null;
  progressPercent: number;
  countVerificationPassed: boolean | null;
  sequenceSyncMode: 'rpc' | 'sql_generated' | 'pending';
  generatedSequenceSql: string[];
  storageSummary: {
    inspected: boolean;
    sourceBuckets: number;
    migratedBuckets: number;
    migratedObjects: number;
    failedObjects: number;
    note: string;
  };
  authSummary: {
    erpAuthMode: 'public.users_bcrypt';
    usersMigrated: number;
    supabaseAuthUsersCount: number | null;
    note: string;
  };
  tableResults: TableMigrationProgress[];
  logs: Array<{ timestamp: string; level: 'info' | 'warning' | 'error'; message: string }>;
  errorSummary: string | null;
  rollbackReason?: string | null;
}

export interface MigrationOperationLock {
  locked: boolean;
  operation: 'migration' | 'cutover' | 'rollback' | null;
  migrationId: string | null;
  startedAt: string | null;
  actorName: string | null;
}

export interface PersistedPreviousRollbackSnapshot {
  provider: DatabaseProvider;
  environment: DatabaseEnvironment;
  supabaseUrl: string;
  serviceRoleKey: string;
  authMode: ServerDbAuthMode;
  configVersion: number;
  capturedAt: string;
  cutoverMigrationId: string | null;
  cutoverAt: string;
  sourceRowCounts: Record<string, number>;
}

interface PersistedControlPlaneState {
  schemaVersion: 1;
  activeOverride: StoredDbCredentials | null;
  activeMeta: {
    environment?: DatabaseEnvironment;
    lastHealthCheckAt?: string | null;
    lastHealthLatencyMs?: number | null;
    lastMigrationAt?: string | null;
    connectionStatus?: ConnectionHealthStatus;
    schemaCompatibilityStatus?: string | null;
    schemaCompatibilityCheckedAt?: string | null;
  };
  stagedTarget: {
    provider: DatabaseProvider;
    environment: DatabaseEnvironment;
    supabaseUrl: string;
    serviceRoleKey: string;
    savedAt: string;
    savedBy: string;
    lastValidation: TargetValidationSummary | null;
    lastSchemaComparisonAt: string | null;
    lastSchemaCompatibilityStatus: string | null;
    lastPreflightOk: boolean | null;
  } | null;
  previousSnapshot: PersistedPreviousRollbackSnapshot | null;
  migrationHistory: MigrationRunRecord[];
}

interface EncryptedEnvelope {
  v: 1;
  alg: 'aes-256-gcm';
  iv: string;
  tag: string;
  ciphertext: string;
  updatedAt: string;
}

const DEFAULT_STATE_FILE = path.resolve(process.cwd(), '.ensec-server-state', 'db-control.enc.json');
const MAX_MIGRATION_HISTORY = 30;
const MAX_LOGS_PER_RUN = 400;

function resolveStateFilePath(): string {
  const custom = (process.env.ENSEC_DB_STATE_PATH || '').trim();
  return custom ? path.resolve(custom) : DEFAULT_STATE_FILE;
}

function emptyState(): PersistedControlPlaneState {
  return {
    schemaVersion: 1,
    activeOverride: null,
    activeMeta: {},
    stagedTarget: null,
    previousSnapshot: null,
    migrationHistory: [],
  };
}

let inMemoryStateCache: PersistedControlPlaneState | null = null;
let loadedPath = '';
let activeOperationLock: MigrationOperationLock = {
  locked: false,
  operation: null,
  migrationId: null,
  startedAt: null,
  actorName: null,
};

function loadStateFromDisk(): PersistedControlPlaneState {
  const filePath = resolveStateFilePath();
  if (inMemoryStateCache && loadedPath === filePath) {
    return inMemoryStateCache;
  }

  loadedPath = filePath;
  try {
    if (!fs.existsSync(filePath)) {
      inMemoryStateCache = emptyState();
      return inMemoryStateCache;
    }
    const raw = fs.readFileSync(filePath, 'utf8');
    const envelope = JSON.parse(raw) as EncryptedEnvelope;
    if (!envelope || envelope.alg !== 'aes-256-gcm' || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
      inMemoryStateCache = emptyState();
      return inMemoryStateCache;
    }
    const { key } = getConfigMasterKey();
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(envelope.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');

    const parsed = JSON.parse(decrypted) as PersistedControlPlaneState;
    if (!parsed || parsed.schemaVersion !== 1) {
      inMemoryStateCache = emptyState();
      return inMemoryStateCache;
    }
    inMemoryStateCache = {
      ...emptyState(),
      ...parsed,
      migrationHistory: Array.isArray(parsed.migrationHistory)
        ? parsed.migrationHistory.slice(0, MAX_MIGRATION_HISTORY)
        : [],
    };
    // Recover cleanly if server crashed mid-migration
    for (const run of inMemoryStateCache.migrationHistory) {
      if (run.status === 'Running' || run.status === 'Validating') {
        run.status = 'Failed';
        run.errorSummary =
          run.errorSummary || 'Server restarted while migration was running. You can safely retry.';
      }
    }
    return inMemoryStateCache;
  } catch {
    inMemoryStateCache = emptyState();
    return inMemoryStateCache;
  }
}

function persistStateToDisk(state: PersistedControlPlaneState): void {
  const filePath = resolveStateFilePath();
  loadedPath = filePath;
  inMemoryStateCache = state;

  try {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const { key } = getConfigMasterKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from(JSON.stringify(state), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const envelope: EncryptedEnvelope = {
      v: 1,
      alg: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      updatedAt: new Date().toISOString(),
    };

    const tempPath = `${filePath}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(envelope, null, 2), { mode: 0o600 });
    fs.renameSync(tempPath, filePath);
  } catch (err) {
    console.warn(
      '[DB Store] Unable to persist encrypted DB control state to disk; keeping active state in memory:',
      redactSensitiveText(err instanceof Error ? err.message : String(err))
    );
  }
}

export function resetStoreCacheForTest(): void {
  inMemoryStateCache = null;
  loadedPath = '';
  activeOperationLock = {
    locked: false,
    operation: null,
    migrationId: null,
    startedAt: null,
    actorName: null,
  };
}

export function getActiveDbOverride(): StoredDbCredentials | null {
  return loadStateFromDisk().activeOverride;
}

export function getActiveDbMetadata(): PersistedControlPlaneState['activeMeta'] {
  return loadStateFromDisk().activeMeta || {};
}

export function updateActiveDbMetadata(
  patch: Partial<PersistedControlPlaneState['activeMeta']>
): void {
  const state = loadStateFromDisk();
  state.activeMeta = {
    ...state.activeMeta,
    ...patch,
  };
  persistStateToDisk(state);
}

export function setActiveDbOverride(creds: StoredDbCredentials): void {
  const state = loadStateFromDisk();
  state.activeOverride = { ...creds };
  state.activeMeta = {
    ...state.activeMeta,
    environment: creds.environment,
    lastHealthCheckAt: creds.lastHealthCheckAt ?? state.activeMeta.lastHealthCheckAt ?? null,
    lastHealthLatencyMs: creds.lastHealthLatencyMs ?? state.activeMeta.lastHealthLatencyMs ?? null,
    lastMigrationAt: creds.lastMigrationAt ?? state.activeMeta.lastMigrationAt ?? null,
    connectionStatus: creds.connectionStatus || 'switched',
  };
  persistStateToDisk(state);
}

export function getStagedTargetInternal(): PersistedControlPlaneState['stagedTarget'] {
  return loadStateFromDisk().stagedTarget;
}

export function saveStagedTargetConfig(input: {
  provider: DatabaseProvider;
  environment: DatabaseEnvironment;
  supabaseUrl: string;
  serviceRoleKey: string;
  savedBy: string;
}): StagedTargetSummary {
  const state = loadStateFromDisk();
  const prevUrl = state.stagedTarget?.supabaseUrl || '';
  const prevKey = state.stagedTarget?.serviceRoleKey || '';
  const finalKey = input.serviceRoleKey || (prevUrl === input.supabaseUrl ? prevKey : '');
  const urlChanged = prevUrl !== input.supabaseUrl || prevKey !== finalKey;

  state.stagedTarget = {
    provider: input.provider,
    environment: input.environment,
    supabaseUrl: input.supabaseUrl,
    serviceRoleKey: finalKey,
    savedAt: new Date().toISOString(),
    savedBy: input.savedBy,
    lastValidation: urlChanged ? null : state.stagedTarget?.lastValidation ?? null,
    lastSchemaComparisonAt: urlChanged ? null : state.stagedTarget?.lastSchemaComparisonAt ?? null,
    lastSchemaCompatibilityStatus: urlChanged
      ? null
      : state.stagedTarget?.lastSchemaCompatibilityStatus ?? null,
    lastPreflightOk: urlChanged ? null : state.stagedTarget?.lastPreflightOk ?? null,
  };
  persistStateToDisk(state);
  return getPublicStagedTargetSummary();
}

export function updateStagedTargetValidation(validation: TargetValidationSummary): void {
  const state = loadStateFromDisk();
  if (!state.stagedTarget) return;
  state.stagedTarget.lastValidation = validation;
  persistStateToDisk(state);
}

export function updateStagedTargetSchemaResult(status: string, checkedAt: string): void {
  const state = loadStateFromDisk();
  if (!state.stagedTarget) return;
  state.stagedTarget.lastSchemaCompatibilityStatus = status;
  state.stagedTarget.lastSchemaComparisonAt = checkedAt;
  persistStateToDisk(state);
}

export function updateStagedTargetPreflight(ok: boolean): void {
  const state = loadStateFromDisk();
  if (!state.stagedTarget) return;
  state.stagedTarget.lastPreflightOk = ok;
  persistStateToDisk(state);
}

export function getPublicStagedTargetSummary(): StagedTargetSummary {
  const staged = loadStateFromDisk().stagedTarget;
  if (!staged || !staged.supabaseUrl) {
    return {
      configured: false,
      provider: 'supabase',
      environment: 'Staging',
      maskedUrl: null,
      projectFingerprint: null,
      hasServiceRoleKey: false,
      keyFingerprint: null,
      savedAt: null,
      savedBy: null,
      lastValidation: null,
      lastSchemaComparisonAt: null,
      lastSchemaCompatibilityStatus: null,
      lastPreflightOk: null,
    };
  }
  return {
    configured: Boolean(staged.supabaseUrl && staged.serviceRoleKey),
    provider: staged.provider,
    environment: staged.environment,
    maskedUrl: maskDatabaseUrl(staged.supabaseUrl),
    projectFingerprint: computeProjectFingerprint(staged.supabaseUrl),
    hasServiceRoleKey: Boolean(staged.serviceRoleKey),
    keyFingerprint: computeSecretFingerprint(staged.serviceRoleKey),
    savedAt: staged.savedAt,
    savedBy: staged.savedBy,
    lastValidation: staged.lastValidation,
    lastSchemaComparisonAt: staged.lastSchemaComparisonAt,
    lastSchemaCompatibilityStatus: staged.lastSchemaCompatibilityStatus,
    lastPreflightOk: staged.lastPreflightOk,
  };
}

export function savePreviousRollbackSnapshot(snapshot: PersistedPreviousRollbackSnapshot): void {
  const state = loadStateFromDisk();
  state.previousSnapshot = { ...snapshot };
  persistStateToDisk(state);
}

export function getPreviousRollbackSnapshotInternal(): PersistedPreviousRollbackSnapshot | null {
  return loadStateFromDisk().previousSnapshot;
}

export function clearPreviousRollbackSnapshot(): void {
  const state = loadStateFromDisk();
  state.previousSnapshot = null;
  persistStateToDisk(state);
}

export function getPublicPreviousRollbackSummary(): PreviousRollbackSnapshotSummary | null {
  const snap = loadStateFromDisk().previousSnapshot;
  if (!snap || !snap.supabaseUrl) return null;
  return {
    available: Boolean(snap.supabaseUrl && snap.serviceRoleKey),
    provider: snap.provider,
    environment: snap.environment,
    maskedUrl: maskDatabaseUrl(snap.supabaseUrl),
    projectFingerprint: computeProjectFingerprint(snap.supabaseUrl),
    configVersion: snap.configVersion,
    capturedAt: snap.capturedAt,
    cutoverMigrationId: snap.cutoverMigrationId,
    cutoverAt: snap.cutoverAt,
    sourceRowCounts: snap.sourceRowCounts || {},
  };
}

export function upsertMigrationRun(run: MigrationRunRecord, persistNow = true): void {
  const state = loadStateFromDisk();
  const sanitizedLogs = run.logs.slice(-MAX_LOGS_PER_RUN).map((entry) => ({
    ...entry,
    message: redactSensitiveText(entry.message),
  }));
  const cleanRun: MigrationRunRecord = {
    ...run,
    logs: sanitizedLogs,
    errorSummary: run.errorSummary ? redactSensitiveText(run.errorSummary) : null,
  };
  const idx = state.migrationHistory.findIndex((r) => r.id === cleanRun.id);
  if (idx >= 0) {
    state.migrationHistory[idx] = cleanRun;
  } else {
    state.migrationHistory.unshift(cleanRun);
    if (state.migrationHistory.length > MAX_MIGRATION_HISTORY) {
      state.migrationHistory.length = MAX_MIGRATION_HISTORY;
    }
  }
  if (persistNow) {
    persistStateToDisk(state);
  }
}

export function getMigrationHistory(limit = 20): MigrationRunRecord[] {
  const list = loadStateFromDisk().migrationHistory;
  return list.slice(0, Math.max(1, Math.min(limit, MAX_MIGRATION_HISTORY)));
}

export function getMigrationRunById(id: string): MigrationRunRecord | null {
  const list = loadStateFromDisk().migrationHistory;
  return list.find((r) => r.id === id) || null;
}

export function acquireDbOperationLock(
  operation: 'migration' | 'cutover' | 'rollback',
  migrationId: string | null,
  actorName: string
): { acquired: boolean; lock: MigrationOperationLock } {
  if (activeOperationLock.locked) {
    return { acquired: false, lock: { ...activeOperationLock } };
  }
  activeOperationLock = {
    locked: true,
    operation,
    migrationId,
    startedAt: new Date().toISOString(),
    actorName,
  };
  return { acquired: true, lock: { ...activeOperationLock } };
}

export function releaseDbOperationLock(): void {
  activeOperationLock = {
    locked: false,
    operation: null,
    migrationId: null,
    startedAt: null,
    actorName: null,
  };
}

export function getDbOperationLock(): MigrationOperationLock {
  return { ...activeOperationLock };
}
