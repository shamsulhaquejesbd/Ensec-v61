/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Centralized Server Database Module Exports
 */

export {
  validateCandidateSupabaseUrl,
  maskDatabaseUrl,
  computeProjectFingerprint,
  computeSecretFingerprint,
  inspectSupabaseKeyRoleHint,
  normalizeDatabaseEnvironment,
  redactSensitiveText,
  type DatabaseEnvironment,
  type DatabaseProvider,
  type ServerDbAuthMode,
  type ConnectionHealthStatus,
  type MigrationLifecycleStatus,
} from './configCore.ts';

export {
  getServerDbConfig,
  getPublicSafeDatabaseSummary,
  type ServerDatabaseConfig,
  type PublicSafeDatabaseSummary,
} from './config.ts';

export {
  getServerSupabase,
  requireServerSupabase,
  resetServerSupabaseClient,
  switchActiveDatabaseClient,
  createIsolatedSupabaseClient,
  registerDbSwitchCacheResetHook,
  sanitizeDatabaseError,
  DatabaseNotConfiguredError,
} from './client.ts';

export {
  EXPECTED_ERP_TABLES,
  MIGRATION_TABLE_ORDER,
  TABLE_SPEC_BY_NAME,
  EXPECTED_SCHEMA_EXTENSIONS,
  EXPECTED_SCHEMA_VIEWS,
  EXPECTED_TOTAL_INDEX_COUNT,
  type ExpectedTableSpec,
  type PrimaryKeyIdType,
} from './schemaRegistry.ts';

export {
  checkServerDatabaseStatus,
  verifyDatabaseSchema,
  recordDbAuditEvent,
  getDbAuditEvents,
  type DbAuditEvent,
  type DbAuditEventType,
  type ServerDatabaseStatusResult,
  type SchemaVerificationResult,
  type TableSchemaCheckResult,
} from './health.ts';

export {
  getStagedTargetInternal,
  saveStagedTargetConfig,
  getPublicStagedTargetSummary,
  getPublicPreviousRollbackSummary,
  getMigrationHistory,
  getMigrationRunById,
  getDbOperationLock,
  resetStoreCacheForTest,
  type StagedTargetSummary,
  type TargetValidationSummary,
  type PreviousRollbackSnapshotSummary,
  type MigrationRunRecord,
  type TableMigrationProgress,
  type MigrationOperationLock,
} from './store.ts';

export {
  validateTargetDatabaseConnection,
  compareDatabaseSchemas,
  type CompatibilityStatus,
  type SchemaDiffItem,
  type TableComparisonRow,
  type SchemaComparisonReport,
} from './schemaValidator.ts';

export {
  runPreMigrationChecklist,
  startDatabaseMigration,
  cancelActiveMigration,
  retryFailedMigration,
  executeDatabaseCutover,
  executeDatabaseRollback,
  buildExportableMigrationReport,
  sortSelfReferencingRows,
  type PreflightCheckItem,
  type PreflightChecklistResult,
  type CutoverResult,
  type RollbackResult,
} from './migrator.ts';
