import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  ClipboardCheck,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  FileCode2,
  GitCompare,
  History,
  KeyRound,
  Layers,
  Lock,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Square,
  XCircle,
} from 'lucide-react';
import { apiRequest, getCsrfHeaders } from '../../lib/apiClient.ts';
import { useERP } from '../../context/ERPContext.tsx';

type DbTab =
  | 'target-config'
  | 'schema-compatibility'
  | 'migration-runner'
  | 'cutover-rollback'
  | 'history-logs';

type CompatibilityStatus =
  | 'Compatible'
  | 'Missing'
  | 'Different'
  | 'Extra'
  | 'Requires Attention';

interface PublicSafeDatabaseSummary {
  configured: boolean;
  provider: 'supabase';
  environment: 'Production' | 'Staging' | 'Development';
  hasUrl: boolean;
  hasServiceRoleKey: boolean;
  authMode: 'service_role' | 'anon_env' | 'unconfigured';
  configVersion: number;
  configSource: 'env_baseline' | 'switched_control_plane';
  connectionStatus: 'connected' | 'degraded' | 'unconfigured' | 'switched' | 'error';
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

interface TargetValidationSummary {
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

interface StagedTargetSummary {
  configured: boolean;
  provider: 'supabase';
  environment: 'Production' | 'Staging' | 'Development';
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

interface PreviousRollbackSnapshotSummary {
  available: boolean;
  provider: 'supabase';
  environment: 'Production' | 'Staging' | 'Development';
  maskedUrl: string | null;
  projectFingerprint: string | null;
  configVersion: number;
  capturedAt: string;
  cutoverMigrationId: string | null;
  cutoverAt: string;
}

interface SchemaDiffItem {
  category: string;
  objectName: string;
  tableName?: string;
  status: CompatibilityStatus;
  expectedOrSource: string;
  targetActual: string;
  details: string;
}

interface TableComparisonRow {
  table: string;
  domain: string;
  critical: boolean;
  sourceExists: boolean;
  targetExists: boolean;
  sourceRowCount: number | null;
  targetRowCount: number | null;
  status: CompatibilityStatus;
  columnDiffCount: number;
  missingColumns: string[];
  extraColumns: string[];
  typeOrNullableDiffs: string[];
  pkMatch: CompatibilityStatus;
  fkMatch: CompatibilityStatus;
  rlsStatus: CompatibilityStatus;
  sequenceStatus: CompatibilityStatus;
  notes: string[];
}

interface SchemaComparisonReport {
  checkedAt: string;
  sourceFingerprint: string | null;
  sourceMaskedUrl: string | null;
  targetFingerprint: string | null;
  targetMaskedUrl: string | null;
  overallStatus: CompatibilityStatus;
  migrationEligible: boolean;
  summary: {
    compatible: number;
    missing: number;
    different: number;
    extra: number;
    requiresAttention: number;
    totalTablesExpected: number;
    targetTablesPresent: number;
    extraTablesOnTarget: string[];
    postgresInspectorOnSource: boolean;
    postgresInspectorOnTarget: boolean;
  };
  categorySummary: Record<
    string,
    { compatible: number; missing: number; different: number; extra: number; requiresAttention: number }
  >;
  tableComparisons: TableComparisonRow[];
  diffItems: SchemaDiffItem[];
  recommendedActions: string[];
  markdownReport: string;
}

interface PreflightChecklistResult {
  ok: boolean;
  canStartMigration: boolean;
  checkedAt: string;
  targetExistingDataDetected: boolean;
  targetNonEmptyTables: Array<{ table: string; rows: number }>;
  totalSourceRows: number;
  storageBucketsCount: number;
  checks: Array<{
    id: string;
    label: string;
    severity: 'critical' | 'warning' | 'info';
    status: 'passed' | 'failed' | 'warning';
    details: string;
  }>;
  blockers: string[];
  warnings: string[];
}

interface TableMigrationProgress {
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
  sequenceSyncStatus: 'synced' | 'sql_required' | 'not_applicable' | 'failed' | 'pending';
  durationMs: number;
  error?: string;
}

interface MigrationRunRecord {
  id: string;
  status: string;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  cancelledAt: string | null;
  cutoverAt: string | null;
  rolledBackAt: string | null;
  initiatedByName: string;
  sourceEnvironment: string;
  sourceMaskedUrl: string | null;
  targetEnvironment: string;
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
    erpAuthMode: string;
    usersMigrated: number;
    supabaseAuthUsersCount: number | null;
    note: string;
  };
  tableResults: TableMigrationProgress[];
  logs: Array<{ timestamp: string; level: 'info' | 'warning' | 'error'; message: string }>;
  errorSummary: string | null;
  rollbackReason?: string | null;
}

interface DbAuditEvent {
  id: string;
  timestamp: string;
  eventType: string;
  actorName: string;
  actorRole: string;
  projectFingerprint: string | null;
  outcome: 'success' | 'warning' | 'error';
  details: string;
}

function downloadTextFile(filename: string, content: string, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function formatDateTime(iso?: string | null): string {
  if (!iso) return 'Never';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function StatusTag({ status }: { status: string }) {
  const s = String(status || '').toLowerCase();
  const cls =
    s === 'compatible' || s === 'completed' || s === 'active' || s === 'connected' || s === 'passed'
      ? 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-300 dark:border-emerald-800/70'
      : s === 'missing' || s === 'failed' || s === 'error'
        ? 'bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/50 dark:text-rose-300 dark:border-rose-800/70'
        : s === 'running' || s === 'validating' || s === 'switched' || s === 'cutover pending'
          ? 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-800/70'
          : 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:border-amber-800/70';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-semibold ${cls}`}>
      {status}
    </span>
  );
}

export const DatabaseManagementPage: React.FC = () => {
  const { currentUser } = useERP();
  const [activeTab, setActiveTab] = useState<DbTab>('target-config');

  // Overview state
  const [loadingOverview, setLoadingOverview] = useState(true);
  const [activeDb, setActiveDb] = useState<PublicSafeDatabaseSummary | null>(null);
  const [stagedTarget, setStagedTarget] = useState<StagedTargetSummary | null>(null);
  const [previousSnapshot, setPreviousSnapshot] = useState<PreviousRollbackSnapshotSummary | null>(null);
  const [operationLock, setOperationLock] = useState<{ locked: boolean; operation: string | null }>({
    locked: false,
    operation: null,
  });
  const [expectedTablesCount, setExpectedTablesCount] = useState<number>(114);
  const [verifiedActiveTables, setVerifiedActiveTables] = useState<number | null>(null);
  const [migrationHistory, setMigrationHistory] = useState<MigrationRunRecord[]>([]);
  const [auditEvents, setAuditEvents] = useState<DbAuditEvent[]>([]);

  // Feedback banner
  const [banner, setBanner] = useState<{ type: 'success' | 'error' | 'warning'; text: string } | null>(null);

  // Health & Schema verify busy flags
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [verifyingActiveSchema, setVerifyingActiveSchema] = useState(false);

  // Target Form
  const [targetProvider] = useState<'supabase'>('supabase');
  const [targetEnv, setTargetEnv] = useState<'Production' | 'Staging' | 'Development'>('Staging');
  const [targetUrlInput, setTargetUrlInput] = useState('');
  const [targetKeyInput, setTargetKeyInput] = useState('');
  const [showKeyInput, setShowKeyInput] = useState(false);
  const [savingTarget, setSavingTarget] = useState(false);
  const [testingTarget, setTestingTarget] = useState(false);
  const [lastTestResult, setLastTestResult] = useState<TargetValidationSummary | null>(null);

  // Schema Compatibility
  const [comparingSchema, setComparingSchema] = useState(false);
  const [schemaReport, setSchemaReport] = useState<SchemaComparisonReport | null>(null);
  const [schemaFilterStatus, setSchemaFilterStatus] = useState<string>('ALL');
  const [schemaSearch, setSchemaSearch] = useState('');

  // Pre-migration & Migration Runner
  const [runningPreflight, setRunningPreflight] = useState(false);
  const [preflightResult, setPreflightResult] = useState<PreflightChecklistResult | null>(null);
  const [confirmBackup, setConfirmBackup] = useState(false);
  const [confirmOverwrite, setConfirmOverwrite] = useState(false);
  const [batchSize, setBatchSize] = useState<number>(200);
  const [startingMigration, setStartingMigration] = useState(false);
  const [selectedRun, setSelectedRun] = useState<MigrationRunRecord | null>(null);
  const [tableFilter, setTableFilter] = useState<'ALL' | 'FAILED' | 'NON_EMPTY' | 'SEQUENCE_SQL'>('ALL');

  // Cutover & Rollback state
  const [cutoverConfirmPhrase, setCutoverConfirmPhrase] = useState('');
  const [cutoverConfirmChecklist, setCutoverConfirmChecklist] = useState(false);
  const [executingCutover, setExecutingCutover] = useState(false);

  const [rollbackReason, setRollbackReason] = useState('');
  const [rollbackConfirmPhrase, setRollbackConfirmPhrase] = useState('');
  const [rollbackAckDivergence, setRollbackAckDivergence] = useState(false);
  const [rollbackDivergenceInfo, setRollbackDivergenceInfo] = useState<
    Array<{ table: string; snapshotRows: number; currentRows: number }>
  >([]);
  const [executingRollback, setExecutingRollback] = useState(false);

  const loadOverview = useCallback(async (silent = false) => {
    if (!silent) setLoadingOverview(true);
    try {
      const res = await apiRequest('/api/admin/db/overview');
      setActiveDb(res.active || null);
      setStagedTarget(res.stagedTarget || null);
      setPreviousSnapshot(res.previousSnapshot || null);
      setOperationLock(res.lock || { locked: false, operation: null });
      setExpectedTablesCount(res.expectedTablesCount || 114);
      const history: MigrationRunRecord[] = Array.isArray(res.migrationHistory) ? res.migrationHistory : [];
      setMigrationHistory(history);
      setAuditEvents(Array.isArray(res.auditEvents) ? res.auditEvents : []);
      if (res.stagedTarget?.lastValidation) {
        setLastTestResult(res.stagedTarget.lastValidation);
      }
      if (res.stagedTarget?.environment) {
        setTargetEnv(res.stagedTarget.environment);
      }
      if (history.length > 0 && !selectedRun) {
        setSelectedRun(history[0]);
      }
    } catch (err: any) {
      if (!silent) {
        setBanner({ type: 'error', text: err?.message || 'Unable to load database control plane.' });
      }
    } finally {
      if (!silent) setLoadingOverview(false);
    }
  }, [selectedRun]);

  useEffect(() => {
    if (currentUser?.role === 'Super Admin') {
      loadOverview();
    }
  }, [currentUser?.role, loadOverview]);

  // Poll active migration run automatically while Running / Validating
  useEffect(() => {
    if (!selectedRun || (selectedRun.status !== 'Running' && selectedRun.status !== 'Validating')) {
      return;
    }
    const timer = setInterval(async () => {
      try {
        const res = await apiRequest(`/api/admin/db/migration/${encodeURIComponent(selectedRun.id)}`);
        if (res?.run) {
          setSelectedRun(res.run);
          setOperationLock(res.lock || { locked: false, operation: null });
          if (res.run.status !== 'Running' && res.run.status !== 'Validating') {
            loadOverview(true);
          }
        }
      } catch {
        // Ignore transient poll errors
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [selectedRun, loadOverview]);

  const handleCheckActiveHealth = async () => {
    setCheckingHealth(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/status');
      setActiveDb(res.summary || activeDb);
      setBanner({
        type: res.ok ? 'success' : 'warning',
        text: res.message || 'Active database health checked.',
      });
      loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Active health check failed.' });
    } finally {
      setCheckingHealth(false);
    }
  };

  const handleVerifyActiveSchema = async () => {
    setVerifyingActiveSchema(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/verify-schema', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setVerifiedActiveTables(res.verifiedTablesCount ?? null);
      setBanner({
        type: res.ok ? 'success' : 'warning',
        text: res.ok
          ? `Active database schema verified: ${res.verifiedTablesCount}/${res.totalExpectedTables} ERP tables ready.`
          : `Active schema check found ${res.missingOrInaccessibleCount} missing/inaccessible tables.`,
      });
      loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Active schema verification failed.' });
    } finally {
      setVerifyingActiveSchema(false);
    }
  };

  const handleSaveTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingTarget(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/config/target', {
        method: 'POST',
        body: JSON.stringify({
          provider: targetProvider,
          environment: targetEnv,
          supabaseUrl: targetUrlInput.trim(),
          serviceRoleKey: targetKeyInput.trim() || undefined,
        }),
      });
      setStagedTarget(res.stagedTarget);
      setTargetKeyInput('');
      setShowKeyInput(false);
      setBanner({
        type: 'success',
        text: res.message || 'Target database configuration saved securely server-side (not yet active).',
      });
      loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Failed to save target configuration.' });
    } finally {
      setSavingTarget(false);
    }
  };

  const handleTestTargetConnection = async () => {
    setTestingTarget(true);
    setBanner(null);
    try {
      const payload =
        targetUrlInput.trim() && targetKeyInput.trim()
          ? {
              useSavedTarget: false,
              supabaseUrl: targetUrlInput.trim(),
              serviceRoleKey: targetKeyInput.trim(),
            }
          : { useSavedTarget: true };
      const res = await apiRequest('/api/admin/db/config/test', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setLastTestResult(res.validation || null);
      if (res.stagedTarget) setStagedTarget(res.stagedTarget);
      setBanner({
        type: res.ok ? 'success' : 'warning',
        text: res.ok
          ? `Target connection verified (${res.validation.verifiedTablesCount}/${res.validation.totalExpectedTables} tables, ${res.validation.latencyMs}ms).`
          : res.validation?.error || 'Target connection validation detected issues.',
      });
      loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Connection test failed.' });
    } finally {
      setTestingTarget(false);
    }
  };

  const handleCompareSchema = async () => {
    setComparingSchema(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/schema/compare', {
        method: 'POST',
        body: JSON.stringify({ useSavedTarget: true }),
      });
      setSchemaReport(res.report || null);
      if (res.stagedTarget) setStagedTarget(res.stagedTarget);
      setActiveTab('schema-compatibility');
      setBanner({
        type: res.report?.migrationEligible ? 'success' : 'warning',
        text: res.report
          ? `Schema comparison finished: ${res.report.overallStatus} (Migration eligible: ${res.report.migrationEligible ? 'Yes' : 'No'}).`
          : 'Schema comparison completed.',
      });
      loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Schema compatibility check failed.' });
    } finally {
      setComparingSchema(false);
    }
  };

  const handleRunPreflight = async (nextBackup = confirmBackup, nextOverwrite = confirmOverwrite) => {
    setRunningPreflight(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/migration/preflight', {
        method: 'POST',
        body: JSON.stringify({
          confirmSourceBackupTaken: nextBackup,
          confirmTargetExistingData: nextOverwrite,
        }),
      });
      setPreflightResult(res.preflight || null);
      setBanner({
        type: res.preflight?.ok ? 'success' : 'warning',
        text: res.preflight?.ok
          ? `Pre-migration checks passed (${res.preflight.totalSourceRows.toLocaleString()} source rows ready).`
          : res.preflight?.blockers?.[0] || 'Pre-migration validation found issues.',
      });
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Failed to run pre-migration checklist.' });
    } finally {
      setRunningPreflight(false);
    }
  };

  const handleStartMigration = async () => {
    setStartingMigration(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/migration/start', {
        method: 'POST',
        body: JSON.stringify({
          confirmSourceBackupTaken: confirmBackup,
          confirmTargetExistingData: confirmOverwrite,
          batchSize,
        }),
      });
      if (res.run) {
        setSelectedRun(res.run);
        setActiveTab('migration-runner');
      }
      if (res.preflight) setPreflightResult(res.preflight);
      setBanner({
        type: 'success',
        text: `Full 114-table migration ${res.run?.id} started cleanly.`,
      });
      loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Migration start blocked.' });
    } finally {
      setStartingMigration(false);
    }
  };

  const handleCancelMigration = async (id: string) => {
    try {
      const res = await apiRequest(`/api/admin/db/migration/${encodeURIComponent(id)}/cancel`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      setBanner({ type: 'warning', text: res.message || 'Cancellation signal sent.' });
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Unable to cancel migration.' });
    }
  };

  const handleRetryMigration = async (id: string) => {
    try {
      const res = await apiRequest(`/api/admin/db/migration/${encodeURIComponent(id)}/retry`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      if (res.run) setSelectedRun(res.run);
      setBanner({ type: 'success', text: `Resumed migration ${id} cleanly.` });
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Unable to resume migration.' });
    }
  };

  const handleDownloadRunReport = async (id: string, format: 'json' | 'md') => {
    try {
      const res = await apiRequest(`/api/admin/db/migration/${encodeURIComponent(id)}/report`);
      if (format === 'json') {
        downloadTextFile(
          `ensec-migration-${id}.json`,
          JSON.stringify(res.report.json, null, 2),
          'application/json'
        );
      } else {
        downloadTextFile(`ensec-migration-${id}.md`, res.report.markdown, 'text/markdown');
      }
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Failed to download report.' });
    }
  };

  const handleDownloadSqlScript = async (kind: 'helper-rpcs' | 'schema' | 'rls') => {
    try {
      const res = await apiRequest(`/api/admin/db/sql-scripts/${kind}`);
      downloadTextFile(res.filename, res.content, 'text/sql');
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Unable to download SQL script.' });
    }
  };

  const completedRunForTarget = useMemo(() => {
    if (!stagedTarget?.projectFingerprint) return null;
    return (
      migrationHistory.find(
        (r) =>
          (r.status === 'Completed' || r.status === 'Cutover Pending') &&
          r.targetFingerprint === stagedTarget.projectFingerprint &&
          r.countVerificationPassed === true &&
          r.failedTables === 0
      ) || null
    );
  }, [migrationHistory, stagedTarget]);

  const handleExecuteCutover = async (e: React.FormEvent) => {
    e.preventDefault();
    setExecutingCutover(true);
    setBanner(null);
    try {
      const res = await apiRequest('/api/admin/db/cutover', {
        method: 'POST',
        body: JSON.stringify({
          migrationId: completedRunForTarget?.id,
          confirmationPhrase: cutoverConfirmPhrase,
          confirmChecklist: cutoverConfirmChecklist,
        }),
      });
      setCutoverConfirmPhrase('');
      setCutoverConfirmChecklist(false);
      setBanner({
        type: 'success',
        text: res.message || 'Active database switched successfully.',
      });
      await loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Cutover failed; active DB unchanged.' });
    } finally {
      setExecutingCutover(false);
    }
  };

  const handleExecuteRollback = async (e: React.FormEvent) => {
    e.preventDefault();
    setExecutingRollback(true);
    setBanner(null);
    setRollbackDivergenceInfo([]);
    try {
      const response = await fetch('/api/admin/db/rollback', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...getCsrfHeaders('POST'),
        },
        body: JSON.stringify({
          reason: rollbackReason,
          confirmationPhrase: rollbackConfirmPhrase,
          acknowledgeDataDivergence: rollbackAckDivergence,
        }),
      });
      const res = await response.json().catch(() => ({}));
      if (!response.ok || !res?.ok) {
        if (Array.isArray(res?.divergentTables) && res.divergentTables.length > 0) {
          setRollbackDivergenceInfo(res.divergentTables);
        }
        setBanner({
          type: res?.code === 'DATA_DIVERGENCE_DETECTED' ? 'warning' : 'error',
          text: res?.message || res?.error || 'Rollback rejected or failed.',
        });
        return;
      }
      setRollbackReason('');
      setRollbackConfirmPhrase('');
      setRollbackAckDivergence(false);
      setBanner({
        type: 'success',
        text: res.message || 'Database rolled back to previous snapshot successfully.',
      });
      await loadOverview(true);
    } catch (err: any) {
      setBanner({ type: 'error', text: err?.message || 'Rollback rejected or failed.' });
    } finally {
      setExecutingRollback(false);
    }
  };

  const filteredSchemaDiffs = useMemo(() => {
    if (!schemaReport) return [];
    return schemaReport.diffItems.filter((item) => {
      if (schemaFilterStatus !== 'ALL' && item.status !== schemaFilterStatus) return false;
      if (schemaSearch.trim()) {
        const q = schemaSearch.toLowerCase();
        return (
          item.objectName.toLowerCase().includes(q) ||
          item.category.toLowerCase().includes(q) ||
          item.details.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [schemaReport, schemaFilterStatus, schemaSearch]);

  const filteredMigrationTables = useMemo(() => {
    if (!selectedRun) return [];
    return selectedRun.tableResults.filter((t) => {
      if (tableFilter === 'FAILED') return t.status === 'Failed';
      if (tableFilter === 'NON_EMPTY') return t.sourceRows > 0 || t.migratedRows > 0;
      if (tableFilter === 'SEQUENCE_SQL') return t.sequenceSyncStatus === 'sql_required';
      return true;
    });
  }, [selectedRun, tableFilter]);

  if (currentUser?.role !== 'Super Admin') {
    return (
      <div className="max-w-lg mx-auto mt-12 p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center space-y-3">
        <ShieldAlert className="w-8 h-8 text-rose-600 mx-auto" />
        <h2 className="text-sm font-bold text-slate-900 dark:text-white">
          Super Admin Clearance Required
        </h2>
        <p className="text-xs text-slate-600 dark:text-slate-400">
          Database Migration &amp; Centralized Switching is strictly restricted to Super Admin accounts.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-5 pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-5">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shrink-0">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-base sm:text-lg font-bold text-slate-900 dark:text-white tracking-tight">
                Database Management &amp; Migration Control Plane
              </h1>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                v{activeDb?.configVersion ?? 1} · {activeDb?.environment ?? 'Unconfigured'}
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Centralized server-side database configuration, 114-table schema compatibility, dependency-ordered migration, cutover &amp; rollback.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleCheckActiveHealth}
            disabled={checkingHealth}
            className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${checkingHealth ? 'animate-spin' : ''}`} />
            <span>Check Health</span>
          </button>
          <button
            type="button"
            onClick={handleVerifyActiveSchema}
            disabled={verifyingActiveSchema}
            className="px-3 py-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 hover:bg-slate-800 dark:hover:bg-white text-white dark:text-slate-900 text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{verifyingActiveSchema ? 'Verifying 114 Tables...' : 'Verify 114 Tables'}</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {banner && (
        <div
          className={`p-3.5 rounded-xl border text-xs flex items-start justify-between gap-3 ${
            banner.type === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200'
              : banner.type === 'warning'
                ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200'
                : 'bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200'
          }`}
        >
          <div className="flex items-start gap-2">
            {banner.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
            ) : banner.type === 'warning' ? (
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
            )}
            <span className="font-medium leading-relaxed">{banner.text}</span>
          </div>
          <button
            type="button"
            onClick={() => setBanner(null)}
            className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Active Operation Lock Notice */}
      {operationLock.locked && (
        <div className="p-3 rounded-xl border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-950/40 text-xs text-blue-800 dark:text-blue-200 flex items-center gap-2">
          <Lock className="w-4 h-4 shrink-0" />
          <span>
            Control plane lock active: <b>{operationLock.operation}</b> operation is currently running. Concurrent migrations or switches are prevented.
          </span>
        </div>
      )}

      {/* Section A: Active Database Overview */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3.5">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-medium">Active Database</span>
            <Server className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-bold text-slate-900 dark:text-white uppercase">
              {activeDb?.provider || 'Supabase'} · {activeDb?.environment || 'Production'}
            </span>
            <StatusTag status={activeDb?.connectionStatus || 'unconfigured'} />
          </div>
          <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">
            {activeDb?.maskedUrl || 'No active Supabase URL'}
          </div>
          <div className="text-[11px] text-slate-400 font-mono tabular-nums">
            Fingerprint: {activeDb?.projectFingerprint || 'none'} · Config v{activeDb?.configVersion ?? 1}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-medium">Schema &amp; Table Readiness</span>
            <Layers className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-900 dark:text-white">
            {verifiedActiveTables !== null ? verifiedActiveTables : '—'} / {expectedTablesCount}
          </div>
          <div className="text-[11px] text-slate-600 dark:text-slate-300">
            {activeDb?.schemaCompatibilityStatus || 'Click "Verify 114 Tables" to inspect active schema'}
          </div>
          <div className="text-[11px] text-slate-400">
            Auth: {activeDb?.authMode === 'service_role' ? 'service_role (RLS bypass server-side)' : activeDb?.authMode || 'unconfigured'}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-medium">Telemetry &amp; Migration Stamp</span>
            <History className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-xs text-slate-700 dark:text-slate-200 space-y-1">
            <div>
              <span className="text-slate-400">Last Check:</span>{' '}
              <span className="font-mono tabular-nums">
                {formatDateTime(activeDb?.lastHealthCheckAt)}
                {activeDb?.lastHealthLatencyMs !== null && activeDb?.lastHealthLatencyMs !== undefined
                  ? ` (${activeDb.lastHealthLatencyMs}ms)`
                  : ''}
              </span>
            </div>
            <div>
              <span className="text-slate-400">Last Migration:</span>{' '}
              <span className="font-mono tabular-nums">{formatDateTime(activeDb?.lastMigrationAt)}</span>
            </div>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            Source: {activeDb?.configSource === 'switched_control_plane' ? 'Switched via Control Plane' : 'Server Env Baseline'}
          </div>
        </div>

        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
            <span className="font-medium">Staged Target &amp; Rollback</span>
            <ArrowRightLeft className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-xs text-slate-800 dark:text-slate-200 font-semibold">
            {stagedTarget?.configured
              ? `${stagedTarget.environment} · ${stagedTarget.maskedUrl}`
              : 'No target staged'}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            {stagedTarget?.lastValidation
              ? `Validated: ${stagedTarget.lastValidation.verifiedTablesCount}/${stagedTarget.lastValidation.totalExpectedTables} tables`
              : 'Target validation pending'}
          </div>
          <div className="text-[11px] text-slate-400">
            Rollback Snapshot:{' '}
            {previousSnapshot?.available
              ? `v${previousSnapshot.configVersion} (${previousSnapshot.environment})`
              : 'None captured'}
          </div>
        </div>
      </div>

      {/* Persistence / Multi-instance Info Strip */}
      {activeDb && (
        <div className="px-4 py-2.5 rounded-xl bg-slate-100/80 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-[11px] text-slate-600 dark:text-slate-400">
          <div>
            <span className="font-semibold text-slate-800 dark:text-slate-200">Security &amp; Persistence:</span>{' '}
            {activeDb.multiInstanceNote}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => handleDownloadSqlScript('helper-rpcs')}
              className="px-2.5 py-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 text-slate-700 dark:text-slate-200 font-medium flex items-center gap-1 cursor-pointer"
            >
              <FileCode2 className="w-3 h-3" />
              <span>Helper RPC SQL</span>
            </button>
            <button
              type="button"
              onClick={() => handleDownloadSqlScript('schema')}
              className="px-2.5 py-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 text-slate-700 dark:text-slate-200 font-medium flex items-center gap-1 cursor-pointer"
            >
              <Download className="w-3 h-3" />
              <span>Schema SQL</span>
            </button>
            <button
              type="button"
              onClick={() => handleDownloadSqlScript('rls')}
              className="px-2.5 py-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 text-slate-700 dark:text-slate-200 font-medium flex items-center gap-1 cursor-pointer"
            >
              <Download className="w-3 h-3" />
              <span>RLS Hardening SQL</span>
            </button>
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-1.5 border-b border-slate-200 dark:border-slate-800 pb-2">
        {(
          [
            { id: 'target-config', label: '1. Target Config & Connection Test', icon: KeyRound },
            { id: 'schema-compatibility', label: '2. Schema Compatibility Validator', icon: GitCompare },
            { id: 'migration-runner', label: '3. Pre-Flight & Full Migration (114)', icon: Play },
            { id: 'cutover-rollback', label: '4. Cutover & Rollback', icon: ArrowRightLeft },
            { id: 'history-logs', label: '5. History & Audit Logs', icon: History },
          ] as const
        ).map((tab) => {
          const Icon = tab.icon;
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                active
                  ? 'bg-blue-600 text-white'
                  : 'bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {loadingOverview ? (
        <div className="p-8 text-center text-xs text-slate-500 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
          Loading centralized database control plane...
        </div>
      ) : (
        <>
          {/* TAB 1: Target Configuration & Connection Validation */}
          {activeTab === 'target-config' && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <form
                onSubmit={handleSaveTarget}
                className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4"
              >
                <div className="border-b border-slate-100 dark:border-slate-800 pb-3">
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                    Target Database Configuration
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Credentials are encrypted server-side (AES-256-GCM) and never returned to the browser. Saving stages the target without switching active traffic.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Database Provider
                    </label>
                    <select
                      value={targetProvider}
                      disabled
                      className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-xs text-slate-700 dark:text-slate-200"
                    >
                      <option value="supabase">Supabase PostgreSQL</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Environment Name
                    </label>
                    <select
                      value={targetEnv}
                      onChange={(e) => setTargetEnv(e.target.value as any)}
                      className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white"
                    >
                      <option value="Production">Production</option>
                      <option value="Staging">Staging</option>
                      <option value="Development">Development</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Target Supabase Project URL
                  </label>
                  <input
                    type="url"
                    required
                    value={targetUrlInput}
                    onChange={(e) => setTargetUrlInput(e.target.value)}
                    placeholder={
                      stagedTarget?.maskedUrl
                        ? `Currently staged: ${stagedTarget.maskedUrl} (re-enter to replace)`
                        : 'https://your-new-project.supabase.co'
                    }
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-mono text-slate-900 dark:text-white"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Target Server-Side Service Role Key
                  </label>
                  <div className="relative flex items-center">
                    <input
                      type={showKeyInput ? 'text' : 'password'}
                      required={!stagedTarget?.hasServiceRoleKey}
                      value={targetKeyInput}
                      onChange={(e) => setTargetKeyInput(e.target.value)}
                      autoComplete="new-password"
                      placeholder={
                        stagedTarget?.hasServiceRoleKey
                          ? `Encrypted key saved (fp: ${stagedTarget.keyFingerprint}) — enter new key only to replace`
                          : 'eyJ... or sb_secret_... (never exposed client-side)'
                      }
                      className="w-full pl-3 pr-10 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-mono text-slate-900 dark:text-white"
                    />
                    <button
                      type="button"
                      onClick={() => setShowKeyInput((v) => !v)}
                      className="absolute right-2.5 text-slate-400 hover:text-slate-600 cursor-pointer"
                      aria-label="Toggle service role key visibility"
                    >
                      {showKeyInput ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                    Anon / publishable keys are automatically rejected. Must be a server-side <code className="font-mono">service_role</code> key.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <button
                    type="submit"
                    disabled={savingTarget || operationLock.locked}
                    className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                  >
                    {savingTarget ? 'Encrypting & Saving...' : 'Save Target Configuration'}
                  </button>
                  <button
                    type="button"
                    onClick={handleTestTargetConnection}
                    disabled={testingTarget || (!stagedTarget?.configured && (!targetUrlInput || !targetKeyInput))}
                    className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-100 text-xs font-semibold cursor-pointer disabled:opacity-50"
                  >
                    {testingTarget ? 'Testing Target Connection...' : 'Test Database Connection'}
                  </button>
                </div>
              </form>

              {/* Section C: Connection Validation Results */}
              <div className="lg:col-span-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                  <div>
                    <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                      Connection Validation Report
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Verifies URL, key validity, reachability, OpenAPI schema, 114 tables &amp; service_role privileges without altering active DB.
                    </p>
                  </div>
                  {lastTestResult && (
                    <StatusTag status={lastTestResult.ok ? 'Compatible' : 'Requires Attention'} />
                  )}
                </div>

                {!lastTestResult ? (
                  <div className="py-10 text-center text-xs text-slate-500 dark:text-slate-400">
                    Save a target database and click <b>Test Database Connection</b> to verify connectivity and privileges.
                  </div>
                ) : (
                  <div className="space-y-3 text-xs">
                    <div className="grid grid-cols-2 gap-2.5">
                      <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="text-[11px] text-slate-500">Reachability &amp; Latency</div>
                        <div className="font-bold font-mono tabular-nums text-slate-900 dark:text-white mt-0.5">
                          {lastTestResult.reachable ? `Reachable (${lastTestResult.latencyMs}ms)` : 'Unreachable'}
                        </div>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="text-[11px] text-slate-500">114-Table Verification</div>
                        <div className="font-bold font-mono tabular-nums text-slate-900 dark:text-white mt-0.5">
                          {lastTestResult.verifiedTablesCount} / {lastTestResult.totalExpectedTables} tables
                        </div>
                      </div>
                    </div>

                    <div className="divide-y divide-slate-100 dark:divide-slate-800 border border-slate-200 dark:border-slate-800 rounded-lg">
                      {[
                        { label: 'PostgREST OpenAPI Schema Accessible', ok: lastTestResult.schemaAccessible },
                        { label: 'Critical ERP Tables Ready', ok: lastTestResult.criticalTablesReady },
                        { label: 'Service Role Read Privilege', ok: lastTestResult.readPrivilegeOk },
                        {
                          label: `Service Role Write Privilege (${lastTestResult.writePrivilegeNote})`,
                          ok: lastTestResult.writePrivilegeOk === true,
                        },
                        {
                          label: 'Postgres Catalog Helper RPC (ensec_phase4_inspect_metadata)',
                          ok: lastTestResult.postgresInspectorRpcAvailable,
                        },
                      ].map((row, idx) => (
                        <div key={idx} className="px-3 py-2 flex items-center justify-between gap-2">
                          <span className="text-slate-700 dark:text-slate-300">{row.label}</span>
                          {row.ok ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                          )}
                        </div>
                      ))}
                    </div>

                    {lastTestResult.missingTables.length > 0 && (
                      <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200">
                        <div className="font-semibold mb-1">
                          Missing Tables ({lastTestResult.missingTablesCount}):
                        </div>
                        <div className="font-mono text-[11px] break-all">
                          {lastTestResult.missingTables.slice(0, 20).join(', ')}
                          {lastTestResult.missingTables.length > 20 ? '...' : ''}
                        </div>
                      </div>
                    )}

                    <div className="flex justify-end pt-1">
                      <button
                        type="button"
                        onClick={handleCompareSchema}
                        disabled={comparingSchema}
                        className="px-3.5 py-1.5 rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 font-semibold text-xs flex items-center gap-1.5 cursor-pointer"
                      >
                        <GitCompare className="w-3.5 h-3.5" />
                        <span>{comparingSchema ? 'Comparing...' : 'Run Full Schema Compatibility Check'}</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: Schema Compatibility Validator */}
          {activeTab === 'schema-compatibility' && (
            <div className="space-y-4">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                    Schema Compatibility &amp; Security Policy Comparator
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Read-only inspection of tables, columns, types, nullability, PKs, FKs, unique constraints, indexes, sequences, views, extensions, RLS &amp; privileges.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCompareSchema}
                    disabled={comparingSchema || !stagedTarget?.configured}
                    className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <GitCompare className="w-3.5 h-3.5" />
                    <span>{comparingSchema ? 'Inspecting Source & Target...' : 'Run Schema Comparison'}</span>
                  </button>
                  {schemaReport && (
                    <>
                      <button
                        type="button"
                        onClick={() =>
                          downloadTextFile(
                            'ensec-schema-compatibility-report.md',
                            schemaReport.markdownReport,
                            'text/markdown'
                          )
                        }
                        className="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-1 cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export .MD</span>
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadTextFile(
                            'ensec-schema-compatibility-report.json',
                            JSON.stringify(schemaReport, null, 2),
                            'application/json'
                          )
                        }
                        className="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-1 cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export .JSON</span>
                      </button>
                    </>
                  )}
                </div>
              </div>

              {!schemaReport ? (
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-10 text-center text-xs text-slate-500">
                  Save a target configuration first, then click <b>Run Schema Comparison</b> to inspect compatibility.
                </div>
              ) : (
                <>
                  {/* Summary metrics */}
                  <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
                      <div className="text-[11px] text-slate-500">Overall Status</div>
                      <div className="mt-1">
                        <StatusTag status={schemaReport.overallStatus} />
                      </div>
                    </div>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
                      <div className="text-[11px] text-slate-500">Tables Present</div>
                      <div className="text-base font-bold font-mono tabular-nums text-slate-900 dark:text-white mt-0.5">
                        {schemaReport.summary.targetTablesPresent} / {schemaReport.summary.totalTablesExpected}
                      </div>
                    </div>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
                      <div className="text-[11px] text-slate-500">Compatible Tables</div>
                      <div className="text-base font-bold font-mono tabular-nums text-emerald-600 mt-0.5">
                        {schemaReport.summary.compatible}
                      </div>
                    </div>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
                      <div className="text-[11px] text-slate-500">Missing Objects</div>
                      <div className="text-base font-bold font-mono tabular-nums text-rose-600 mt-0.5">
                        {schemaReport.summary.missing}
                      </div>
                    </div>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
                      <div className="text-[11px] text-slate-500">Type / Null Diffs</div>
                      <div className="text-base font-bold font-mono tabular-nums text-amber-600 mt-0.5">
                        {schemaReport.summary.different}
                      </div>
                    </div>
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3">
                      <div className="text-[11px] text-slate-500">Requires Attention</div>
                      <div className="text-base font-bold font-mono tabular-nums text-amber-600 mt-0.5">
                        {schemaReport.summary.requiresAttention}
                      </div>
                    </div>
                  </div>

                  {schemaReport.recommendedActions.length > 0 && (
                    <div className="bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800 rounded-xl p-4 space-y-1.5 text-xs text-amber-900 dark:text-amber-200">
                      <div className="font-bold">Recommended Schema / Security Actions:</div>
                      <ul className="list-disc pl-5 space-y-1">
                        {schemaReport.recommendedActions.map((act, i) => (
                          <li key={i}>{act}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Filterable Diff List */}
                  <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                    <div className="p-3.5 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="text-xs font-bold text-slate-900 dark:text-white">
                        Itemized Schema Findings ({filteredSchemaDiffs.length})
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="relative">
                          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2" />
                          <input
                            type="text"
                            value={schemaSearch}
                            onChange={(e) => setSchemaSearch(e.target.value)}
                            placeholder="Filter table or object..."
                            className="pl-8 pr-3 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs"
                          />
                        </div>
                        <select
                          value={schemaFilterStatus}
                          onChange={(e) => setSchemaFilterStatus(e.target.value)}
                          className="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs"
                        >
                          <option value="ALL">All Statuses</option>
                          <option value="Missing">Missing</option>
                          <option value="Different">Different</option>
                          <option value="Requires Attention">Requires Attention</option>
                          <option value="Extra">Extra</option>
                          <option value="Compatible">Compatible</option>
                        </select>
                      </div>
                    </div>

                    <div className="overflow-x-auto max-h-96">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead className="bg-slate-50 dark:bg-slate-800/80 text-slate-500 dark:text-slate-400 sticky top-0">
                          <tr>
                            <th className="py-2 px-3 font-semibold">Category</th>
                            <th className="py-2 px-3 font-semibold">Object</th>
                            <th className="py-2 px-3 font-semibold">Status</th>
                            <th className="py-2 px-3 font-semibold">Expected / Source</th>
                            <th className="py-2 px-3 font-semibold">Target Actual</th>
                            <th className="py-2 px-3 font-semibold">Details</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                          {filteredSchemaDiffs.length === 0 ? (
                            <tr>
                              <td colSpan={6} className="py-6 text-center text-slate-500">
                                No schema findings match the current filter.
                              </td>
                            </tr>
                          ) : (
                            filteredSchemaDiffs.slice(0, 200).map((d, idx) => (
                              <tr key={idx} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40">
                                <td className="py-2 px-3 font-mono text-[11px]">{d.category}</td>
                                <td className="py-2 px-3 font-mono font-semibold text-slate-800 dark:text-slate-200">
                                  {d.objectName}
                                </td>
                                <td className="py-2 px-3">
                                  <StatusTag status={d.status} />
                                </td>
                                <td className="py-2 px-3 text-[11px] text-slate-600 dark:text-slate-300">
                                  {d.expectedOrSource}
                                </td>
                                <td className="py-2 px-3 text-[11px] text-slate-600 dark:text-slate-300">
                                  {d.targetActual}
                                </td>
                                <td className="py-2 px-3 text-[11px] text-slate-500 dark:text-slate-400">
                                  {d.details}
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* TAB 3: Pre-Migration Checklist & Controlled Migration Runner */}
          {activeTab === 'migration-runner' && (
            <div className="space-y-4">
              {/* Pre-migration Checklist Panel */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
                  <div>
                    <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <ClipboardCheck className="w-4 h-4 text-blue-600" />
                      <span>Pre-Migration Validation Checklist</span>
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Validates source/target reachability, 114-table compatibility, privileges, existing target row conflicts, storage &amp; backup confirmation.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRunPreflight()}
                    disabled={runningPreflight || !stagedTarget?.configured}
                    className="px-3.5 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs font-semibold cursor-pointer disabled:opacity-50"
                  >
                    {runningPreflight ? 'Running 11-Point Checks...' : 'Run Pre-Migration Checks'}
                  </button>
                </div>

                {preflightResult && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                      {preflightResult.checks.map((chk) => (
                        <div
                          key={chk.id}
                          className="p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 flex items-start gap-2.5"
                        >
                          {chk.status === 'passed' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                          ) : chk.status === 'warning' ? (
                            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                          ) : (
                            <XCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                          )}
                          <div className="min-w-0">
                            <div className="font-semibold text-slate-800 dark:text-slate-200">
                              {chk.label}
                            </div>
                            <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                              {chk.details}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>

                    {preflightResult.targetExistingDataDetected && (
                      <div className="p-3.5 rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-xs text-amber-900 dark:text-amber-200 space-y-2">
                        <div className="font-bold flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4" />
                          <span>
                            Target Database Already Contains Existing Data ({preflightResult.targetNonEmptyTables.length} non-empty tables)
                          </span>
                        </div>
                        <div className="font-mono text-[11px]">
                          {preflightResult.targetNonEmptyTables
                            .slice(0, 12)
                            .map((t) => `${t.table}=${t.rows}`)
                            .join(' · ')}
                        </div>
                        <label className="flex items-center gap-2 font-semibold cursor-pointer">
                          <input
                            type="checkbox"
                            checked={confirmOverwrite}
                            onChange={(e) => {
                              setConfirmOverwrite(e.target.checked);
                              handleRunPreflight(confirmBackup, e.target.checked);
                            }}
                          />
                          <span>
                            I confirm existing target records with matching primary keys may be updated idempotently during migration.
                          </span>
                        </label>
                      </div>
                    )}
                  </div>
                )}

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-100 dark:border-slate-800">
                  <div className="space-y-2 text-xs">
                    <label className="flex items-center gap-2 font-semibold text-slate-700 dark:text-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={confirmBackup}
                        onChange={(e) => {
                          setConfirmBackup(e.target.checked);
                        }}
                      />
                      <span>
                        I confirm a full backup snapshot of the current source database has been taken.
                      </span>
                    </label>
                    <div className="flex items-center gap-2 text-[11px] text-slate-500">
                      <span>Upsert Batch Size:</span>
                      <select
                        value={batchSize}
                        onChange={(e) => setBatchSize(Number(e.target.value))}
                        className="px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs"
                      >
                        <option value={100}>100 rows / batch</option>
                        <option value={200}>200 rows / batch (Recommended)</option>
                        <option value={350}>350 rows / batch</option>
                      </select>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleStartMigration}
                    disabled={
                      startingMigration ||
                      operationLock.locked ||
                      !stagedTarget?.configured ||
                      !confirmBackup ||
                      (Boolean(preflightResult?.targetExistingDataDetected) && !confirmOverwrite)
                    }
                    className="px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shrink-0"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>{startingMigration ? 'Starting Migration...' : 'Start Full 114-Table Migration'}</span>
                  </button>
                </div>
              </div>

              {/* Active / Selected Migration Run Monitor */}
              {selectedRun && (
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                          {selectedRun.id}
                        </h3>
                        <StatusTag status={selectedRun.status} />
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        {selectedRun.sourceEnvironment} ({selectedRun.sourceMaskedUrl}) → {selectedRun.targetEnvironment} ({selectedRun.targetMaskedUrl})
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      {(selectedRun.status === 'Running' || selectedRun.status === 'Validating') && (
                        <button
                          type="button"
                          onClick={() => handleCancelMigration(selectedRun.id)}
                          className="px-3 py-1.5 rounded-lg border border-rose-300 text-rose-700 hover:bg-rose-50 text-xs font-semibold flex items-center gap-1 cursor-pointer"
                        >
                          <Square className="w-3 h-3" />
                          <span>Cancel Run</span>
                        </button>
                      )}
                      {(selectedRun.status === 'Failed' || selectedRun.status === 'Cancelled') && (
                        <button
                          type="button"
                          onClick={() => handleRetryMigration(selectedRun.id)}
                          disabled={operationLock.locked}
                          className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold flex items-center gap-1 cursor-pointer disabled:opacity-50"
                        >
                          <RotateCcw className="w-3 h-3" />
                          <span>Retry Incomplete Tables</span>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => handleDownloadRunReport(selectedRun.id, 'md')}
                        className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-xs font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-1 cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        <span>Report (.MD)</span>
                      </button>
                    </div>
                  </div>

                  {/* Progress Bar & Counters */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-700 dark:text-slate-200">
                        {selectedRun.currentTable
                          ? `Copying table: ${selectedRun.currentTable}...`
                          : `Tables: ${selectedRun.completedTables} / ${selectedRun.totalTables} completed (${selectedRun.failedTables} failed)`}
                      </span>
                      <span className="font-mono tabular-nums font-bold text-slate-900 dark:text-white">
                        {selectedRun.progressPercent}%
                      </span>
                    </div>
                    <div className="w-full h-2.5 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${
                          selectedRun.failedTables > 0 ? 'bg-rose-600' : 'bg-blue-600'
                        }`}
                        style={{ width: `${selectedRun.progressPercent}%` }}
                      />
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs pt-1">
                      <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="text-[11px] text-slate-500">Source Rows</div>
                        <div className="font-bold font-mono tabular-nums">{selectedRun.totalSourceRows.toLocaleString()}</div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="text-[11px] text-slate-500">Rows Copied</div>
                        <div className="font-bold font-mono tabular-nums">{selectedRun.totalMigratedRows.toLocaleString()}</div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="text-[11px] text-slate-500">Target Verified</div>
                        <div className="font-bold font-mono tabular-nums">{selectedRun.totalTargetVerifiedRows.toLocaleString()}</div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="text-[11px] text-slate-500">Count Verification</div>
                        <div className="font-bold">
                          {selectedRun.countVerificationPassed === true
                            ? 'Exact Match'
                            : selectedRun.countVerificationPassed === false
                              ? 'Mismatch'
                              : 'Pending'}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Auth & Storage Handling Details */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                      <div className="font-bold text-slate-800 dark:text-slate-200">Auth Migration Handling</div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-1">
                        {selectedRun.authSummary.note} Users migrated: <b className="font-mono">{selectedRun.authSummary.usersMigrated}</b>.
                      </p>
                    </div>
                    <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                      <div className="font-bold text-slate-800 dark:text-slate-200">Storage Buckets Handling</div>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-1">
                        {selectedRun.storageSummary.note}
                      </p>
                    </div>
                  </div>

                  {/* Sequence Sync SQL if Postgres RPC not installed */}
                  {selectedRun.generatedSequenceSql.length > 0 && (
                    <div className="p-3.5 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-xs space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-amber-900 dark:text-amber-200">
                          Sequence Sync SQL Required ({selectedRun.generatedSequenceSql.length} serial sequences)
                        </span>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => navigator.clipboard?.writeText(selectedRun.generatedSequenceSql.join('\n'))}
                            className="px-2.5 py-1 rounded border border-amber-300 bg-white dark:bg-slate-900 text-xs font-semibold flex items-center gap-1 cursor-pointer"
                          >
                            <Copy className="w-3 h-3" />
                            <span>Copy SQL</span>
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              downloadTextFile(
                                `ensec-sync-sequences-${selectedRun.id}.sql`,
                                selectedRun.generatedSequenceSql.join('\n'),
                                'text/sql'
                              )
                            }
                            className="px-2.5 py-1 rounded border border-amber-300 bg-white dark:bg-slate-900 text-xs font-semibold flex items-center gap-1 cursor-pointer"
                          >
                            <Download className="w-3 h-3" />
                            <span>Download SQL</span>
                          </button>
                        </div>
                      </div>
                      <p className="text-[11px] text-amber-800 dark:text-amber-300">
                        Run these statements in the target Supabase SQL Editor (or install <code className="font-mono">sql/phase4_migration_helper_rpcs.sql</code>) so auto-increment <code className="font-mono">SERIAL</code> primary keys advance past migrated IDs cleanly.
                      </p>
                    </div>
                  )}

                  {/* Per-table breakdown */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                        Per-Table Topological Migration Progress ({filteredMigrationTables.length})
                      </div>
                      <select
                        value={tableFilter}
                        onChange={(e) => setTableFilter(e.target.value as any)}
                        className="px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs"
                      >
                        <option value="ALL">All 114 Tables</option>
                        <option value="NON_EMPTY">Non-Empty Tables Only</option>
                        <option value="FAILED">Failed Tables Only</option>
                        <option value="SEQUENCE_SQL">Sequence SQL Required</option>
                      </select>
                    </div>

                    <div className="overflow-x-auto max-h-72 border border-slate-200 dark:border-slate-800 rounded-lg">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead className="bg-slate-50 dark:bg-slate-800/80 text-slate-500 sticky top-0">
                          <tr>
                            <th className="py-2 px-3 font-semibold">#</th>
                            <th className="py-2 px-3 font-semibold">Table</th>
                            <th className="py-2 px-3 font-semibold">Status</th>
                            <th className="py-2 px-3 font-semibold text-right">Source</th>
                            <th className="py-2 px-3 font-semibold text-right">Copied</th>
                            <th className="py-2 px-3 font-semibold text-right">Target Verified</th>
                            <th className="py-2 px-3 font-semibold">Sequence</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                          {filteredMigrationTables.map((t) => (
                            <tr key={t.table} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                              <td className="py-1.5 px-3 font-mono text-[11px] text-slate-400">{t.migrationOrder}</td>
                              <td className="py-1.5 px-3 font-mono font-semibold text-slate-800 dark:text-slate-200">
                                {t.table}
                                {t.error && <div className="text-[11px] font-sans text-rose-600">{t.error}</div>}
                              </td>
                              <td className="py-1.5 px-3">
                                <StatusTag status={t.status} />
                              </td>
                              <td className="py-1.5 px-3 font-mono tabular-nums text-right">{t.sourceRows}</td>
                              <td className="py-1.5 px-3 font-mono tabular-nums text-right">{t.migratedRows}</td>
                              <td className="py-1.5 px-3 font-mono tabular-nums text-right">
                                {t.targetVerifiedRows ?? '—'}
                              </td>
                              <td className="py-1.5 px-3 font-mono text-[11px] text-slate-500">
                                {t.sequenceSyncStatus}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: Controlled Cutover & Rollback */}
          {activeTab === 'cutover-rollback' && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Controlled Cutover */}
              <form
                onSubmit={handleExecuteCutover}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4"
              >
                <div className="border-b border-slate-100 dark:border-slate-800 pb-3">
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <ArrowRightLeft className="w-4 h-4 text-blue-600" />
                    <span>Controlled Database Cutover</span>
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Atomically switches the centralized server database client and clears operational server caches after post-migration verification passes.
                  </p>
                </div>

                {!completedRunForTarget ? (
                  <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-300 space-y-1">
                    <div className="font-semibold text-slate-800 dark:text-slate-100">
                      Cutover Blocked — Verified Migration Required
                    </div>
                    <p>
                      Complete a full 114-table migration with verified row counts for the currently staged target database before switching live ERP traffic.
                    </p>
                  </div>
                ) : (
                  <div className="p-3.5 rounded-lg bg-emerald-50/70 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 text-xs space-y-1">
                    <div className="font-bold text-emerald-800 dark:text-emerald-200">
                      Eligible Migration Ready: <span className="font-mono">{completedRunForTarget.id}</span>
                    </div>
                    <div className="text-emerald-700 dark:text-emerald-300 font-mono tabular-nums">
                      {completedRunForTarget.completedTables}/114 tables · {completedRunForTarget.totalTargetVerifiedRows.toLocaleString()} verified rows → {completedRunForTarget.targetEnvironment} ({completedRunForTarget.targetMaskedUrl})
                    </div>
                  </div>
                )}

                <label className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cutoverConfirmChecklist}
                    onChange={(e) => setCutoverConfirmChecklist(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    I confirm record counts match, sequences are synchronized (or SQL executed), Super Admin credentials exist on target, and I authorize switching all ERP traffic.
                  </span>
                </label>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Type <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded">CUTOVER TO TARGET</code> to confirm
                  </label>
                  <input
                    type="text"
                    value={cutoverConfirmPhrase}
                    onChange={(e) => setCutoverConfirmPhrase(e.target.value)}
                    placeholder="CUTOVER TO TARGET"
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-mono"
                  />
                </div>

                <button
                  type="submit"
                  disabled={
                    executingCutover ||
                    operationLock.locked ||
                    !completedRunForTarget ||
                    !cutoverConfirmChecklist ||
                    cutoverConfirmPhrase.trim() !== 'CUTOVER TO TARGET'
                  }
                  className="w-full py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  {executingCutover ? 'Executing Atomic Cutover...' : 'Execute Atomic Database Cutover'}
                </button>
              </form>

              {/* Controlled Rollback */}
              <form
                onSubmit={handleExecuteRollback}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4"
              >
                <div className="border-b border-slate-100 dark:border-slate-800 pb-3">
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <RotateCcw className="w-4 h-4 text-amber-600" />
                    <span>Controlled Database Rollback</span>
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    Safely reverts active database pointers to the pre-cutover snapshot after verifying health and checking for post-cutover write divergence. Both databases remain intact.
                  </p>
                </div>

                {!previousSnapshot?.available ? (
                  <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 text-xs text-slate-500">
                    No rollback snapshot captured yet. A snapshot is automatically created whenever a controlled cutover executes.
                  </div>
                ) : (
                  <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 text-xs space-y-1">
                    <div className="font-semibold text-slate-900 dark:text-white">
                      Available Rollback Snapshot: {previousSnapshot.environment} (v{previousSnapshot.configVersion})
                    </div>
                    <div className="font-mono text-[11px] text-slate-500">
                      {previousSnapshot.maskedUrl} · Cutover at {formatDateTime(previousSnapshot.cutoverAt)}
                    </div>
                  </div>
                )}

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Rollback Reason (Logged in Audit Trail)
                  </label>
                  <textarea
                    rows={2}
                    value={rollbackReason}
                    onChange={(e) => setRollbackReason(e.target.value)}
                    placeholder="Describe why database traffic is rolling back (min. 8 characters)..."
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs"
                  />
                </div>

                {rollbackDivergenceInfo.length > 0 && (
                  <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-xs text-rose-800 dark:text-rose-200 space-y-1">
                    <div className="font-bold">Post-Cutover Data Divergence Detected</div>
                    <div className="font-mono text-[11px]">
                      {rollbackDivergenceInfo
                        .map((d) => `${d.table}: snapshot=${d.snapshotRows} vs current=${d.currentRows}`)
                        .join(' · ')}
                    </div>
                  </div>
                )}

                <label className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={rollbackAckDivergence}
                    onChange={(e) => setRollbackAckDivergence(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    Acknowledge post-cutover write divergence if any new rows were written after switching (no data will be deleted on either project).
                  </span>
                </label>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Type <code className="font-mono bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded">ROLLBACK TO PREVIOUS</code> to confirm
                  </label>
                  <input
                    type="text"
                    value={rollbackConfirmPhrase}
                    onChange={(e) => setRollbackConfirmPhrase(e.target.value)}
                    placeholder="ROLLBACK TO PREVIOUS"
                    className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-mono"
                  />
                </div>

                <button
                  type="submit"
                  disabled={
                    executingRollback ||
                    operationLock.locked ||
                    !previousSnapshot?.available ||
                    rollbackReason.trim().length < 8 ||
                    rollbackConfirmPhrase.trim() !== 'ROLLBACK TO PREVIOUS'
                  }
                  className="w-full py-2.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  {executingRollback ? 'Verifying & Rolling Back...' : 'Execute Controlled Rollback'}
                </button>
              </form>
            </div>
          )}

          {/* TAB 5: Migration History & Redacted Audit Logs */}
          {activeTab === 'history-logs' && (
            <div className="space-y-5">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                    Migration Run History ({migrationHistory.length})
                  </h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead className="bg-slate-50 dark:bg-slate-800/80 text-slate-500">
                      <tr>
                        <th className="py-2.5 px-3 font-semibold">Run ID</th>
                        <th className="py-2.5 px-3 font-semibold">Status</th>
                        <th className="py-2.5 px-3 font-semibold">Target</th>
                        <th className="py-2.5 px-3 font-semibold text-right">Tables</th>
                        <th className="py-2.5 px-3 font-semibold text-right">Verified Rows</th>
                        <th className="py-2.5 px-3 font-semibold">Initiated By</th>
                        <th className="py-2.5 px-3 font-semibold">Started</th>
                        <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {migrationHistory.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="py-8 text-center text-slate-500">
                            No migration runs recorded yet.
                          </td>
                        </tr>
                      ) : (
                        migrationHistory.map((run) => (
                          <tr key={run.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                            <td className="py-2.5 px-3 font-mono font-semibold text-slate-800 dark:text-slate-200">
                              {run.id}
                            </td>
                            <td className="py-2.5 px-3">
                              <StatusTag status={run.status} />
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px] text-slate-600 dark:text-slate-300">
                              {run.targetEnvironment} · {run.targetMaskedUrl}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-right">
                              {run.completedTables}/{run.totalTables}
                            </td>
                            <td className="py-2.5 px-3 font-mono tabular-nums text-right">
                              {run.totalTargetVerifiedRows.toLocaleString()}
                            </td>
                            <td className="py-2.5 px-3">{run.initiatedByName}</td>
                            <td className="py-2.5 px-3 font-mono text-[11px] text-slate-500">
                              {formatDateTime(run.startedAt)}
                            </td>
                            <td className="py-2.5 px-3 text-right space-x-2">
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedRun(run);
                                  setActiveTab('migration-runner');
                                }}
                                className="text-blue-600 hover:underline font-semibold cursor-pointer"
                              >
                                Inspect
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDownloadRunReport(run.id, 'json')}
                                className="text-slate-600 dark:text-slate-300 hover:underline font-semibold cursor-pointer"
                              >
                                JSON
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Redacted Server Audit Trail */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-slate-200 dark:border-slate-800">
                  <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                    Centralized Database Control Audit Logs ({auditEvents.length})
                  </h2>
                </div>
                <div className="overflow-x-auto max-h-80">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead className="bg-slate-50 dark:bg-slate-800/80 text-slate-500 sticky top-0">
                      <tr>
                        <th className="py-2 px-3 font-semibold">Timestamp</th>
                        <th className="py-2 px-3 font-semibold">Event</th>
                        <th className="py-2 px-3 font-semibold">Actor</th>
                        <th className="py-2 px-3 font-semibold">Outcome</th>
                        <th className="py-2 px-3 font-semibold">Details (Credential-Redacted)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                      {auditEvents.map((ev) => (
                        <tr key={ev.id}>
                          <td className="py-2 px-3 font-mono text-[11px] text-slate-500 whitespace-nowrap">
                            {formatDateTime(ev.timestamp)}
                          </td>
                          <td className="py-2 px-3 font-mono text-[11px] font-semibold">{ev.eventType}</td>
                          <td className="py-2 px-3 whitespace-nowrap">{ev.actorName}</td>
                          <td className="py-2 px-3">
                            <StatusTag status={ev.outcome} />
                          </td>
                          <td className="py-2 px-3 text-slate-600 dark:text-slate-300">{ev.details}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
