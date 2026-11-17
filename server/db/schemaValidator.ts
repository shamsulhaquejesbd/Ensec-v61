/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Target Connection Validation & Deep Schema Compatibility Validator
 * Uses HTTPS PostgREST OpenAPI introspection + 114-table service_role probes +
 * optional Postgres catalog RPC (sql/phase4_migration_helper_rpcs.sql) for
 * indexes, sequences, views, extensions, RLS status, policies, and constraints.
 * Strictly read-only: NEVER modifies target business data or schema.
 */

import { SupabaseClient } from '@supabase/supabase-js';
import {
  computeProjectFingerprint,
  inspectSupabaseKeyRoleHint,
  maskDatabaseUrl,
  validateCandidateSupabaseUrl,
} from './configCore.ts';
import { getServerDbConfig } from './config.ts';
import {
  createIsolatedSupabaseClient,
  sanitizeDatabaseError,
} from './client.ts';
import { recordDbAuditEvent } from './health.ts';
import {
  EXPECTED_ERP_TABLES,
  EXPECTED_SCHEMA_EXTENSIONS,
  EXPECTED_SCHEMA_VIEWS,
  EXPECTED_TOTAL_INDEX_COUNT,
  type ExpectedTableSpec,
} from './schemaRegistry.ts';
import {
  updateStagedTargetSchemaResult,
  updateStagedTargetValidation,
  type TargetValidationSummary,
} from './store.ts';

export type CompatibilityStatus =
  | 'Compatible'
  | 'Missing'
  | 'Different'
  | 'Extra'
  | 'Requires Attention';

export interface OpenApiColumnMeta {
  name: string;
  type: string;
  format: string;
  nullable: boolean;
  isPrimaryKey: boolean;
  foreignKeyTarget: string | null;
}

export interface OpenApiTableMeta {
  name: string;
  columns: Map<string, OpenApiColumnMeta>;
}

export interface PostgresCatalogSnapshot {
  available: boolean;
  inspectedAt?: string;
  extensions: Array<{ name: string; version?: string }>;
  tablesRls: Map<string, boolean>;
  views: Set<string>;
  indexes: Array<{ table: string; name: string; unique: boolean }>;
  sequences: Array<{ name: string; lastValue: number | null; startValue: number | null }>;
  policies: Array<{
    table: string;
    name: string;
    permissive: string;
    roles: string[];
    cmd: string;
    qual: string | null;
    withCheck: string | null;
  }>;
  constraints: Array<{ table: string; name: string; type: string }>;
  error?: string;
}

export interface SchemaDiffItem {
  category:
    | 'Table'
    | 'Column'
    | 'DataType'
    | 'Nullable'
    | 'PrimaryKey'
    | 'ForeignKey'
    | 'UniqueConstraint'
    | 'Index'
    | 'Sequence'
    | 'View'
    | 'Extension'
    | 'RLS'
    | 'Policy'
    | 'Privilege';
  objectName: string;
  tableName?: string;
  status: CompatibilityStatus;
  expectedOrSource: string;
  targetActual: string;
  details: string;
}

export interface TableComparisonRow {
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

export interface SchemaComparisonReport {
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

export async function fetchPostgrestOpenApiSpec(
  baseUrl: string,
  serviceRoleKey: string
): Promise<{
  ok: boolean;
  tables: Map<string, OpenApiTableMeta>;
  latencyMs: number;
  error?: string;
}> {
  const startedAt = Date.now();
  const cleanUrl = baseUrl.trim().replace(/\/+$/, '');
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    const response = await fetch(`${cleanUrl}/rest/v1/`, {
      method: 'GET',
      headers: {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
        Accept: 'application/openapi+json, application/json',
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    const latencyMs = Date.now() - startedAt;
    if (!response.ok) {
      return {
        ok: false,
        tables: new Map(),
        latencyMs,
        error: `PostgREST OpenAPI endpoint returned HTTP ${response.status}`,
      };
    }

    const spec = (await response.json()) as any;
    const definitions = spec?.definitions || spec?.components?.schemas || {};
    const tables = new Map<string, OpenApiTableMeta>();

    for (const [tableName, def] of Object.entries<any>(definitions)) {
      if (!def || typeof def !== 'object') continue;
      const requiredSet = new Set<string>(Array.isArray(def.required) ? def.required : []);
      const props = def.properties || {};
      const cols = new Map<string, OpenApiColumnMeta>();

      for (const [colName, colDef] of Object.entries<any>(props)) {
        const desc = String(colDef?.description || '');
        const fkMatch = desc.match(/<fk\s+table='([^']+)'\s+col='([^']+)'/i);
        const isPk = /<pk\s*\/?>/i.test(desc);
        cols.set(colName, {
          name: colName,
          type: String(colDef?.type || 'unknown'),
          format: String(colDef?.format || colDef?.type || 'unknown'),
          nullable: !requiredSet.has(colName),
          isPrimaryKey: isPk,
          foreignKeyTarget: fkMatch ? `${fkMatch[1]}.${fkMatch[2]}` : null,
        });
      }

      tables.set(tableName, { name: tableName, columns: cols });
    }

    return { ok: true, tables, latencyMs };
  } catch (err) {
    return {
      ok: false,
      tables: new Map(),
      latencyMs: Date.now() - startedAt,
      error: sanitizeDatabaseError(err),
    };
  }
}

export async function fetchPostgresCatalogSnapshot(
  client: SupabaseClient
): Promise<PostgresCatalogSnapshot> {
  try {
    const { data, error } = await client.rpc('ensec_phase4_inspect_metadata');
    if (error || !data || typeof data !== 'object') {
      return {
        available: false,
        extensions: [],
        tablesRls: new Map(),
        views: new Set(),
        indexes: [],
        sequences: [],
        policies: [],
        constraints: [],
        error: error ? sanitizeDatabaseError(error) : 'Helper RPC not available',
      };
    }

    const payload = data as any;
    const tablesRls = new Map<string, boolean>();
    for (const t of Array.isArray(payload.tables) ? payload.tables : []) {
      if (t?.table) tablesRls.set(String(t.table), Boolean(t.rlsEnabled));
    }
    const views = new Set<string>(
      (Array.isArray(payload.views) ? payload.views : [])
        .map((v: any) => String(v?.name || ''))
        .filter(Boolean)
    );

    return {
      available: true,
      inspectedAt: String(payload.inspectedAt || new Date().toISOString()),
      extensions: Array.isArray(payload.extensions) ? payload.extensions : [],
      tablesRls,
      views,
      indexes: Array.isArray(payload.indexes) ? payload.indexes : [],
      sequences: Array.isArray(payload.sequences) ? payload.sequences : [],
      policies: Array.isArray(payload.policies) ? payload.policies : [],
      constraints: Array.isArray(payload.constraints) ? payload.constraints : [],
    };
  } catch (err) {
    return {
      available: false,
      extensions: [],
      tablesRls: new Map(),
      views: new Set(),
      indexes: [],
      sequences: [],
      policies: [],
      constraints: [],
      error: sanitizeDatabaseError(err),
    };
  }
}

export async function probeTablesExistenceAndCounts(
  client: SupabaseClient,
  specs: readonly ExpectedTableSpec[] = EXPECTED_ERP_TABLES
): Promise<Map<string, { exists: boolean; count: number | null; error?: string }>> {
  const map = new Map<string, { exists: boolean; count: number | null; error?: string }>();
  const BATCH = 15;
  for (let i = 0; i < specs.length; i += BATCH) {
    const slice = specs.slice(i, i + BATCH);
    const settled = await Promise.all(
      slice.map(async (spec) => {
        try {
          const { count, error } = await client
            .from(spec.name)
            .select('id', { count: 'exact' })
            .limit(0);
          if (error) {
            return {
              table: spec.name,
              exists: false,
              count: null,
              error: sanitizeDatabaseError(error),
            };
          }
          return {
            table: spec.name,
            exists: true,
            count: typeof count === 'number' ? count : 0,
          };
        } catch (err) {
          return {
            table: spec.name,
            exists: false,
            count: null,
            error: sanitizeDatabaseError(err),
          };
        }
      })
    );
    for (const item of settled) {
      map.set(item.table, { exists: item.exists, count: item.count, error: item.error });
    }
  }
  return map;
}

/**
 * Verifies non-destructively whether the client has elevated service_role write privileges
 * (without mutating real business rows) by testing RPC privilege or attempting a rollback-safe
 * schema/permission check.
 */
export async function checkTargetWritePrivilegeNonDestructive(
  client: SupabaseClient,
  serviceRoleKey: string
): Promise<{ writePrivilegeOk: boolean | null; note: string }> {
  const hint = inspectSupabaseKeyRoleHint(serviceRoleKey);
  if (hint.looksLikeAnonKey) {
    return {
      writePrivilegeOk: false,
      note: `Rejected: provided key carries role "${hint.jwtRole || 'anon'}", not service_role.`,
    };
  }

  // Test non-existent impossible-value update (zero matching rows) on audit_logs / users
  // With service_role + schema present, PostgREST returns ok (0 rows affected).
  // With restricted anon/read-only role, PostgREST returns HTTP 401/403 permission denied.
  try {
    const { error } = await client
      .from('audit_logs')
      .delete()
      .eq('id', -999999999);
    if (error) {
      const msg = sanitizeDatabaseError(error);
      const permDenied = /permission denied|row-level security|insufficient_privilege|42501/i.test(msg);
      if (permDenied) {
        return {
          writePrivilegeOk: false,
          note: `Write privilege check denied by database: ${msg}`,
        };
      }
      // If table missing, privilege cannot be confirmed
      return {
        writePrivilegeOk: null,
        note: `Write check inconclusive (${msg})`,
      };
    }
    return {
      writePrivilegeOk: true,
      note: 'Verified service_role write privilege via zero-row DML permission check (business data untouched).',
    };
  } catch (err) {
    return {
      writePrivilegeOk: null,
      note: `Write check error: ${sanitizeDatabaseError(err)}`,
    };
  }
}

export async function validateTargetDatabaseConnection(params: {
  supabaseUrl: string;
  serviceRoleKey: string;
  persistToStaged?: boolean;
  actor?: { id: string; name: string; role: string };
}): Promise<TargetValidationSummary> {
  const checkedAt = new Date().toISOString();
  const urlCheck = validateCandidateSupabaseUrl(params.supabaseUrl);
  if (!urlCheck.valid) {
    return {
      ok: false,
      checkedAt,
      latencyMs: null,
      reachable: false,
      schemaAccessible: false,
      totalExpectedTables: EXPECTED_ERP_TABLES.length,
      verifiedTablesCount: 0,
      missingTablesCount: EXPECTED_ERP_TABLES.length,
      missingTables: EXPECTED_ERP_TABLES.map((t) => t.name),
      criticalTablesReady: false,
      readPrivilegeOk: false,
      writePrivilegeOk: false,
      writePrivilegeNote: 'Not evaluated (invalid URL).',
      postgresInspectorRpcAvailable: false,
      error: urlCheck.error,
    };
  }

  const key = String(params.serviceRoleKey || '').trim();
  if (!key || key.length < 16) {
    return {
      ok: false,
      checkedAt,
      latencyMs: null,
      reachable: false,
      schemaAccessible: false,
      totalExpectedTables: EXPECTED_ERP_TABLES.length,
      verifiedTablesCount: 0,
      missingTablesCount: EXPECTED_ERP_TABLES.length,
      missingTables: EXPECTED_ERP_TABLES.map((t) => t.name),
      criticalTablesReady: false,
      readPrivilegeOk: false,
      writePrivilegeOk: false,
      writePrivilegeNote: 'Service Role Key is missing or too short.',
      postgresInspectorRpcAvailable: false,
      error: 'Valid server-side Service Role Key is required.',
    };
  }

  const keyHint = inspectSupabaseKeyRoleHint(key);
  if (keyHint.looksLikeAnonKey) {
    return {
      ok: false,
      checkedAt,
      latencyMs: null,
      reachable: false,
      schemaAccessible: false,
      totalExpectedTables: EXPECTED_ERP_TABLES.length,
      verifiedTablesCount: 0,
      missingTablesCount: EXPECTED_ERP_TABLES.length,
      missingTables: EXPECTED_ERP_TABLES.map((t) => t.name),
      criticalTablesReady: false,
      readPrivilegeOk: false,
      writePrivilegeOk: false,
      writePrivilegeNote: `Key appears to be a public/anon key (${keyHint.jwtRole || 'publishable'}).`,
      postgresInspectorRpcAvailable: false,
      error: 'Anon or publishable keys are rejected. Provide a server-only service_role key.',
    };
  }

  const openApi = await fetchPostgrestOpenApiSpec(urlCheck.normalizedUrl, key);
  if (!openApi.ok) {
    const failedSummary: TargetValidationSummary = {
      ok: false,
      checkedAt,
      latencyMs: openApi.latencyMs,
      reachable: false,
      schemaAccessible: false,
      totalExpectedTables: EXPECTED_ERP_TABLES.length,
      verifiedTablesCount: 0,
      missingTablesCount: EXPECTED_ERP_TABLES.length,
      missingTables: EXPECTED_ERP_TABLES.map((t) => t.name),
      criticalTablesReady: false,
      readPrivilegeOk: false,
      writePrivilegeOk: false,
      writePrivilegeNote: 'Target unreachable.',
      postgresInspectorRpcAvailable: false,
      error: openApi.error || 'Target Supabase endpoint could not be reached.',
    };
    if (params.persistToStaged) updateStagedTargetValidation(failedSummary);
    return failedSummary;
  }

  const client = createIsolatedSupabaseClient(urlCheck.normalizedUrl, key);
  const probes = await probeTablesExistenceAndCounts(client);
  const missingTables: string[] = [];
  let criticalTablesReady = true;
  for (const spec of EXPECTED_ERP_TABLES) {
    const res = probes.get(spec.name);
    if (!res?.exists) {
      missingTables.push(spec.name);
      if (spec.critical) criticalTablesReady = false;
    }
  }
  const verifiedTablesCount = EXPECTED_ERP_TABLES.length - missingTables.length;
  const readPrivilegeOk = verifiedTablesCount > 0;
  const writeCheck = await checkTargetWritePrivilegeNonDestructive(client, key);
  const pgSnapshot = await fetchPostgresCatalogSnapshot(client);

  const ok =
    openApi.ok &&
    missingTables.length === 0 &&
    readPrivilegeOk &&
    writeCheck.writePrivilegeOk !== false;

  const summary: TargetValidationSummary = {
    ok,
    checkedAt,
    latencyMs: openApi.latencyMs,
    reachable: true,
    schemaAccessible: openApi.tables.size > 0,
    totalExpectedTables: EXPECTED_ERP_TABLES.length,
    verifiedTablesCount,
    missingTablesCount: missingTables.length,
    missingTables,
    criticalTablesReady,
    readPrivilegeOk,
    writePrivilegeOk: writeCheck.writePrivilegeOk,
    writePrivilegeNote: writeCheck.note,
    postgresInspectorRpcAvailable: pgSnapshot.available,
    error: ok
      ? undefined
      : missingTables.length > 0
        ? `Target reachable, but ${missingTables.length}/${EXPECTED_ERP_TABLES.length} ERP tables are missing or inaccessible.`
        : writeCheck.writePrivilegeOk === false
          ? writeCheck.note
          : 'Target validation completed with warnings.',
  };

  if (params.persistToStaged) {
    updateStagedTargetValidation(summary);
  }

  if (params.actor) {
    recordDbAuditEvent({
      eventType: 'DB_TARGET_TESTED',
      actorId: params.actor.id,
      actorName: params.actor.name,
      actorRole: params.actor.role,
      outcome: ok ? 'success' : 'warning',
      details: `Tested target (${maskDatabaseUrl(urlCheck.normalizedUrl)}): ${verifiedTablesCount}/${EXPECTED_ERP_TABLES.length} tables verified in ${openApi.latencyMs}ms.`,
    });
  }

  return summary;
}

function normalizeColumnTypeForComparison(meta: OpenApiColumnMeta): string {
  const fmt = meta.format.toLowerCase();
  if (fmt === 'integer' || fmt === 'int4' || fmt === 'int' || fmt === 'serial') return 'integer';
  if (fmt === 'bigint' || fmt === 'int8' || fmt === 'bigserial') return 'bigint';
  if (fmt.startsWith('numeric') || fmt === 'double precision' || fmt === 'real') return 'numeric';
  if (fmt === 'boolean' || fmt === 'bool') return 'boolean';
  if (fmt.includes('timestamp')) return 'timestamptz';
  if (fmt === 'text' || fmt === 'character varying' || fmt === 'string') return 'text';
  if (fmt === 'jsonb' || fmt === 'json') return 'jsonb';
  if (fmt === 'uuid') return 'uuid';
  return fmt;
}

export async function compareDatabaseSchemas(params: {
  targetUrl: string;
  targetServiceRoleKey: string;
  persistToStaged?: boolean;
  actor?: { id: string; name: string; role: string };
}): Promise<SchemaComparisonReport> {
  const checkedAt = new Date().toISOString();
  const activeCfg = getServerDbConfig();
  const urlCheck = validateCandidateSupabaseUrl(params.targetUrl);
  if (!urlCheck.valid || !params.targetServiceRoleKey) {
    throw new Error(urlCheck.error || 'Target database URL and Service Role Key are required.');
  }

  const targetUrl = urlCheck.normalizedUrl;
  const targetClient = createIsolatedSupabaseClient(targetUrl, params.targetServiceRoleKey);

  // Inspect Target
  const [targetOpenApi, targetProbes, targetPg] = await Promise.all([
    fetchPostgrestOpenApiSpec(targetUrl, params.targetServiceRoleKey),
    probeTablesExistenceAndCounts(targetClient),
    fetchPostgresCatalogSnapshot(targetClient),
  ]);

  // Inspect Active Source if configured
  let sourceOpenApi: { ok: boolean; tables: Map<string, OpenApiTableMeta> } = {
    ok: false,
    tables: new Map(),
  };
  let sourceProbes = new Map<string, { exists: boolean; count: number | null; error?: string }>();
  let sourcePg: PostgresCatalogSnapshot = {
    available: false,
    extensions: [],
    tablesRls: new Map(),
    views: new Set(),
    indexes: [],
    sequences: [],
    policies: [],
    constraints: [],
  };

  if (activeCfg.isConfigured) {
    const sourceClient = createIsolatedSupabaseClient(activeCfg.supabaseUrl, activeCfg.supabaseKey);
    const [sApi, sProbes, sPg] = await Promise.all([
      fetchPostgrestOpenApiSpec(activeCfg.supabaseUrl, activeCfg.supabaseKey),
      probeTablesExistenceAndCounts(sourceClient),
      fetchPostgresCatalogSnapshot(sourceClient),
    ]);
    sourceOpenApi = sApi;
    sourceProbes = sProbes;
    sourcePg = sPg;
  }

  const diffItems: SchemaDiffItem[] = [];
  const tableComparisons: TableComparisonRow[] = [];
  const expectedNamesSet = new Set(EXPECTED_ERP_TABLES.map((t) => t.name));

  const extraTablesOnTarget = Array.from(targetOpenApi.tables.keys()).filter(
    (name) => !expectedNamesSet.has(name) && !EXPECTED_SCHEMA_VIEWS.includes(name)
  );
  for (const extraName of extraTablesOnTarget) {
    diffItems.push({
      category: 'Table',
      objectName: extraName,
      tableName: extraName,
      status: 'Extra',
      expectedOrSource: 'Not in canonical 114-table schema',
      targetActual: 'Present on target',
      details: `Extra table "${extraName}" found in target public schema (will not be modified).`,
    });
  }

  let targetTablesPresent = 0;

  for (const spec of EXPECTED_ERP_TABLES) {
    const srcProbe = sourceProbes.get(spec.name);
    const tgtProbe = targetProbes.get(spec.name);
    const sourceExists = activeCfg.isConfigured ? Boolean(srcProbe?.exists) : true;
    const targetExists = Boolean(tgtProbe?.exists);
    if (targetExists) targetTablesPresent += 1;

    const srcMeta = sourceOpenApi.tables.get(spec.name);
    const tgtMeta = targetOpenApi.tables.get(spec.name);

    const missingColumns: string[] = [];
    const extraColumns: string[] = [];
    const typeOrNullableDiffs: string[] = [];
    const notes: string[] = [];

    if (!targetExists) {
      diffItems.push({
        category: 'Table',
        objectName: spec.name,
        tableName: spec.name,
        status: 'Missing',
        expectedOrSource: 'Required ERP table',
        targetActual: tgtProbe?.error || 'Missing or inaccessible',
        details: `Table "${spec.name}" must be created in target before migration (run supabase_schema.sql).`,
      });
    } else if (tgtMeta) {
      const referenceCols = srcMeta
        ? Array.from(srcMeta.columns.keys())
        : [...spec.expectedColumns];

      for (const col of referenceCols) {
        if (!tgtMeta.columns.has(col)) {
          missingColumns.push(col);
          diffItems.push({
            category: 'Column',
            objectName: `${spec.name}.${col}`,
            tableName: spec.name,
            status: 'Missing',
            expectedOrSource: col,
            targetActual: 'Missing',
            details: `Column "${col}" missing on target table "${spec.name}".`,
          });
        } else if (srcMeta?.columns.has(col)) {
          const sCol = srcMeta.columns.get(col)!;
          const tCol = tgtMeta.columns.get(col)!;
          const sType = normalizeColumnTypeForComparison(sCol);
          const tType = normalizeColumnTypeForComparison(tCol);
          if (sType !== tType) {
            typeOrNullableDiffs.push(`${col}: ${sType} vs ${tType}`);
            diffItems.push({
              category: 'DataType',
              objectName: `${spec.name}.${col}`,
              tableName: spec.name,
              status: 'Different',
              expectedOrSource: `${sCol.format} (${sType})`,
              targetActual: `${tCol.format} (${tType})`,
              details: `Data type mismatch on ${spec.name}.${col}.`,
            });
          }
          if (sCol.nullable !== tCol.nullable) {
            typeOrNullableDiffs.push(
              `${col} nullable: ${sCol.nullable} vs ${tCol.nullable}`
            );
            diffItems.push({
              category: 'Nullable',
              objectName: `${spec.name}.${col}`,
              tableName: spec.name,
              status: 'Different',
              expectedOrSource: sCol.nullable ? 'NULLABLE' : 'NOT NULL',
              targetActual: tCol.nullable ? 'NULLABLE' : 'NOT NULL',
              details: `Nullability differs on ${spec.name}.${col}.`,
            });
          }
        }
      }

      for (const col of tgtMeta.columns.keys()) {
        if (!referenceCols.includes(col)) {
          extraColumns.push(col);
          diffItems.push({
            category: 'Column',
            objectName: `${spec.name}.${col}`,
            tableName: spec.name,
            status: 'Extra',
            expectedOrSource: 'Not in source/baseline',
            targetActual: col,
            details: `Extra column "${col}" present on target table "${spec.name}".`,
          });
        }
      }
    }

    // Primary Key check
    let pkMatch: CompatibilityStatus = 'Compatible';
    if (!targetExists) {
      pkMatch = 'Missing';
    } else if (tgtMeta) {
      const pkCol = tgtMeta.columns.get(spec.primaryKey);
      if (!pkCol || !pkCol.isPrimaryKey) {
        pkMatch = targetPg.available
          ? targetPg.constraints.some((c) => c.table === spec.name && c.type === 'PRIMARY KEY')
            ? 'Compatible'
            : 'Missing'
          : 'Requires Attention';
        if (pkMatch !== 'Compatible') {
          diffItems.push({
            category: 'PrimaryKey',
            objectName: `${spec.name}.${spec.primaryKey}`,
            tableName: spec.name,
            status: pkMatch,
            expectedOrSource: `PRIMARY KEY (${spec.primaryKey})`,
            targetActual: pkCol ? 'Column exists without PK metadata' : 'Missing',
            details: `Primary key on "${spec.name}" could not be confirmed on target.`,
          });
        }
      }
    } else {
      pkMatch = 'Requires Attention';
    }

    // Foreign Key check
    let fkMatch: CompatibilityStatus = 'Compatible';
    if (!targetExists) {
      fkMatch = spec.parentTables.length > 0 ? 'Missing' : 'Compatible';
    } else if (spec.parentTables.length > 0 && tgtMeta) {
      const detectedParents = new Set(
        Array.from(tgtMeta.columns.values())
          .map((c) => c.foreignKeyTarget?.split('.')[0])
          .filter(Boolean)
      );
      const missingFkParents = spec.parentTables.filter((p) => !detectedParents.has(p));
      if (missingFkParents.length > 0) {
        if (targetPg.available) {
          const hasPgFk = targetPg.constraints.some(
            (c) => c.table === spec.name && c.type === 'FOREIGN KEY'
          );
          fkMatch = hasPgFk ? 'Compatible' : 'Requires Attention';
        } else {
          fkMatch = 'Requires Attention';
        }
        if (fkMatch !== 'Compatible') {
          notes.push(`FK metadata unconfirmed for parent(s): ${missingFkParents.join(', ')}`);
          diffItems.push({
            category: 'ForeignKey',
            objectName: `${spec.name} -> [${missingFkParents.join(',')}]`,
            tableName: spec.name,
            status: fkMatch,
            expectedOrSource: spec.parentTables.join(', '),
            targetActual: Array.from(detectedParents).join(', ') || 'None detected in OpenAPI',
            details: `Expected FK relationships to [${missingFkParents.join(', ')}] not detected in PostgREST spec.`,
          });
        }
      }
    }

    // RLS status check
    let rlsStatus: CompatibilityStatus = 'Requires Attention';
    if (!targetExists) {
      rlsStatus = 'Missing';
    } else if (targetPg.available) {
      const enabled = targetPg.tablesRls.get(spec.name);
      rlsStatus = enabled ? 'Compatible' : 'Requires Attention';
      if (!enabled) {
        notes.push('RLS is disabled on target table (run supabase_rls_hardening.sql)');
        diffItems.push({
          category: 'RLS',
          objectName: spec.name,
          tableName: spec.name,
          status: 'Requires Attention',
          expectedOrSource: 'RLS Enabled',
          targetActual: 'RLS Disabled',
          details: `Row Level Security is disabled on target "${spec.name}". Apply supabase_rls_hardening.sql after migration.`,
        });
      }
    } else {
      notes.push('RLS/indexes/policies need helper RPC or manual SQL verification');
    }

    // Sequence check
    let sequenceStatus: CompatibilityStatus = 'Compatible';
    if (spec.hasSequence) {
      if (!targetExists) {
        sequenceStatus = 'Missing';
      } else if (targetPg.available) {
        const seqName = spec.sequenceName || `${spec.name}_id_seq`;
        const foundSeq = targetPg.sequences.find((s) => s.name === seqName);
        if (!foundSeq) {
          sequenceStatus = 'Missing';
          diffItems.push({
            category: 'Sequence',
            objectName: seqName,
            tableName: spec.name,
            status: 'Missing',
            expectedOrSource: seqName,
            targetActual: 'Missing',
            details: `Expected sequence "${seqName}" missing on target.`,
          });
        }
      } else {
        sequenceStatus = 'Requires Attention';
      }
    }

    let rowStatus: CompatibilityStatus = 'Compatible';
    if (!targetExists || missingColumns.length > 0 || pkMatch === 'Missing') {
      rowStatus = 'Missing';
    } else if (typeOrNullableDiffs.length > 0) {
      rowStatus = 'Different';
    } else if (
      extraColumns.length > 0 &&
      rlsStatus === 'Compatible' &&
      fkMatch === 'Compatible' &&
      sequenceStatus === 'Compatible'
    ) {
      rowStatus = 'Extra';
    } else if (
      fkMatch === 'Requires Attention' ||
      rlsStatus === 'Requires Attention' ||
      sequenceStatus === 'Requires Attention'
    ) {
      rowStatus = 'Requires Attention';
    }

    tableComparisons.push({
      table: spec.name,
      domain: spec.domain,
      critical: Boolean(spec.critical),
      sourceExists,
      targetExists,
      sourceRowCount: srcProbe?.count ?? null,
      targetRowCount: tgtProbe?.count ?? null,
      status: rowStatus,
      columnDiffCount: missingColumns.length + extraColumns.length + typeOrNullableDiffs.length,
      missingColumns,
      extraColumns,
      typeOrNullableDiffs,
      pkMatch,
      fkMatch,
      rlsStatus,
      sequenceStatus,
      notes,
    });
  }

  // Extensions, Views, Indexes, Unique Constraints, Policies, Privileges global checks
  if (targetPg.available) {
    for (const ext of EXPECTED_SCHEMA_EXTENSIONS) {
      const found = targetPg.extensions.some((e) => e.name === ext);
      diffItems.push({
        category: 'Extension',
        objectName: ext,
        status: found ? 'Compatible' : 'Missing',
        expectedOrSource: ext,
        targetActual: found ? 'Installed' : 'Missing',
        details: found
          ? `Extension "${ext}" installed on target.`
          : `Required Postgres extension "${ext}" is missing on target.`,
      });
    }

    for (const viewName of EXPECTED_SCHEMA_VIEWS) {
      const found = targetPg.views.has(viewName);
      diffItems.push({
        category: 'View',
        objectName: viewName,
        status: found ? 'Compatible' : 'Requires Attention',
        expectedOrSource: viewName,
        targetActual: found ? 'Present' : 'Missing',
        details: found
          ? `View "${viewName}" exists on target.`
          : `View "${viewName}" is missing on target.`,
      });
    }

    // Check permissive policies on target
    const permissivePolicies = targetPg.policies.filter((p) => {
      const roles = Array.isArray(p.roles) ? p.roles : [];
      const touchesPublicRoles = roles.some((r) =>
        ['public', 'anon', 'authenticated'].includes(String(r).toLowerCase())
      );
      const q = String(p.qual || '').trim().toLowerCase();
      const wc = String(p.withCheck || '').trim().toLowerCase();
      return (
        p.permissive === 'PERMISSIVE' &&
        touchesPublicRoles &&
        (q === 'true' || q === '(true)' || wc === 'true' || wc === '(true)')
      );
    });

    if (permissivePolicies.length > 0) {
      for (const p of permissivePolicies.slice(0, 25)) {
        diffItems.push({
          category: 'Policy',
          objectName: `${p.table}.${p.name}`,
          tableName: p.table,
          status: 'Requires Attention',
          expectedOrSource: 'Strict default-deny (no public/anon permissive policies)',
          targetActual: `Permissive policy for [${(p.roles || []).join(', ')}]`,
          details: `Apply supabase_rls_hardening.sql on target before cutover to remove permissive policy "${p.name}".`,
        });
      }
    } else {
      diffItems.push({
        category: 'Policy',
        objectName: 'public/anon RLS policies',
        status: 'Compatible',
        expectedOrSource: '0 permissive public/anon policies',
        targetActual: '0 permissive policies',
        details: 'No permissive public/anon/authenticated policies detected.',
      });
    }

    const indexCount = targetPg.indexes.length;
    diffItems.push({
      category: 'Index',
      objectName: 'public schema indexes',
      status: indexCount >= EXPECTED_TOTAL_INDEX_COUNT ? 'Compatible' : 'Requires Attention',
      expectedOrSource: `>= ${EXPECTED_TOTAL_INDEX_COUNT} indexes`,
      targetActual: `${indexCount} indexes`,
      details:
        indexCount >= EXPECTED_TOTAL_INDEX_COUNT
          ? `Target has ${indexCount} public indexes.`
          : `Target has ${indexCount} indexes vs ${EXPECTED_TOTAL_INDEX_COUNT} baseline indexes.`,
    });

    const uniqueConstraints = targetPg.constraints.filter((c) => c.type === 'UNIQUE').length;
    diffItems.push({
      category: 'UniqueConstraint',
      objectName: 'public schema unique constraints',
      status: uniqueConstraints > 0 ? 'Compatible' : 'Requires Attention',
      expectedOrSource: 'UNIQUE constraints present',
      targetActual: `${uniqueConstraints} UNIQUE constraints`,
      details: `Detected ${uniqueConstraints} UNIQUE constraints via PostgreSQL catalog.`,
    });
  } else {
    for (const [cat, label] of [
      ['Extension', `Extensions (${EXPECTED_SCHEMA_EXTENSIONS.join(', ')})`],
      ['View', `Views (${EXPECTED_SCHEMA_VIEWS.join(', ')})`],
      ['Index', `Indexes (${EXPECTED_TOTAL_INDEX_COUNT} expected)`],
      ['Sequence', 'SERIAL/BIGSERIAL Sequences (74 expected)'],
      ['UniqueConstraint', 'UNIQUE Constraints'],
      ['RLS', 'Row-Level Security status across 114 tables'],
      ['Policy', 'Absence of permissive public/anon RLS policies'],
    ] as const) {
      diffItems.push({
        category: cat,
        objectName: label,
        status: 'Requires Attention',
        expectedOrSource: label,
        targetActual: 'Postgres catalog RPC not installed on target',
        details:
          'PostgREST OpenAPI does not expose pg_catalog metadata directly. Run sql/phase4_migration_helper_rpcs.sql on target for live inspection, or verify via Supabase SQL Editor.',
      });
    }
  }

  // Privilege check summary
  const writeCheck = await checkTargetWritePrivilegeNonDestructive(
    targetClient,
    params.targetServiceRoleKey
  );
  diffItems.push({
    category: 'Privilege',
    objectName: 'service_role read & write access',
    status:
      writeCheck.writePrivilegeOk === true && targetTablesPresent === EXPECTED_ERP_TABLES.length
        ? 'Compatible'
        : writeCheck.writePrivilegeOk === false
          ? 'Missing'
          : 'Requires Attention',
    expectedOrSource: 'service_role read/write on all 114 ERP tables',
    targetActual: writeCheck.note,
    details: writeCheck.note,
  });

  // Summarize counts across diffItems & tables
  const categorySummary: SchemaComparisonReport['categorySummary'] = {};
  const bump = (cat: string, st: CompatibilityStatus) => {
    if (!categorySummary[cat]) {
      categorySummary[cat] = { compatible: 0, missing: 0, different: 0, extra: 0, requiresAttention: 0 };
    }
    if (st === 'Compatible') categorySummary[cat].compatible += 1;
    else if (st === 'Missing') categorySummary[cat].missing += 1;
    else if (st === 'Different') categorySummary[cat].different += 1;
    else if (st === 'Extra') categorySummary[cat].extra += 1;
    else categorySummary[cat].requiresAttention += 1;
  };

  for (const row of tableComparisons) {
    if (row.targetExists) bump('Table', row.status === 'Missing' ? 'Compatible' : 'Compatible');
    else bump('Table', 'Missing');
  }
  for (const d of diffItems) {
    bump(d.category, d.status);
  }

  const missingCount = diffItems.filter((d) => d.status === 'Missing').length;
  const differentCount = diffItems.filter((d) => d.status === 'Different').length;
  const extraCount = diffItems.filter((d) => d.status === 'Extra').length;
  const requiresAttentionCount = diffItems.filter((d) => d.status === 'Requires Attention').length;
  const compatibleCount = tableComparisons.filter((t) => t.status === 'Compatible').length;

  const missingTables = tableComparisons.filter((t) => !t.targetExists);
  const missingCriticalColumns = tableComparisons.filter(
    (t) => t.critical && t.missingColumns.length > 0
  );

  let overallStatus: CompatibilityStatus = 'Compatible';
  if (missingTables.length > 0 || missingCriticalColumns.length > 0 || writeCheck.writePrivilegeOk === false) {
    overallStatus = 'Missing';
  } else if (differentCount > 0) {
    overallStatus = 'Different';
  } else if (requiresAttentionCount > 0) {
    overallStatus = 'Requires Attention';
  } else if (extraCount > 0) {
    overallStatus = 'Extra';
  }

  // Migration eligible when all 114 tables exist, no missing columns on critical tables, no type mismatches, and write privilege OK
  const migrationEligible =
    targetTablesPresent === EXPECTED_ERP_TABLES.length &&
    tableComparisons.every((t) => t.missingColumns.length === 0) &&
    differentCount === 0 &&
    writeCheck.writePrivilegeOk !== false;

  const recommendedActions: string[] = [];
  if (missingTables.length > 0) {
    recommendedActions.push(
      `Execute supabase_schema.sql on the target Supabase project to create the ${missingTables.length} missing table(s).`
    );
  }
  if (!targetPg.available) {
    recommendedActions.push(
      'Run sql/phase4_migration_helper_rpcs.sql on target (and source) Supabase SQL Editor to enable live Postgres inspection of indexes, sequences, views, extensions, RLS, policies, and automatic sequence sync.'
    );
  }
  if (targetPg.available && diffItems.some((d) => d.category === 'RLS' && d.status !== 'Compatible')) {
    recommendedActions.push(
      'Execute supabase_rls_hardening.sql on target before cutover to enforce default-deny RLS across all 114 tables.'
    );
  }
  if (missingCriticalColumns.length > 0) {
    recommendedActions.push(
      `Align missing columns on critical table(s): ${missingCriticalColumns.map((t) => t.table).join(', ')}.`
    );
  }

  const mdLines: string[] = [
    `# Ensec ERP Schema Compatibility Report`,
    `- **Checked At**: ${checkedAt}`,
    `- **Source**: ${activeCfg.maskedUrl || 'Canonical 114-table baseline (source env unconfigured)'} (${activeCfg.projectFingerprint || 'baseline'})`,
    `- **Target**: ${maskDatabaseUrl(targetUrl)}`,
    `- **Overall Status**: ${overallStatus}`,
    `- **Migration Eligible**: ${migrationEligible ? 'YES' : 'NO'}`,
    `- **Target Tables Present**: ${targetTablesPresent}/${EXPECTED_ERP_TABLES.length}`,
    `- **Postgres Catalog RPC (Target)**: ${targetPg.available ? 'Installed (Live Catalog)' : 'Not Installed (PostgREST OpenAPI Mode)'}`,
    ``,
    `## Findings (${diffItems.length})`,
    ...diffItems.map(
      (d) => `- [${d.status}] **${d.category}** \`${d.objectName}\`: ${d.details} (Expected: ${d.expectedOrSource} | Actual: ${d.targetActual})`
    ),
    ``,
    `## Recommended Actions`,
    ...(recommendedActions.length > 0 ? recommendedActions.map((a) => `- ${a}`) : ['- None required.']),
  ];

  const report: SchemaComparisonReport = {
    checkedAt,
    sourceFingerprint: activeCfg.projectFingerprint,
    sourceMaskedUrl: activeCfg.maskedUrl,
    targetFingerprint: computeProjectFingerprint(targetUrl),
    targetMaskedUrl: maskDatabaseUrl(targetUrl),
    overallStatus,
    migrationEligible,
    summary: {
      compatible: compatibleCount,
      missing: missingCount,
      different: differentCount,
      extra: extraCount,
      requiresAttention: requiresAttentionCount,
      totalTablesExpected: EXPECTED_ERP_TABLES.length,
      targetTablesPresent,
      extraTablesOnTarget,
      postgresInspectorOnSource: sourcePg.available,
      postgresInspectorOnTarget: targetPg.available,
    },
    categorySummary,
    tableComparisons,
    diffItems,
    recommendedActions,
    markdownReport: mdLines.join('\n'),
  };

  if (params.persistToStaged) {
    updateStagedTargetSchemaResult(overallStatus, checkedAt);
  }

  if (params.actor) {
    recordDbAuditEvent({
      eventType: 'DB_SCHEMA_COMPARED',
      actorId: params.actor.id,
      actorName: params.actor.name,
      actorRole: params.actor.role,
      outcome: migrationEligible ? 'success' : 'warning',
      details: `Schema comparison completed (${overallStatus}, eligible=${migrationEligible}, targetTables=${targetTablesPresent}/${EXPECTED_ERP_TABLES.length}).`,
    });
  }

  return report;
}
