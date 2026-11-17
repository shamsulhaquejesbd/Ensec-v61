/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Ensec ERP - Phase 4 Super-Admin Database Migration & Switching API Routes
 * All endpoints strictly enforce valid signed Super Admin session + CSRF protection
 * and NEVER expose raw database URLs, service_role keys, or session secrets.
 */

import express from 'express';
import fs from 'fs';
import path from 'path';
import {
  buildExportableMigrationReport,
  cancelActiveMigration,
  compareDatabaseSchemas,
  computeProjectFingerprint,
  executeDatabaseCutover,
  executeDatabaseRollback,
  EXPECTED_ERP_TABLES,
  getDbAuditEvents,
  getDbOperationLock,
  getMigrationHistory,
  getMigrationRunById,
  getPublicPreviousRollbackSummary,
  getPublicSafeDatabaseSummary,
  getPublicStagedTargetSummary,
  getStagedTargetInternal,
  inspectSupabaseKeyRoleHint,
  maskDatabaseUrl,
  normalizeDatabaseEnvironment,
  recordDbAuditEvent,
  retryFailedMigration,
  runPreMigrationChecklist,
  sanitizeDatabaseError,
  saveStagedTargetConfig,
  startDatabaseMigration,
  validateCandidateSupabaseUrl,
  validateTargetDatabaseConnection,
} from '../db/index.ts';

export type RequireSuperAdminFn = (
  req: express.Request,
  res: express.Response
) => Promise<{ id: string; name: string; role: string } | null>;

function resolveTargetCredentialsFromRequest(body: any): {
  supabaseUrl: string;
  serviceRoleKey: string;
  error?: string;
} {
  const staged = getStagedTargetInternal();
  const useSaved = body?.useSavedTarget !== false;
  const rawUrl = String(body?.supabaseUrl || '').trim();
  const rawKey = String(body?.serviceRoleKey || '').trim();

  if (rawUrl) {
    const urlCheck = validateCandidateSupabaseUrl(rawUrl);
    if (!urlCheck.valid) {
      return { supabaseUrl: '', serviceRoleKey: '', error: urlCheck.error };
    }
    const key =
      rawKey ||
      (staged &&
      computeProjectFingerprint(staged.supabaseUrl) ===
        computeProjectFingerprint(urlCheck.normalizedUrl)
        ? staged.serviceRoleKey
        : '');
    if (!key) {
      return {
        supabaseUrl: '',
        serviceRoleKey: '',
        error: 'Service Role Key is required to test or compare this target URL.',
      };
    }
    return { supabaseUrl: urlCheck.normalizedUrl, serviceRoleKey: key };
  }

  if (useSaved && staged?.supabaseUrl && staged?.serviceRoleKey) {
    return {
      supabaseUrl: staged.supabaseUrl,
      serviceRoleKey: staged.serviceRoleKey,
    };
  }

  return {
    supabaseUrl: '',
    serviceRoleKey: '',
    error: 'No target database configuration saved yet. Save a target configuration first.',
  };
}

export function registerDatabaseMigrationRoutes(
  app: express.Express,
  requireSuperAdminSession: RequireSuperAdminFn
) {
  app.get('/api/admin/db/overview', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    return res.status(200).json({
      ok: true,
      active: getPublicSafeDatabaseSummary(),
      stagedTarget: getPublicStagedTargetSummary(),
      previousSnapshot: getPublicPreviousRollbackSummary(),
      lock: getDbOperationLock(),
      expectedTablesCount: EXPECTED_ERP_TABLES.length,
      migrationHistory: getMigrationHistory(15),
      auditEvents: getDbAuditEvents(50),
    });
  });

  app.post('/api/admin/db/config/target', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const lock = getDbOperationLock();
    if (lock.locked) {
      return res.status(409).json({
        ok: false,
        code: 'OPERATION_LOCKED',
        error: `Cannot change target configuration while "${lock.operation}" is active.`,
      });
    }

    const provider = String(req.body?.provider || 'supabase').trim().toLowerCase();
    if (provider !== 'supabase') {
      return res.status(400).json({
        ok: false,
        code: 'UNSUPPORTED_PROVIDER',
        error: 'Only "supabase" provider is currently supported.',
      });
    }

    const environment = normalizeDatabaseEnvironment(req.body?.environment || 'Staging');
    const urlCheck = validateCandidateSupabaseUrl(req.body?.supabaseUrl);
    if (!urlCheck.valid) {
      return res.status(400).json({
        ok: false,
        code: 'INVALID_TARGET_URL',
        error: urlCheck.error,
      });
    }

    const rawKey = String(req.body?.serviceRoleKey || '').trim();
    const existingStaged = getStagedTargetInternal();
    const canReuseExistingKey =
      !rawKey &&
      Boolean(existingStaged?.serviceRoleKey) &&
      computeProjectFingerprint(existingStaged!.supabaseUrl) ===
        computeProjectFingerprint(urlCheck.normalizedUrl);

    const finalKey = canReuseExistingKey ? existingStaged!.serviceRoleKey : rawKey;
    if (!finalKey || finalKey.length < 16) {
      return res.status(400).json({
        ok: false,
        code: 'INVALID_SERVICE_ROLE_KEY',
        error: 'A valid server-side Supabase Service Role Key is required.',
      });
    }

    const keyHint = inspectSupabaseKeyRoleHint(finalKey);
    if (keyHint.looksLikeAnonKey) {
      return res.status(400).json({
        ok: false,
        code: 'ANON_KEY_REJECTED',
        error: 'Anon or publishable keys cannot be used for centralized database control. Provide the service_role key.',
      });
    }

    const stagedSummary = saveStagedTargetConfig({
      provider: 'supabase',
      environment,
      supabaseUrl: urlCheck.normalizedUrl,
      serviceRoleKey: finalKey,
      savedBy: admin.name,
    });

    recordDbAuditEvent({
      eventType: 'DB_TARGET_SAVED',
      actorId: admin.id,
      actorName: admin.name,
      actorRole: admin.role,
      outcome: 'success',
      details: `Saved staged target config (${environment}, ${maskDatabaseUrl(urlCheck.normalizedUrl)}, active DB unchanged).`,
    });

    return res.status(200).json({
      ok: true,
      message: 'Target database configuration saved securely on server (not yet active).',
      stagedTarget: stagedSummary,
    });
  });

  app.post('/api/admin/db/config/test', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const creds = resolveTargetCredentialsFromRequest(req.body);
    if (creds.error) {
      return res.status(400).json({ ok: false, code: 'TARGET_UNCONFIGURED', error: creds.error });
    }

    const staged = getStagedTargetInternal();
    const matchesStaged =
      Boolean(staged) &&
      computeProjectFingerprint(staged!.supabaseUrl) ===
        computeProjectFingerprint(creds.supabaseUrl);

    const validation = await validateTargetDatabaseConnection({
      supabaseUrl: creds.supabaseUrl,
      serviceRoleKey: creds.serviceRoleKey,
      persistToStaged: matchesStaged,
      actor: admin,
    });

    return res.status(200).json({
      ok: validation.ok,
      validation,
      stagedTarget: getPublicStagedTargetSummary(),
    });
  });

  app.post('/api/admin/db/schema/compare', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const creds = resolveTargetCredentialsFromRequest(req.body);
    if (creds.error) {
      return res.status(400).json({ ok: false, code: 'TARGET_UNCONFIGURED', error: creds.error });
    }

    try {
      const staged = getStagedTargetInternal();
      const matchesStaged =
        Boolean(staged) &&
        computeProjectFingerprint(staged!.supabaseUrl) ===
          computeProjectFingerprint(creds.supabaseUrl);

      const report = await compareDatabaseSchemas({
        targetUrl: creds.supabaseUrl,
        targetServiceRoleKey: creds.serviceRoleKey,
        persistToStaged: matchesStaged,
        actor: admin,
      });

      return res.status(200).json({
        ok: true,
        report,
        stagedTarget: getPublicStagedTargetSummary(),
      });
    } catch (err) {
      return res.status(500).json({
        ok: false,
        code: 'SCHEMA_COMPARE_ERROR',
        error: sanitizeDatabaseError(err),
      });
    }
  });

  app.post('/api/admin/db/migration/preflight', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    try {
      const preflight = await runPreMigrationChecklist({
        confirmSourceBackupTaken: Boolean(req.body?.confirmSourceBackupTaken),
        confirmTargetExistingData: Boolean(req.body?.confirmTargetExistingData),
        actor: admin,
      });
      return res.status(200).json({
        ok: true,
        preflight,
        stagedTarget: getPublicStagedTargetSummary(),
      });
    } catch (err) {
      return res.status(500).json({
        ok: false,
        code: 'PREFLIGHT_ERROR',
        error: sanitizeDatabaseError(err),
      });
    }
  });

  app.post('/api/admin/db/migration/start', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const result = await startDatabaseMigration({
      confirmSourceBackupTaken: Boolean(req.body?.confirmSourceBackupTaken),
      confirmTargetExistingData: Boolean(req.body?.confirmTargetExistingData),
      batchSize: Number(req.body?.batchSize) || 200,
      waitForCompletion: Boolean(req.body?.waitForCompletion),
      actor: admin,
    });

    if (!result.ok) {
      const status =
        result.code === 'MIGRATION_LOCKED'
          ? 409
          : result.code === 'PREFLIGHT_BLOCKED' || result.code === 'DB_NOT_CONFIGURED'
            ? 400
            : 500;
      return res.status(status).json(result);
    }

    return res.status(200).json(result);
  });

  app.get('/api/admin/db/migration/:id', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const run = getMigrationRunById(String(req.params.id || ''));
    if (!run) {
      return res.status(404).json({ ok: false, code: 'NOT_FOUND', error: 'Migration run not found.' });
    }
    return res.status(200).json({ ok: true, run, lock: getDbOperationLock() });
  });

  app.get('/api/admin/db/migration/:id/report', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const run = getMigrationRunById(String(req.params.id || ''));
    if (!run) {
      return res.status(404).json({ ok: false, code: 'NOT_FOUND', error: 'Migration run not found.' });
    }
    const report = buildExportableMigrationReport(run);
    return res.status(200).json({ ok: true, report });
  });

  app.post('/api/admin/db/migration/:id/cancel', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const result = await cancelActiveMigration(String(req.params.id || ''), admin);
    return res.status(result.ok ? 200 : 400).json(result);
  });

  app.post('/api/admin/db/migration/:id/retry', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const result = await retryFailedMigration({
      migrationId: String(req.params.id || ''),
      waitForCompletion: Boolean(req.body?.waitForCompletion),
      actor: admin,
    });
    if (!result.ok) {
      return res.status(result.code === 'MIGRATION_LOCKED' ? 409 : 400).json(result);
    }
    return res.status(200).json(result);
  });

  app.post('/api/admin/db/cutover', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const result = await executeDatabaseCutover({
      migrationId: req.body?.migrationId ? String(req.body.migrationId) : undefined,
      confirmationPhrase: String(req.body?.confirmationPhrase || ''),
      confirmChecklist: Boolean(req.body?.confirmChecklist),
      actor: admin,
    });

    if (!result.ok) {
      const status =
        result.code === 'OPERATION_LOCKED'
          ? 409
          : result.code === 'TARGET_HEALTH_FAILED' || result.code === 'TARGET_NO_SUPER_ADMIN'
            ? 422
            : 400;
      return res.status(status).json(result);
    }

    return res.status(200).json({
      ...result,
      active: getPublicSafeDatabaseSummary(),
      previousSnapshot: getPublicPreviousRollbackSummary(),
      migrationHistory: getMigrationHistory(15),
    });
  });

  app.post('/api/admin/db/rollback', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const result = await executeDatabaseRollback({
      reason: String(req.body?.reason || ''),
      confirmationPhrase: String(req.body?.confirmationPhrase || ''),
      acknowledgeDataDivergence: Boolean(req.body?.acknowledgeDataDivergence),
      actor: admin,
    });

    if (!result.ok) {
      const status =
        result.code === 'OPERATION_LOCKED' || result.code === 'DATA_DIVERGENCE_DETECTED'
          ? 409
          : result.code === 'PREVIOUS_DB_UNHEALTHY'
            ? 422
            : 400;
      return res.status(status).json(result);
    }

    return res.status(200).json({
      ...result,
      active: getPublicSafeDatabaseSummary(),
      previousSnapshot: getPublicPreviousRollbackSummary(),
      migrationHistory: getMigrationHistory(15),
    });
  });

  app.get('/api/admin/db/sql-scripts/:kind', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;

    const kind = String(req.params.kind || '').toLowerCase();
    const rootDir = process.cwd();
    const map: Record<string, { file: string; label: string }> = {
      'helper-rpcs': {
        file: path.join(rootDir, 'sql', 'phase4_migration_helper_rpcs.sql'),
        label: 'phase4_migration_helper_rpcs.sql',
      },
      schema: {
        file: path.join(rootDir, 'supabase_schema.sql'),
        label: 'supabase_schema.sql',
      },
      rls: {
        file: path.join(rootDir, 'supabase_rls_hardening.sql'),
        label: 'supabase_rls_hardening.sql',
      },
    };

    const spec = map[kind];
    if (!spec || !fs.existsSync(spec.file)) {
      return res.status(404).json({ ok: false, error: 'Requested SQL script not found.' });
    }
    const content = fs.readFileSync(spec.file, 'utf8');
    return res.status(200).json({
      ok: true,
      filename: spec.label,
      content,
    });
  });
}
