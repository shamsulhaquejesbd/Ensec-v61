import type express from 'express';
import { hasPageAction } from '../../src/types/pagePermissions.ts';
import {
  sanitizeProductionOrderForUser,
} from '../../src/lib/manufacturingPermissions.ts';
import {
  resolveOvertimePermissions,
  sanitizeOvertimeRecordForUser,
} from '../../src/lib/overtimePermissions.ts';
import {
  getServerSupabase,
  recordDbAuditEvent,
  sanitizeDatabaseError,
} from '../db/index.ts';
import {
  extractSessionToken,
  hashPassword,
  indexUserInAuthCache,
  isBcryptHash,
  lookupAuthoritativeUser,
  mapSupabaseUserRowSafe,
  resolveRequestUser,
  revokeAllSessionsForUser,
  sanitizeUserForClient,
  type AuthenticatedErpUser,
} from '../auth/authService.ts';
import { emitErpTableEvent } from './events.ts';
import {
  TABLE_RBAC_CONFIG,
  authorizeTableOperation,
  type OperationType,
} from '../../src/lib/tableRbac.ts';

export { TABLE_RBAC_CONFIG, authorizeTableOperation, type OperationType };


const ALLOWED_SELECT_EXPRESSIONS = new Set([
  '*',
  '*, stock_cid_receipt_items(*)',
  '*, stock_transfer_items(*)',
  '*, accounting_periods(*)',
  '*, accounting_voucher_lines(*)',
]);

function sanitizeSelectExpr(table: string, selectExpr?: string): string {
  if (!selectExpr || !selectExpr.trim()) return '*';
  const trimmed = selectExpr.trim();
  if (ALLOWED_SELECT_EXPRESSIONS.has(trimmed)) {
    return trimmed;
  }
  // Safe comma-separated column names (excluding password on users)
  const cols = trimmed
    .split(',')
    .map((c) => c.trim())
    .filter((c) => /^[a-zA-Z0-9_]+$/.test(c));
  if (cols.length === 0) return '*';
  const safeCols = table === 'users' ? cols.filter((c) => c.toLowerCase() !== 'password' && c.toLowerCase() !== 'password_hash') : cols;
  return safeCols.length > 0 ? safeCols.join(', ') : 'id';
}

export function sanitizeRowForCaller(table: string, row: any, caller: AuthenticatedErpUser): any {
  if (!row || typeof row !== 'object') return row;
  if (table === 'users') {
    const { password: _p, password_hash: _ph, ...safe } = row;
    return safe;
  }
  if (table === 'production_orders') {
    return sanitizeProductionOrderForUser(row, caller);
  }
  if (table === 'overtime_requests' || table === 'overtime_batch_allocations' || table === 'employee_overtimes') {
    const perms = resolveOvertimePermissions(caller);
    if (!perms.viewCost) {
      return sanitizeOvertimeRecordForUser(row, caller);
    }
  }
  if (table === 'raw_materials') {
    const canSeeRates =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'raw-material-inventory', 'view_raw_material_purchase_rate') ||
      hasPageAction(caller, 'raw-material-inventory', 'view_raw_material_stock_value') ||
      hasPageAction(caller, 'raw-material-receive', 'create') ||
      hasPageAction(caller, 'procurement', 'view') ||
      hasPageAction(caller, 'manufacturing', 'view_batch_rate') ||
      hasPageAction(caller, 'manufacturing', 'update_bom');
    if (!canSeeRates) {
      const copy = { ...row };
      delete copy.last_purchase_unit_cost_bdt;
      delete copy.standard_cost_bdt;
      return copy;
    }
  }
  return row;
}

async function prepareWritePayload(table: string, payload: any): Promise<any> {
  const processSingle = async (item: any) => {
    if (!item || typeof item !== 'object') return item;
    const copy = { ...item };
    if (table === 'users') {
      if (copy.password !== undefined && copy.password !== null && String(copy.password).trim() !== '') {
        const rawPass = String(copy.password).trim();
        copy.password = isBcryptHash(rawPass) ? rawPass : await hashPassword(rawPass);
      } else if (copy.password === '') {
        delete copy.password;
      }
    }
    return copy;
  };

  if (Array.isArray(payload)) {
    return Promise.all(payload.map(processSingle));
  }
  return processSingle(payload);
}

interface QueryFilter {
  type: 'eq' | 'neq' | 'in' | 'ilike' | 'gte' | 'or';
  column?: string;
  value?: any;
  expr?: string;
}

const SENSITIVE_USER_COLUMNS = new Set(['password', 'password_hash', 'passwordhash', '_passwordhash']);

function assertSafeQueryFiltersAndOrders(
  table: string,
  filters: QueryFilter[],
  orders: Array<{ column: string; ascending?: boolean }>
): string | null {
  if (table === 'users') {
    for (const f of filters) {
      if (f.column && SENSITIVE_USER_COLUMNS.has(f.column.trim().toLowerCase())) {
        return 'Filtering on sensitive credential columns is forbidden.';
      }
      if (f.type === 'or' && typeof f.expr === 'string') {
        const lowerExpr = f.expr.toLowerCase();
        if (/\b(password|password_hash|passwordhash)\b/.test(lowerExpr)) {
          return 'Filtering on sensitive credential columns is forbidden.';
        }
      }
    }
    for (const ord of orders) {
      if (ord.column && SENSITIVE_USER_COLUMNS.has(ord.column.trim().toLowerCase())) {
        return 'Sorting by sensitive credential columns is forbidden.';
      }
    }
  }
  return null;
}

function validateUsersWriteAuthorization(
  caller: AuthenticatedErpUser,
  operation: OperationType,
  payload: any,
  filters: QueryFilter[]
): string | null {
  const items = Array.isArray(payload) ? payload : [payload];
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    if (String(item.role || '').trim() === 'Super Admin' && caller.role !== 'Super Admin') {
      return 'Forbidden: Only a Super Admin may assign or modify the Super Admin role.';
    }
    if (
      item.permissions !== undefined &&
      caller.role !== 'Super Admin' &&
      !hasPageAction(caller, 'users-permissions', 'assign_permissions')
    ) {
      return 'Forbidden: assign_permissions permission is required to modify user permissions.';
    }
    if (
      item.password !== undefined &&
      String(item.password).trim() !== '' &&
      caller.role !== 'Super Admin' &&
      !hasPageAction(caller, 'users-permissions', 'reset_password') &&
      !(operation === 'insert' && hasPageAction(caller, 'users-permissions', 'create'))
    ) {
      return 'Forbidden: reset_password permission is required to update user credentials.';
    }
  }
  if (operation === 'update' || operation === 'delete') {
    for (const f of filters) {
      if (
        f.column?.toLowerCase() === 'role' &&
        String(f.value || '').trim() === 'Super Admin' &&
        caller.role !== 'Super Admin'
      ) {
        return 'Forbidden: Only a Super Admin may modify or delete Super Admin accounts.';
      }
    }
  }
  return null;
}

function applyFilters(query: any, filters: QueryFilter[]) {
  let q = query;
  for (const f of filters) {
    if (f.type === 'eq' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.eq(f.column, f.value);
    } else if (f.type === 'neq' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.neq(f.column, f.value);
    } else if (f.type === 'in' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column) && Array.isArray(f.value)) {
      q = q.in(f.column, f.value.slice(0, 500));
    } else if (f.type === 'ilike' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.ilike(f.column, f.value);
    } else if (f.type === 'gte' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.gte(f.column, f.value);
    } else if (f.type === 'or' && typeof f.expr === 'string' && f.expr.trim().length > 0 && f.expr.length < 400) {
      // Allow only safe PostgREST eq/ilike clause lists (no nested injection)
      const parts = f.expr.split(',').map((p) => p.trim());
      const allSafe = parts.every((p) => /^[a-zA-Z0-9_]+\.(eq|ilike)\.[^\s;]+$/.test(p));
      if (allSafe) {
        q = q.or(f.expr.trim());
      }
    }
  }
  return q;
}

function stripMissingColumnFromPayload(payload: any, errMessage: string): boolean {
  const match =
    errMessage.match(/column ["']?([a-zA-Z0-9_]+)["']? of relation/i) ||
    errMessage.match(/Could not find the ['"]?([a-zA-Z0-9_]+)['"]? column/i);
  if (!match || !match[1]) return false;
  const col = match[1];
  let removed = false;
  const items = Array.isArray(payload) ? payload : [payload];
  for (const item of items) {
    if (item && typeof item === 'object' && col in item) {
      delete item[col];
      removed = true;
    }
  }
  return removed;
}

export function registerErpGatewayRoutes(app: express.Application) {
  // --------------------------------------------------------------------------
  // Centralized Authenticated & RBAC-Protected Database Gateway for 59 Tables
  // --------------------------------------------------------------------------
  app.post('/api/erp/db/:table', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        data: null,
        error: {
          message: 'Authentication required. Please sign in to Ensec ERP.',
          code: 'UNAUTHORIZED',
          status: 401,
        },
      });
    }

    const table = String(req.params.table || '').trim();
    const body = req.body || {};
    const operation: OperationType = (['select', 'insert', 'upsert', 'update', 'delete'].includes(body.operation)
      ? body.operation
      : 'select') as OperationType;

    const auth = authorizeTableOperation(caller, table, operation);
    if (!auth.allowed) {
      return res.status(403).json({
        data: null,
        error: {
          message: auth.reason || `Forbidden: Access denied to "${table}" (${operation}).`,
          code: '42501',
          status: 403,
        },
      });
    }

    const filters: QueryFilter[] = Array.isArray(body.filters) ? body.filters : [];
    const orders: Array<{ column: string; ascending?: boolean }> = Array.isArray(body.orders) ? body.orders : [];

    const unsafeQueryReason = assertSafeQueryFiltersAndOrders(table, filters, orders);
    if (unsafeQueryReason) {
      return res.status(403).json({
        data: null,
        error: {
          message: unsafeQueryReason,
          code: 'SENSITIVE_COLUMN_FORBIDDEN',
          status: 403,
        },
      });
    }

    if ((operation === 'update' || operation === 'delete') && filters.length === 0) {
      return res.status(400).json({
        data: null,
        error: {
          message: `Refusing unfiltered ${operation} on "${table}". Specify at least one filter.`,
          code: 'UNFILTERED_WRITE_FORBIDDEN',
          status: 400,
        },
      });
    }

    if (table === 'users' && operation !== 'select') {
      const userWriteErr = validateUsersWriteAuthorization(caller, operation, body.payload, filters);
      if (userWriteErr) {
        return res.status(403).json({
          data: null,
          error: {
            message: userWriteErr,
            code: 'USERS_PRIVILEGE_ESCALATION_BLOCKED',
            status: 403,
          },
        });
      }
    }

    const db = getServerSupabase();
    if (!db) {
      return res.status(503).json({
        data: null,
        error: {
          message: 'Server database connection is not configured.',
          code: 'DB_NOT_CONFIGURED',
          status: 503,
        },
      });
    }

    try {
      const limit = typeof body.limit === 'number' && body.limit > 0 ? Math.min(body.limit, 5000) : undefined;
      const returnRows = Boolean(body.returnSelect) || operation === 'select';
      const selectExpr = sanitizeSelectExpr(table, body.select);

      if (operation === 'select') {
        let q: any = db.from(table).select(selectExpr);
        q = applyFilters(q, filters);
        for (const ord of orders) {
          if (ord.column && /^[a-zA-Z0-9_]+$/.test(ord.column)) {
            q = q.order(ord.column, { ascending: ord.ascending !== false });
          }
        }
        if (limit) q = q.limit(limit);
        if (body.single) q = q.single();
        else if (body.maybeSingle) q = q.maybeSingle();

        const { data, error } = await q;
        if (error) {
          return res.status(400).json({
            data: null,
            error: {
              message: sanitizeDatabaseError(error.message),
              code: error.code || 'DB_ERROR',
            },
          });
        }
        const sanitized = Array.isArray(data)
          ? data.map((row) => sanitizeRowForCaller(table, row, caller))
          : data
          ? sanitizeRowForCaller(table, data, caller)
          : data;
        return res.status(200).json({ data: sanitized, error: null });
      }

      if (operation === 'insert' || operation === 'upsert' || operation === 'update') {
        let payload = await prepareWritePayload(table, body.payload);
        let resultData: any = null;
        let lastErr: any = null;

        for (let attempt = 0; attempt < 8; attempt++) {
          let q: any;
          if (operation === 'insert') {
            q = db.from(table).insert(payload);
          } else if (operation === 'upsert') {
            const upsertOpts: any = {};
            if (body.options?.onConflict && /^[a-zA-Z0-9_,]+$/.test(String(body.options.onConflict))) {
              upsertOpts.onConflict = String(body.options.onConflict);
            }
            if (body.options?.ignoreDuplicates !== undefined) {
              upsertOpts.ignoreDuplicates = Boolean(body.options.ignoreDuplicates);
            }
            q = db.from(table).upsert(payload, Object.keys(upsertOpts).length > 0 ? upsertOpts : undefined);
          } else {
            q = db.from(table).update(payload);
            q = applyFilters(q, filters);
          }

          if (returnRows) {
            q = q.select(selectExpr === '*' ? undefined : selectExpr);
            if (body.single) q = q.single();
            else if (body.maybeSingle) q = q.maybeSingle();
          }

          const { data, error } = await q;
          if (!error) {
            resultData = data;
            lastErr = null;
            break;
          }
          lastErr = error;
          const stripped = stripMissingColumnFromPayload(payload, error.message || '');
          if (stripped) continue;
          break;
        }

        if (lastErr) {
          return res.status(400).json({
            data: null,
            error: {
              message: sanitizeDatabaseError(lastErr.message),
              code: lastErr.code || 'DB_WRITE_ERROR',
            },
          });
        }

        const sanitized = Array.isArray(resultData)
          ? resultData.map((row) => sanitizeRowForCaller(table, row, caller))
          : resultData
          ? sanitizeRowForCaller(table, resultData, caller)
          : resultData;

        const firstRow = Array.isArray(sanitized) ? sanitized[0] : sanitized || (Array.isArray(payload) ? payload[0] : payload);
        if (table === 'users' && firstRow && (firstRow.status === 'Blocked' || firstRow.status === 'Inactive')) {
          revokeAllSessionsForUser([firstRow.id, firstRow.uid, firstRow.user_id, firstRow.email]);
        }
        emitErpTableEvent({
          table,
          eventType: operation === 'update' ? 'UPDATE' : 'INSERT',
          newRow: firstRow || null,
        });

        return res.status(200).json({ data: sanitized ?? null, error: null });
      }

      if (operation === 'delete') {
        let q: any = db.from(table).delete();
        q = applyFilters(q, filters);
        if (returnRows) q = q.select();
        const { data, error } = await q;
        if (error) {
          return res.status(400).json({
            data: null,
            error: {
              message: sanitizeDatabaseError(error.message),
              code: error.code || 'DB_DELETE_ERROR',
            },
          });
        }

        const deletedFirst = Array.isArray(data) ? data[0] : data;
        if (table === 'users') {
          const filterIds = filters.map((f) => (f.value !== undefined ? String(f.value) : '')).filter(Boolean);
          revokeAllSessionsForUser([
            deletedFirst?.id,
            deletedFirst?.uid,
            deletedFirst?.user_id,
            deletedFirst?.email,
            ...filterIds,
          ]);
        }
        emitErpTableEvent({
          table,
          eventType: 'DELETE',
          oldRow: deletedFirst || null,
        });

        return res.status(200).json({ data: data ?? null, error: null });
      }

      return res.status(400).json({ data: null, error: { message: 'Unsupported database operation.' } });
    } catch (err: any) {
      return res.status(500).json({
        data: null,
        error: {
          message: sanitizeDatabaseError(err?.message || 'Internal database gateway error.'),
          code: 'GATEWAY_ERROR',
        },
      });
    }
  });

  // --------------------------------------------------------------------------
  // Dedicated User Management Endpoints (Always bcrypt-hashed, never expose passwords)
  // --------------------------------------------------------------------------
  app.get('/api/erp/users', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ ok: false, error: 'Authentication required.' });
    }
    if (caller.role !== 'Super Admin' && !hasPageAction(caller, 'users-permissions', 'view')) {
      return res.status(403).json({
        ok: false,
        code: 'USERS_FORBIDDEN',
        error: 'Forbidden: User Management view permission required.',
      });
    }

    const db = getServerSupabase();
    if (db) {
      try {
        const { data, error } = await db.from('users').select('*').order('id', { ascending: true });
        if (!error && Array.isArray(data)) {
          const users = data.map((row) => mapSupabaseUserRowSafe(row));
          users.forEach((u) => indexUserInAuthCache(u));
          return res.json({ ok: true, users });
        }
      } catch (err: any) {
        return res.status(500).json({ ok: false, error: sanitizeDatabaseError(err?.message) });
      }
    }

    return res.status(200).json({ ok: true, users: [], dbConfigured: false });
  });

  app.put('/api/erp/users/:id/password', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }

    const targetId = String(req.params.id || '').trim();
    const isSelf =
      caller.id === targetId ||
      caller.userId.toLowerCase() === targetId.toLowerCase() ||
      (caller.email && caller.email.toLowerCase() === targetId.toLowerCase());

    const canAdminReset =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'users-permissions', 'reset_password') ||
      hasPageAction(caller, 'users-permissions', 'edit');

    if (!isSelf && !canAdminReset) {
      return res.status(403).json({
        success: false,
        code: 'PASSWORD_RESET_FORBIDDEN',
        error: 'Forbidden: You do not have permission to reset another user password.',
      });
    }

    const cleanPassword = String(req.body?.newPassword || req.body?.password || '').trim();
    if (!cleanPassword || cleanPassword.length < 4) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 4 characters long.',
      });
    }

    const passwordHash = await hashPassword(cleanPassword);
    const targetEmail = req.body?.email ? String(req.body.email).trim().toLowerCase() : '';
    const targetUid = req.body?.userId ? String(req.body.userId).trim() : targetId;
    const currentToken = extractSessionToken(req);

    const existingCachedTarget = await lookupAuthoritativeUser(targetId, targetUid, targetEmail);
    if (existingCachedTarget && existingCachedTarget.role === 'Super Admin' && caller.role !== 'Super Admin') {
      return res.status(403).json({
        success: false,
        code: 'SUPER_ADMIN_PASSWORD_FORBIDDEN',
        error: 'Forbidden: Only a Super Admin can reset a Super Admin account password.',
      });
    }

    const db = getServerSupabase();
    if (!db) {
      if (existingCachedTarget) {
        indexUserInAuthCache(existingCachedTarget, passwordHash);
      } else if (isSelf) {
        indexUserInAuthCache(caller, passwordHash);
      }
      revokeAllSessionsForUser([targetId, targetUid, targetEmail], isSelf ? currentToken : null);
      recordDbAuditEvent({
        eventType: 'USER_PASSWORD_UPDATED',
        actorId: caller.id,
        actorName: caller.name,
        actorRole: caller.role,
        outcome: 'success',
        details: `Updated password in server auth cache for ${targetUid || targetId}.`,
      });
      return res.status(200).json({
        success: true,
        warning: 'Database is not configured on the server; updated server session cache only.',
      });
    }

    try {
      let existingSbUser: any = null;

      if (targetEmail) {
        const { data } = await db.from('users').select('id, email, name, role, uid').ilike('email', targetEmail).limit(1);
        if (Array.isArray(data) && data.length > 0) existingSbUser = data[0];
      }
      if (!existingSbUser && targetUid) {
        const { data } = await db.from('users').select('id, email, name, role, uid').eq('uid', targetUid).limit(1);
        if (Array.isArray(data) && data.length > 0) existingSbUser = data[0];
      }
      if (!existingSbUser && /^u-sb-(\d+)$/i.test(targetId)) {
        const numId = Number(targetId.replace(/^u-sb-/i, ''));
        const { data } = await db.from('users').select('id, email, name, role, uid').eq('id', numId).limit(1);
        if (Array.isArray(data) && data.length > 0) existingSbUser = data[0];
      }

      if (existingSbUser) {
        if (existingSbUser.role === 'Super Admin' && caller.role !== 'Super Admin') {
          return res.status(403).json({
            success: false,
            code: 'SUPER_ADMIN_PASSWORD_FORBIDDEN',
            error: 'Forbidden: Only a Super Admin can reset a Super Admin account password.',
          });
        }
        const updatePayload: any = {
          password: passwordHash,
          updated_at: new Date().toISOString(),
        };
        let lastErr: any = null;
        for (let attempt = 0; attempt < 4; attempt++) {
          const { error } = await db.from('users').update(updatePayload).eq('id', existingSbUser.id);
          if (!error) {
            lastErr = null;
            break;
          }
          lastErr = error;
          if (!stripMissingColumnFromPayload(updatePayload, error.message || '')) break;
        }
        if (lastErr) {
          return res.status(400).json({
            success: false,
            error: sanitizeDatabaseError(lastErr.message),
          });
        }
        if (existingCachedTarget) {
          indexUserInAuthCache(existingCachedTarget, passwordHash);
        }
        revokeAllSessionsForUser(
          [targetId, targetUid, targetEmail, existingSbUser.uid, existingSbUser.email],
          isSelf ? currentToken : null
        );
        recordDbAuditEvent({
          eventType: 'USER_PASSWORD_UPDATED',
          actorId: caller.id,
          actorName: caller.name,
          actorRole: caller.role,
          outcome: 'success',
          details: `Updated password for user ${existingSbUser.email || targetUid || targetId}.`,
        });
        return res.status(200).json({ success: true });
      }

      if (!canAdminReset) {
        return res.status(404).json({
          success: false,
          error: 'Target user account not found in database.',
        });
      }

      const requestedRole = String(req.body?.role || 'Field Force').trim();
      const safeRole = requestedRole === 'Super Admin' && caller.role !== 'Super Admin' ? 'Field Force' : requestedRole;

      // Create missing user row with hashed password if not yet persisted (admin-only)
      const insertPayload: any = {
        name: req.body?.name || 'Ensec Staff',
        email: targetEmail || `${targetUid.toLowerCase()}@ensecbd.com`,
        password: passwordHash,
        phone: req.body?.phone || null,
        role: safeRole,
        designation: req.body?.designation || null,
        department: req.body?.department || 'Operations',
        status: req.body?.status || 'Active',
        uid: targetUid,
        permissions:
          caller.role === 'Super Admin' || hasPageAction(caller, 'users-permissions', 'assign_permissions')
            ? req.body?.permissions || {}
            : {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      let lastInsErr: any = null;
      for (let attempt = 0; attempt < 8; attempt++) {
        const { error } = await db.from('users').upsert(insertPayload, { onConflict: 'email' });
        if (!error) {
          lastInsErr = null;
          break;
        }
        lastInsErr = error;
        if (!stripMissingColumnFromPayload(insertPayload, error.message || '')) break;
      }
      if (lastInsErr) {
        return res.status(400).json({
          success: false,
          error: sanitizeDatabaseError(lastInsErr.message),
        });
      }
      recordDbAuditEvent({
        eventType: 'USER_PASSWORD_UPDATED',
        actorId: caller.id,
        actorName: caller.name,
        actorRole: caller.role,
        outcome: 'success',
        details: `Created/updated credentials for user ${insertPayload.email}.`,
      });
      return res.status(200).json({ success: true });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        error: sanitizeDatabaseError(err?.message || 'Failed to update password.'),
      });
    }
  });
}
