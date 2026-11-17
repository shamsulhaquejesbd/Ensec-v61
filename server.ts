import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import {
  getServerSupabase,
  getPublicSafeDatabaseSummary,
  checkServerDatabaseStatus,
  verifyDatabaseSchema,
  getDbAuditEvents,
  recordDbAuditEvent,
  registerDbSwitchCacheResetHook,
  sanitizeDatabaseError,
} from './server/db/index.ts';
import {
  CSRF_COOKIE_NAME,
  SESSION_COOKIE_NAME,
  extractSessionToken,
  createSessionForUser,
  parseCookies,
  revokeSessionToken,
  revokeAllSessionsForUser,
  setSessionCookie,
  clearSessionCookie,
  findRawUserRecordByIdentifier,
  verifyPasswordAndMigrateHash,
  sanitizeUserForClient,
  hashPassword,
  indexUserInAuthCache,
  clearUserLookupCache,
  resolveRequestUser,
} from './server/auth/authService.ts';
import { registerEventsRoutes, emitErpTableEvent } from './server/routes/events.ts';
import { registerErpGatewayRoutes } from './server/routes/erpGateway.ts';
import { registerDatabaseMigrationRoutes } from './server/routes/databaseMigrationRoutes.ts';
import { registerSystemSettingsRoutes } from './server/routes/systemSettingsRoutes.ts';
import { hasPageAction } from './src/types/pagePermissions.ts';
import {
  DEFAULT_ALLOWED_RADIUS_METERS,
  DEFAULT_GRACE_PERIOD_MINUTES,
  DEFAULT_MAX_GPS_ACCURACY_METERS,
  DEFAULT_OFFICE_LOCATIONS,
  DEFAULT_SHIFT_START_TIME,
  calculateShiftAttendanceStatus,
  evaluateGeofenceAttendance,
  isValidCoordinatePair,
} from './src/lib/geofence.ts';
import type {
  AttendanceRecord,
  OfficeLocation,
  RejectedAttendanceAttempt,
} from './src/types/payroll.ts';
import type { FieldForceRep } from './src/types/erp.ts';
import {
  resolveEmployeeForERPUser,
  verifyTransactionIdentityMatchesUser,
  type ResolvedMobileEmployeeProfile,
} from './src/lib/fieldForceAuth.ts';
import {
  authorizeCostSheetForUser,
  resolveManufacturingCostPermissions,
  sanitizeMaterialIssueContextForUser,
  sanitizeMaterialIssueRecordForUser,
  sanitizeProductionOrderForUser,
} from './src/lib/manufacturingPermissions.ts';
import {
  authorizeOvertimeSubPage,
  resolveOvertimePermissions,
  sanitizeOvertimeRecordForUser,
} from './src/lib/overtimePermissions.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Centralized server-side Supabase client accessor (configured strictly via server env vars)
const getDb = () => getServerSupabase();

// Authoritative server-side stores (hydrated from Supabase if available + synced from client)
const officeLocationsStore = new Map<string, OfficeLocation>(
  DEFAULT_OFFICE_LOCATIONS.map((loc) => [loc.id, loc])
);
const attendanceRecordsStore = new Map<string, AttendanceRecord>(); // key: `${employeeId}_${date}`
const rejectedAttemptsStore: RejectedAttendanceAttempt[] = [];
const lastEmployeeGpsPing = new Map<
  string,
  { latitude: number; longitude: number; timestampMs: number }
>();

interface ResolvedOfficeConfig {
  assignedOfficeId: string;
  assignedOfficeName: string;
  officeAddress: string;
  officeLatitude: number;
  officeLongitude: number;
  allowedRadiusMeters: number;
  locationStatus: 'Active' | 'Inactive';
}

async function resolveOfficeForEmployee(body: any): Promise<ResolvedOfficeConfig> {
  // 1. Prefer server-stored office if assignedOfficeId exists
  const officeId = String(body.assignedOfficeId || body.officeId || '').trim();
  let storedOffice = officeId ? officeLocationsStore.get(officeId) : undefined;

  if (!storedOffice && getDb() && officeId) {
    try {
      const { data } = await getDb()
        .from('office_locations')
        .select('*')
        .eq('id', officeId)
        .maybeSingle();
      if (data) {
        storedOffice = {
          id: String(data.id),
          code: data.code || undefined,
          name: data.name,
          address: data.address,
          latitude: Number(data.latitude),
          longitude: Number(data.longitude),
          allowedRadiusMeters: Number(data.allowed_radius_meters) || DEFAULT_ALLOWED_RADIUS_METERS,
          status: data.status === 'Inactive' ? 'Inactive' : 'Active',
        };
        officeLocationsStore.set(storedOffice.id, storedOffice);
      }
    } catch {
      // Ignore if table not migrated yet
    }
  }

  // 2. Also inspect employee record from Supabase field_force_reps if available
  let dbRepOffice: Partial<ResolvedOfficeConfig> | null = null;
  if (getDb() && body.employeeId) {
    try {
      const empIdNum = Number(body.employeeId);
      const query = !isNaN(empIdNum)
        ? getDb().from('field_force_reps').select('*').eq('id', empIdNum).maybeSingle()
        : getDb()
            .from('field_force_reps')
            .select('*')
            .eq('code', body.employeeCode || body.employeeId)
            .maybeSingle();
      const { data: repRow } = await query;
      if (repRow && isValidCoordinatePair(Number(repRow.office_latitude), Number(repRow.office_longitude))) {
        dbRepOffice = {
          assignedOfficeId: repRow.assigned_office_id || officeId || 'custom',
          assignedOfficeName: repRow.assigned_office_name || 'Assigned Office',
          officeAddress: repRow.office_address || '',
          officeLatitude: Number(repRow.office_latitude),
          officeLongitude: Number(repRow.office_longitude),
          allowedRadiusMeters: Number(repRow.allowed_radius_meters) || DEFAULT_ALLOWED_RADIUS_METERS,
          locationStatus: repRow.location_status === 'Inactive' ? 'Inactive' : 'Active',
        };
      }
    } catch {
      // Ignore missing column errors
    }
  }

  const officeLatitude =
    dbRepOffice?.officeLatitude ??
    storedOffice?.latitude ??
    Number(body.officeLatitude);
  const officeLongitude =
    dbRepOffice?.officeLongitude ??
    storedOffice?.longitude ??
    Number(body.officeLongitude);

  const allowedRadiusMeters =
    Number(dbRepOffice?.allowedRadiusMeters) ||
    Number(storedOffice?.allowedRadiusMeters) ||
    Number(body.allowedRadiusMeters) ||
    DEFAULT_ALLOWED_RADIUS_METERS;

  const assignedOfficeId =
    dbRepOffice?.assignedOfficeId ||
    storedOffice?.id ||
    officeId ||
    'office-hq';

  const assignedOfficeName =
    dbRepOffice?.assignedOfficeName ||
    storedOffice?.name ||
    body.assignedOfficeName ||
    'Head Office';

  const officeAddress =
    dbRepOffice?.officeAddress ||
    storedOffice?.address ||
    body.officeAddress ||
    '';

  const locationStatus =
    dbRepOffice?.locationStatus ||
    storedOffice?.status ||
    (body.locationStatus === 'Inactive' ? 'Inactive' : 'Active');

  return {
    assignedOfficeId,
    assignedOfficeName,
    officeAddress,
    officeLatitude,
    officeLongitude,
    allowedRadiusMeters,
    locationStatus,
  };
}

function getTodayDateString(): string {
  return new Date().toISOString().slice(0, 10);
}

function getCurrentTimeHHmm(): string {
  const now = new Date();
  return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
}

function getCurrentTimeHHmmss(): string {
  const now = new Date();
  return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
}

async function persistRejectedAttempt(attempt: RejectedAttendanceAttempt) {
  rejectedAttemptsStore.unshift(attempt);
  if (rejectedAttemptsStore.length > 1000) {
    rejectedAttemptsStore.pop();
  }
  if (getDb()) {
    try {
      await getDb().from('attendance_rejected_attempts').insert({
        id: attempt.id,
        employee_id: attempt.employeeId,
        employee_code: attempt.employeeCode || null,
        employee_name: attempt.employeeName,
        department: attempt.department || null,
        designation: attempt.designation || null,
        assigned_office_id: attempt.assignedOfficeId || null,
        assigned_office_name: attempt.assignedOfficeName || null,
        office_latitude: attempt.officeLatitude ?? null,
        office_longitude: attempt.officeLongitude ?? null,
        allowed_radius_meters: attempt.allowedRadiusMeters,
        attempt_type: attempt.attemptType,
        attendance_date: attempt.attendanceDate,
        attempt_time: attempt.attemptTime,
        latitude: attempt.latitude ?? null,
        longitude: attempt.longitude ?? null,
        distance_meters: attempt.distanceMeters ?? null,
        gps_accuracy_meters: attempt.gpsAccuracyMeters ?? null,
        gps_validation_status: 'Rejected',
        rejection_reason: attempt.rejectionReason,
        device_info: attempt.deviceInfo || null,
      });
    } catch {
      // Non-fatal if table not yet created
    }
  }
}

async function persistAcceptedAttendance(record: AttendanceRecord) {
  const key = `${record.employeeId}_${record.date}`;
  attendanceRecordsStore.set(key, record);
  if (getDb()) {
    try {
      await getDb().from('employee_attendances').upsert(
        {
          id: record.id,
          employee_id: record.employeeId || record.fieldForceId || '',
          employee_code: record.employeeCode || '',
          employee_name: record.employeeName,
          department: record.department || null,
          designation: record.designation || null,
          date: record.date,
          status: record.status,
          in_time: record.inTime || record.checkInTime || null,
          out_time: record.outTime || record.checkOutTime || null,
          overtime_hours: record.overtimeHours || 0,
          work_hours: record.workHours || 0,
          late_duration_minutes: record.lateDurationMinutes ?? record.lateMinutes ?? 0,
          assigned_office_id: record.assignedOfficeId || null,
          assigned_office_name: record.assignedOfficeName || null,
          office_latitude: record.officeLatitude ?? null,
          office_longitude: record.officeLongitude ?? null,
          allowed_radius_meters: record.allowedRadiusMeters ?? DEFAULT_ALLOWED_RADIUS_METERS,
          check_in_latitude: record.checkInLatitude ?? null,
          check_in_longitude: record.checkInLongitude ?? null,
          check_in_distance_meters: record.checkInDistanceMeters ?? null,
          check_in_gps_accuracy_meters: record.checkInGpsAccuracyMeters ?? null,
          check_in_location_text: record.checkInLocationText || null,
          check_out_latitude: record.checkOutLatitude ?? null,
          check_out_longitude: record.checkOutLongitude ?? null,
          check_out_distance_meters: record.checkOutDistanceMeters ?? null,
          check_out_gps_accuracy_meters: record.checkOutGpsAccuracyMeters ?? null,
          check_out_location_text: record.checkOutLocationText || null,
          gps_validation_status: record.gpsValidationStatus || 'Accepted',
          validation_reason: record.validationReason || null,
          remarks: record.remarks || null,
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'employee_id,date' }
      );
    } catch {
      // Non-fatal if migration pending
    }
  }
}

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const BLOCKED_FORM_CONTENT_TYPES = ['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'];

const authFailureTracker = new Map<string, { count: number; windowStart: number }>();
const AUTH_FAILURE_WINDOW_MS = 15 * 60 * 1000;
const AUTH_FAILURE_MAX_ATTEMPTS = 25;

function getClientIpKey(req: express.Request): string {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0]?.trim();
  return xff || req.ip || req.socket?.remoteAddress || 'unknown';
}

function isAuthRateLimited(key: string): boolean {
  const rec = authFailureTracker.get(key);
  if (!rec) return false;
  if (Date.now() - rec.windowStart > AUTH_FAILURE_WINDOW_MS) {
    authFailureTracker.delete(key);
    return false;
  }
  return rec.count >= AUTH_FAILURE_MAX_ATTEMPTS;
}

function recordAuthFailure(key: string) {
  const now = Date.now();
  const rec = authFailureTracker.get(key);
  if (!rec || now - rec.windowStart > AUTH_FAILURE_WINDOW_MS) {
    authFailureTracker.set(key, { count: 1, windowStart: now });
  } else {
    rec.count += 1;
  }
}

function clearAuthFailures(key: string) {
  authFailureTracker.delete(key);
}

function addNormalizedHost(hosts: Set<string>, rawHost?: string) {
  const clean = String(rawHost || '').trim().toLowerCase();
  if (!clean) return;
  hosts.add(clean);
  const strippedDefaultPort = clean.replace(/:(443|80)$/, '');
  if (strippedDefaultPort) hosts.add(strippedDefaultPort);
}

function getAllowedServerHosts(req: express.Request): Set<string> {
  const hosts = new Set<string>();
  addNormalizedHost(hosts, String(req.headers['host'] || ''));
  addNormalizedHost(hosts, String(req.headers['x-forwarded-host'] || '').split(',')[0]);
  const forwardedHdr = String(req.headers['forwarded'] || '');
  const fwdHostMatch = forwardedHdr.match(/host=([^;,\s"]+)/i);
  if (fwdHostMatch?.[1]) {
    addNormalizedHost(hosts, fwdHostMatch[1]);
  }
  const appUrl = (process.env.APP_URL || '').trim();
  if (appUrl) {
    try {
      addNormalizedHost(hosts, new URL(appUrl).host);
    } catch {
      // Ignore invalid APP_URL
    }
  }
  return hosts;
}

function getAllowedCorsOrigins(): Set<string> {
  const origins = new Set<string>();
  const raw = [
    process.env.CORS_ALLOWED_ORIGINS || '',
    process.env.FRONTEND_URL || '',
  ]
    .join(',')
    .split(',');
  for (const item of raw) {
    const clean = item.trim().replace(/\/+$/, '').toLowerCase();
    if (!clean) continue;
    try {
      origins.add(new URL(clean).origin.toLowerCase());
    } catch {
      // Ignore malformed origin entries
    }
  }
  return origins;
}

export function createAppServer() {
  const app = express();
  app.set('trust proxy', true);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '4mb' }));

  // Host Header Validation + CSRF / Origin Protection + Explicit CORS Allowlist for /api/*
  app.use('/api', (req, res, next) => {
    const rawHost = String(req.headers['host'] || '').trim();
    if (!rawHost || /[\s@\\/]/.test(rawHost)) {
      return res.status(400).json({ ok: false, code: 'INVALID_HOST_HEADER', error: 'Invalid Host header.' });
    }

    const originHdr = String(req.headers['origin'] || '').trim();
    const allowedCorsOrigins = getAllowedCorsOrigins();
    let normalizedOrigin = '';
    if (originHdr) {
      try {
        normalizedOrigin = new URL(originHdr).origin.toLowerCase();
      } catch {
        normalizedOrigin = '';
      }
    }
    const isExplicitCorsOriginAllowed = Boolean(
      normalizedOrigin && allowedCorsOrigins.has(normalizedOrigin)
    );

    if (isExplicitCorsOriginAllowed) {
      res.setHeader('Access-Control-Allow-Origin', originHdr);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-CSRF-Token, X-ERP-Session-Token, X-Mobile-Portal'
      );
      res.setHeader('Vary', 'Origin');
    }

    if (req.method.toUpperCase() === 'OPTIONS') {
      if (isExplicitCorsOriginAllowed) {
        return res.status(204).end();
      }
      return res.status(403).json({
        ok: false,
        code: 'CORS_ORIGIN_FORBIDDEN',
        error: 'Forbidden: Preflight Origin is not allowed.',
      });
    }

    if (STATE_CHANGING_METHODS.has(req.method.toUpperCase())) {
      const secFetchSite = String(req.headers['sec-fetch-site'] || '').trim().toLowerCase();
      if (secFetchSite === 'cross-site' && !isExplicitCorsOriginAllowed) {
        return res.status(403).json({
          ok: false,
          code: 'CSRF_CROSS_SITE_BLOCKED',
          error: 'Forbidden: Cross-site state-changing requests are blocked.',
        });
      }

      const allowedHosts = getAllowedServerHosts(req);
      const refererHdr = String(req.headers['referer'] || '').trim();

      if (originHdr) {
        try {
          const originHost = new URL(originHdr).host.toLowerCase();
          if (!allowedHosts.has(originHost) && !isExplicitCorsOriginAllowed) {
            return res.status(403).json({
              ok: false,
              code: 'CSRF_ORIGIN_MISMATCH',
              error: 'Forbidden: Request Origin does not match server host.',
            });
          }
        } catch {
          return res.status(403).json({
            ok: false,
            code: 'CSRF_INVALID_ORIGIN',
            error: 'Forbidden: Invalid Origin header.',
          });
        }
      } else if (refererHdr) {
        try {
          const refUrl = new URL(refererHdr);
          const refHost = refUrl.host.toLowerCase();
          const refOrigin = refUrl.origin.toLowerCase();
          if (!allowedHosts.has(refHost) && !allowedCorsOrigins.has(refOrigin)) {
            return res.status(403).json({
              ok: false,
              code: 'CSRF_REFERER_MISMATCH',
              error: 'Forbidden: Request Referer does not match server host.',
            });
          }
        } catch {
          return res.status(403).json({
            ok: false,
            code: 'CSRF_INVALID_REFERER',
            error: 'Forbidden: Invalid Referer header.',
          });
        }
      }

      const cookies = parseCookies(req.headers.cookie);
      const hasSessionCookie = Boolean(cookies[SESSION_COOKIE_NAME]);
      const contentType = String(req.headers['content-type'] || '').toLowerCase();
      if (hasSessionCookie && contentType && BLOCKED_FORM_CONTENT_TYPES.some((ct) => contentType.startsWith(ct))) {
        return res.status(415).json({
          ok: false,
          code: 'CSRF_CONTENT_TYPE_BLOCKED',
          error: 'Unsupported Content-Type for authenticated API mutation.',
        });
      }

      const headerCsrf = String(req.headers['x-csrf-token'] || '').trim();
      const cookieCsrf = String(cookies[CSRF_COOKIE_NAME] || '').trim();
      if (hasSessionCookie && cookieCsrf && req.path !== '/auth/login') {
        const a = Buffer.from(headerCsrf, 'utf8');
        const b = Buffer.from(cookieCsrf, 'utf8');
        if (!headerCsrf || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
          return res.status(403).json({
            ok: false,
            code: 'CSRF_TOKEN_MISMATCH',
            error: 'Forbidden: Missing or invalid CSRF token.',
          });
        }
      }
    }

    next();
  });

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'ensec-erp-geofence-server' });
  });

  // --------------------------------------------------------------------------
  // Office Locations CRUD (Authenticated & RBAC Enforced)
  // --------------------------------------------------------------------------
  app.get('/api/office-locations', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canView =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'basic-data-warehouses', 'view') ||
      hasPageAction(caller, 'payroll', 'view') ||
      hasPageAction(caller, 'mobile-field', 'view') ||
      hasPageAction(caller, 'overtime-management', 'view') ||
      hasPageAction(caller, 'field-tracker', 'view') ||
      hasPageAction(caller, 'dashboard', 'view');
    if (!canView) {
      return res.status(403).json({ error: 'Forbidden: Missing permission to view office locations.' });
    }

    if (getDb()) {
      try {
        const { data, error } = await getDb()
          .from('office_locations')
          .select('*')
          .order('created_at', { ascending: true });
        if (!error && Array.isArray(data) && data.length > 0) {
          for (const row of data) {
            officeLocationsStore.set(String(row.id), {
              id: String(row.id),
              code: row.code || undefined,
              name: row.name || 'Office Location',
              address: row.address || '',
              latitude: Number(row.latitude),
              longitude: Number(row.longitude),
              allowedRadiusMeters: Number(row.allowed_radius_meters) || DEFAULT_ALLOWED_RADIUS_METERS,
              status: row.status === 'Inactive' ? 'Inactive' : 'Active',
              createdAt: row.created_at,
              updatedAt: row.updated_at,
            });
          }
        }
      } catch {}
    }
    res.json({ locations: Array.from(officeLocationsStore.values()) });
  });

  app.post('/api/office-locations/sync', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canSync =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'basic-data-warehouses', 'edit') ||
      hasPageAction(caller, 'payroll', 'edit');
    if (!canSync) {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions to sync office locations.' });
    }
    const locations = Array.isArray(req.body?.locations) ? req.body.locations : [];
    for (const loc of locations) {
      if (loc && loc.id && loc.name) {
        officeLocationsStore.set(String(loc.id), {
          id: String(loc.id),
          code: loc.code,
          name: String(loc.name),
          address: String(loc.address || ''),
          latitude: Number(loc.latitude),
          longitude: Number(loc.longitude),
          allowedRadiusMeters: Number(loc.allowedRadiusMeters) || DEFAULT_ALLOWED_RADIUS_METERS,
          status: loc.status === 'Inactive' ? 'Inactive' : 'Active',
        });
      }
    }
    res.json({ synced: officeLocationsStore.size, locations: Array.from(officeLocationsStore.values()) });
  });

  app.post('/api/office-locations', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canCreate =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'basic-data-warehouses', 'create') ||
      hasPageAction(caller, 'payroll', 'create') ||
      hasPageAction(caller, 'payroll', 'edit');
    if (!canCreate) {
      return res.status(403).json({ error: 'Forbidden: Missing permission to create office locations.' });
    }

    const { id, code, name, address, latitude, longitude, allowedRadiusMeters, status, skipSupabaseSync } = req.body || {};
    const lat = Number(latitude);
    const lng = Number(longitude);
    if (!name || !isValidCoordinatePair(lat, lng)) {
      return res.status(400).json({ error: 'Valid office name, latitude, and longitude are required.' });
    }
    const nowIso = new Date().toISOString();
    const normalizedCode = code && String(code).trim() ? String(code).trim() : undefined;
    const loc: OfficeLocation = {
      id: id ? String(id) : `office-${Date.now().toString().slice(-6)}`,
      code: normalizedCode,
      name: String(name).trim(),
      address: String(address || '').trim(),
      latitude: lat,
      longitude: lng,
      allowedRadiusMeters: Number(allowedRadiusMeters) > 0 ? Number(allowedRadiusMeters) : DEFAULT_ALLOWED_RADIUS_METERS,
      status: status === 'Inactive' ? 'Inactive' : 'Active',
      createdAt: nowIso,
      updatedAt: nowIso,
    };
    officeLocationsStore.set(loc.id, loc);
    if (getDb() && !skipSupabaseSync) {
      const { error } = await getDb().from('office_locations').upsert(
        {
          id: loc.id,
          code: loc.code || null,
          name: loc.name,
          address: loc.address,
          latitude: loc.latitude,
          longitude: loc.longitude,
          allowed_radius_meters: loc.allowedRadiusMeters,
          status: loc.status,
          created_at: nowIso,
          updated_at: loc.updatedAt,
        },
        { onConflict: 'id' }
      );
      if (error) {
        return res.status(400).json({ error: sanitizeDatabaseError(error.message) });
      }
    }
    emitErpTableEvent({ table: 'office_locations', eventType: 'INSERT', newRow: loc });
    return res.status(201).json({ location: loc });
  });

  app.put('/api/office-locations/:id', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canEdit =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'basic-data-warehouses', 'edit') ||
      hasPageAction(caller, 'payroll', 'edit');
    if (!canEdit) {
      return res.status(403).json({ error: 'Forbidden: Missing permission to update office locations.' });
    }

    const locId = String(req.params.id);
    const existing = officeLocationsStore.get(locId);
    const body = req.body || {};
    const lat = body.latitude !== undefined ? Number(body.latitude) : existing?.latitude;
    const lng = body.longitude !== undefined ? Number(body.longitude) : existing?.longitude;
    if (!isValidCoordinatePair(lat, lng)) {
      return res.status(400).json({ error: 'Valid office latitude and longitude are required.' });
    }
    const normalizedCode =
      body.code !== undefined
        ? body.code && String(body.code).trim()
          ? String(body.code).trim()
          : undefined
        : existing?.code;
    const updated: OfficeLocation = {
      id: locId,
      code: normalizedCode,
      name: String(body.name ?? existing?.name ?? 'Office Location').trim(),
      address: String(body.address ?? existing?.address ?? '').trim(),
      latitude: lat!,
      longitude: lng!,
      allowedRadiusMeters:
        Number(body.allowedRadiusMeters ?? existing?.allowedRadiusMeters) || DEFAULT_ALLOWED_RADIUS_METERS,
      status: (body.status ?? existing?.status) === 'Inactive' ? 'Inactive' : 'Active',
      createdAt: existing?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    officeLocationsStore.set(locId, updated);
    if (getDb() && !body.skipSupabaseSync) {
      const { error } = await getDb().from('office_locations').upsert(
        {
          id: updated.id,
          code: updated.code || null,
          name: updated.name,
          address: updated.address,
          latitude: updated.latitude,
          longitude: updated.longitude,
          allowed_radius_meters: updated.allowedRadiusMeters,
          status: updated.status,
          updated_at: updated.updatedAt,
        },
        { onConflict: 'id' }
      );
      if (error) {
        return res.status(400).json({ error: sanitizeDatabaseError(error.message) });
      }
    }
    emitErpTableEvent({ table: 'office_locations', eventType: 'UPDATE', newRow: updated });
    return res.json({ location: updated });
  });

  app.delete('/api/office-locations/:id', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canDelete =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'basic-data-warehouses', 'delete') ||
      hasPageAction(caller, 'payroll', 'edit');
    if (!canDelete) {
      return res.status(403).json({ error: 'Forbidden: Missing permission to delete office locations.' });
    }

    const locId = String(req.params.id);
    officeLocationsStore.delete(locId);
    if (getDb() && req.query.skipSupabaseSync !== '1') {
      const { error } = await getDb().from('office_locations').delete().eq('id', locId);
      if (error) {
        return res.status(400).json({ error: sanitizeDatabaseError(error.message) });
      }
    }
    emitErpTableEvent({ table: 'office_locations', eventType: 'DELETE', oldRow: { id: locId } });
    res.json({ deleted: true, id: locId });
  });

  // --------------------------------------------------------------------------
  // Dry-Run GPS Distance Validation Endpoint (Authenticated)
  // --------------------------------------------------------------------------
  app.post('/api/attendance/validate', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const body = req.body || {};
    const office = await resolveOfficeForEmployee(body);
    const result = evaluateGeofenceAttendance({
      employeeLatitude: Number(body.latitude),
      employeeLongitude: Number(body.longitude),
      gpsAccuracyMeters:
        body.accuracy !== undefined && body.accuracy !== null ? Number(body.accuracy) : undefined,
      officeLatitude: office.officeLatitude,
      officeLongitude: office.officeLongitude,
      allowedRadiusMeters: office.allowedRadiusMeters,
      locationStatus: office.locationStatus,
      maxGpsAccuracyMeters: Number(body.maxGpsAccuracyMeters) || DEFAULT_MAX_GPS_ACCURACY_METERS,
    });
    res.json({
      ...result,
      office,
    });
  });

  // --------------------------------------------------------------------------
  // Authoritative Attendance Check-In (Authenticated ERP User + Geofence Validation)
  // --------------------------------------------------------------------------
  app.post('/api/attendance/check-in', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        accepted: false,
        errorCode: 'UNAUTHORIZED',
        reason: 'Authentication required. Please sign in to Ensec ERP before marking attendance.',
      });
    }

    const resolvedEmployee = await resolveEmployeeProfileForCaller(caller);
    if (!resolvedEmployee) {
      return res.status(403).json({
        accepted: false,
        errorCode: 'EMPLOYEE_UNRESOLVED',
        reason: 'Unable to resolve an active employee profile for this ERP user.',
      });
    }

    const body = req.body || {};
    const isMobileSource =
      req.headers['x-mobile-portal'] === 'true' || body.source === 'mobile-field';

    if (isMobileSource || !['Super Admin', 'HR', 'Admin'].includes(String(caller.role || ''))) {
      const identityCheck = verifyTransactionIdentityMatchesUser(
        {
          userId: body.userId,
          employeeId: body.employeeId,
          fieldForceId: body.fieldForceId,
          employeeCode: body.employeeCode,
          salespersonId: body.salespersonId,
          assignedSalespersonId: body.assignedSalespersonId,
          repId: body.repId,
          ffCode: body.ffCode,
          employee: body.employee && typeof body.employee === 'object' ? body.employee : undefined,
        },
        resolvedEmployee
      );
      if (!identityCheck.valid) {
        return res.status(403).json({
          accepted: false,
          errorCode: 'IDENTITY_MISMATCH',
          reason: identityCheck.reason,
        });
      }
    }

    const employeeId = isMobileSource
      ? resolvedEmployee.employeeId
      : String(body.employeeId || resolvedEmployee.employeeId).trim();
    const employeeCode = isMobileSource
      ? resolvedEmployee.employeeCode
      : String(body.employeeCode || resolvedEmployee.employeeCode).trim();
    const employeeName = isMobileSource
      ? resolvedEmployee.name
      : String(body.employeeName || resolvedEmployee.name).trim();
    if (!employeeId || !employeeName) {
      return res.status(400).json({
        accepted: false,
        reason: 'Employee ID and Employee Name are required.',
      });
    }

    const bodyForOffice = {
      ...body,
      employeeId,
      employeeCode,
      employeeName,
      assignedOfficeId: body.assignedOfficeId || resolvedEmployee.assignedOfficeId,
    };

    const attendanceDate = String(body.date || getTodayDateString()).slice(0, 10);
    const checkInTime = String(body.checkInTime || getCurrentTimeHHmm());
    const attemptTime = getCurrentTimeHHmmss();
    const key = `${employeeId}_${attendanceDate}`;

    // Check duplicate check-in on server store (and optional client existing record marker)
    const existing = attendanceRecordsStore.get(key);
    if ((existing && (existing.checkInTime || existing.inTime) && existing.gpsValidationStatus === 'Accepted') || body.hasExistingCheckIn) {
      return res.status(409).json({
        accepted: false,
        errorCode: 'DUPLICATE_CHECK_IN',
        reason: `Duplicate Check-In blocked: ${employeeName} has already checked in for ${attendanceDate}.`,
      });
    }

    const office = await resolveOfficeForEmployee(bodyForOffice);
    const empLat = Number(body.latitude);
    const empLng = Number(body.longitude);
    const gpsAccuracy =
      body.accuracy !== undefined && body.accuracy !== null ? Number(body.accuracy) : undefined;
    const prevPing = lastEmployeeGpsPing.get(employeeId);

    const validation = evaluateGeofenceAttendance({
      employeeLatitude: empLat,
      employeeLongitude: empLng,
      gpsAccuracyMeters: gpsAccuracy,
      officeLatitude: office.officeLatitude,
      officeLongitude: office.officeLongitude,
      allowedRadiusMeters: office.allowedRadiusMeters,
      locationStatus: office.locationStatus,
      maxGpsAccuracyMeters: Number(body.maxGpsAccuracyMeters) || DEFAULT_MAX_GPS_ACCURACY_METERS,
      previousCheckPoint: prevPing,
      currentTimestampMs: Date.now(),
    });

    if (!validation.accepted) {
      const rejectedAttempt: RejectedAttendanceAttempt = {
        id: `att-rej-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        employeeId,
        employeeCode: body.employeeCode ? String(body.employeeCode) : undefined,
        employeeName,
        department: body.department ? String(body.department) : undefined,
        designation: body.designation ? String(body.designation) : undefined,
        assignedOfficeId: office.assignedOfficeId,
        assignedOfficeName: office.assignedOfficeName,
        officeLatitude: isValidCoordinatePair(office.officeLatitude, office.officeLongitude)
          ? office.officeLatitude
          : undefined,
        officeLongitude: isValidCoordinatePair(office.officeLatitude, office.officeLongitude)
          ? office.officeLongitude
          : undefined,
        allowedRadiusMeters: validation.allowedRadiusMeters,
        attemptType: 'Check In',
        attendanceDate,
        attemptTime,
        latitude: Number.isFinite(empLat) ? empLat : undefined,
        longitude: Number.isFinite(empLng) ? empLng : undefined,
        distanceMeters: validation.distanceMeters,
        gpsAccuracyMeters: gpsAccuracy,
        gpsValidationStatus: 'Rejected',
        rejectionReason: validation.reason,
        deviceInfo: body.deviceInfo ? String(body.deviceInfo) : req.headers['user-agent'],
        createdAt: new Date().toISOString(),
      };
      await persistRejectedAttempt(rejectedAttempt);
      return res.status(403).json({
        accepted: false,
        errorCode: validation.errorCode,
        distanceMeters: validation.distanceMeters,
        allowedRadiusMeters: validation.allowedRadiusMeters,
        gpsValidationStatus: 'Rejected',
        reason: validation.reason,
        rejectedAttempt,
      });
    }

    lastEmployeeGpsPing.set(employeeId, {
      latitude: empLat,
      longitude: empLng,
      timestampMs: Date.now(),
    });

    const shiftCalc = calculateShiftAttendanceStatus({
      checkInTime,
      shiftStartTime: body.shiftStartTime || DEFAULT_SHIFT_START_TIME,
      gracePeriodMinutes:
        body.gracePeriodMinutes !== undefined
          ? Number(body.gracePeriodMinutes)
          : DEFAULT_GRACE_PERIOD_MINUTES,
      standardDailyHours: Number(body.standardDailyHours) || 8,
    });

    const nowIso = new Date().toISOString();
    const record: AttendanceRecord = {
      id: `att-${Date.now().toString().slice(-6)}-${Math.random().toString(36).slice(2, 5)}`,
      userId: caller.id,
      fieldForceId: employeeId,
      employeeId,
      employeeCode: employeeCode || undefined,
      employeeName,
      employeeCategory: body.employeeCategory,
      department: body.department ? String(body.department) : resolvedEmployee.department || 'Operations',
      designation: body.designation ? String(body.designation) : resolvedEmployee.designation,
      date: attendanceDate,
      status: shiftCalc.status,
      inTime: checkInTime,
      checkInTime,
      isLate: shiftCalc.isLate,
      lateMinutes: shiftCalc.lateDurationMinutes,
      lateDurationMinutes: shiftCalc.lateDurationMinutes,
      workHours: 0,
      overtimeHours: 0,
      assignedOfficeId: office.assignedOfficeId,
      assignedOfficeName: office.assignedOfficeName,
      officeLatitude: office.officeLatitude,
      officeLongitude: office.officeLongitude,
      allowedRadiusMeters: validation.allowedRadiusMeters,
      checkInLatitude: empLat,
      checkInLongitude: empLng,
      checkInDistanceMeters: validation.distanceMeters,
      checkInGpsAccuracyMeters: gpsAccuracy,
      checkInLocationText: `${empLat.toFixed(6)}, ${empLng.toFixed(6)}`,
      gpsValidationStatus: 'Accepted',
      validationReason: validation.reason,
      remarks: `GPS Check-In Accepted (${validation.distanceMeters}m from ${office.assignedOfficeName})`,
      recordedBy: caller.name || 'Mobile GPS Geofence',
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    await persistAcceptedAttendance(record);

    return res.status(200).json({
      accepted: true,
      distanceMeters: validation.distanceMeters,
      allowedRadiusMeters: validation.allowedRadiusMeters,
      gpsValidationStatus: 'Accepted',
      reason: validation.reason,
      record,
    });
  });

  // --------------------------------------------------------------------------
  // Authoritative Attendance Check-Out (Authenticated ERP User + GPS Validation)
  // --------------------------------------------------------------------------
  app.post('/api/attendance/check-out', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        accepted: false,
        errorCode: 'UNAUTHORIZED',
        reason: 'Authentication required. Please sign in to Ensec ERP before checking out.',
      });
    }

    const resolvedEmployee = await resolveEmployeeProfileForCaller(caller);
    if (!resolvedEmployee) {
      return res.status(403).json({
        accepted: false,
        errorCode: 'EMPLOYEE_UNRESOLVED',
        reason: 'Unable to resolve an active employee profile for this ERP user.',
      });
    }

    const body = req.body || {};
    const isMobileSource =
      req.headers['x-mobile-portal'] === 'true' || body.source === 'mobile-field';

    if (isMobileSource || !['Super Admin', 'HR', 'Admin'].includes(String(caller.role || ''))) {
      const identityCheck = verifyTransactionIdentityMatchesUser(
        {
          userId: body.userId,
          employeeId: body.employeeId,
          fieldForceId: body.fieldForceId,
          employeeCode: body.employeeCode,
          salespersonId: body.salespersonId,
          assignedSalespersonId: body.assignedSalespersonId,
          repId: body.repId,
          ffCode: body.ffCode,
          employee: body.employee && typeof body.employee === 'object' ? body.employee : undefined,
        },
        resolvedEmployee
      );
      if (!identityCheck.valid) {
        return res.status(403).json({
          accepted: false,
          errorCode: 'IDENTITY_MISMATCH',
          reason: identityCheck.reason,
        });
      }
    }

    const employeeId = isMobileSource
      ? resolvedEmployee.employeeId
      : String(body.employeeId || resolvedEmployee.employeeId).trim();
    const employeeCode = isMobileSource
      ? resolvedEmployee.employeeCode
      : String(body.employeeCode || resolvedEmployee.employeeCode).trim();
    const employeeName = isMobileSource
      ? resolvedEmployee.name
      : String(body.employeeName || resolvedEmployee.name).trim();
    if (!employeeId || !employeeName) {
      return res.status(400).json({
        accepted: false,
        reason: 'Employee ID and Employee Name are required.',
      });
    }

    const attendanceDate = String(body.date || getTodayDateString()).slice(0, 10);
    const checkOutTime = String(body.checkOutTime || getCurrentTimeHHmm());
    const attemptTime = getCurrentTimeHHmmss();
    const key = `${employeeId}_${attendanceDate}`;

    // Reconcile existing check-in from server store or client-synced existingRecord
    const existing: AttendanceRecord | undefined =
      attendanceRecordsStore.get(key) ||
      (body.existingRecord && body.existingRecord.date === attendanceDate
        ? (body.existingRecord as AttendanceRecord)
        : undefined);

    if (!existing || !(existing.checkInTime || existing.inTime) || existing.status === 'Absent') {
      return res.status(400).json({
        accepted: false,
        errorCode: 'NO_CHECK_IN',
        reason: `Cannot Check Out: No valid Check-In record found for ${employeeName} on ${attendanceDate}.`,
      });
    }

    if (existing.checkOutTime || existing.outTime) {
      return res.status(409).json({
        accepted: false,
        errorCode: 'DUPLICATE_CHECK_OUT',
        reason: `Duplicate Check-Out blocked: ${employeeName} has already checked out on ${attendanceDate} at ${existing.checkOutTime || existing.outTime}.`,
      });
    }

    const office = await resolveOfficeForEmployee({
      ...body,
      employeeId,
      employeeCode,
      employeeName,
      assignedOfficeId: body.assignedOfficeId || resolvedEmployee.assignedOfficeId,
    });
    const empLat = Number(body.latitude);
    const empLng = Number(body.longitude);
    const gpsAccuracy =
      body.accuracy !== undefined && body.accuracy !== null ? Number(body.accuracy) : undefined;
    const prevPing = lastEmployeeGpsPing.get(employeeId);

    const validation = evaluateGeofenceAttendance({
      employeeLatitude: empLat,
      employeeLongitude: empLng,
      gpsAccuracyMeters: gpsAccuracy,
      officeLatitude: office.officeLatitude,
      officeLongitude: office.officeLongitude,
      allowedRadiusMeters: office.allowedRadiusMeters,
      locationStatus: office.locationStatus,
      maxGpsAccuracyMeters: Number(body.maxGpsAccuracyMeters) || DEFAULT_MAX_GPS_ACCURACY_METERS,
      previousCheckPoint: prevPing,
      currentTimestampMs: Date.now(),
    });

    if (!validation.accepted) {
      const rejectedAttempt: RejectedAttendanceAttempt = {
        id: `att-rej-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        employeeId,
        employeeCode: body.employeeCode ? String(body.employeeCode) : existing.employeeCode,
        employeeName,
        department: body.department ? String(body.department) : existing.department,
        designation: body.designation ? String(body.designation) : existing.designation,
        assignedOfficeId: office.assignedOfficeId,
        assignedOfficeName: office.assignedOfficeName,
        officeLatitude: isValidCoordinatePair(office.officeLatitude, office.officeLongitude)
          ? office.officeLatitude
          : undefined,
        officeLongitude: isValidCoordinatePair(office.officeLatitude, office.officeLongitude)
          ? office.officeLongitude
          : undefined,
        allowedRadiusMeters: validation.allowedRadiusMeters,
        attemptType: 'Check Out',
        attendanceDate,
        attemptTime,
        latitude: Number.isFinite(empLat) ? empLat : undefined,
        longitude: Number.isFinite(empLng) ? empLng : undefined,
        distanceMeters: validation.distanceMeters,
        gpsAccuracyMeters: gpsAccuracy,
        gpsValidationStatus: 'Rejected',
        rejectionReason: validation.reason,
        deviceInfo: body.deviceInfo ? String(body.deviceInfo) : req.headers['user-agent'],
        createdAt: new Date().toISOString(),
      };
      await persistRejectedAttempt(rejectedAttempt);
      return res.status(403).json({
        accepted: false,
        errorCode: validation.errorCode,
        distanceMeters: validation.distanceMeters,
        allowedRadiusMeters: validation.allowedRadiusMeters,
        gpsValidationStatus: 'Rejected',
        reason: validation.reason,
        rejectedAttempt,
      });
    }

    lastEmployeeGpsPing.set(employeeId, {
      latitude: empLat,
      longitude: empLng,
      timestampMs: Date.now(),
    });

    const checkInTimeStr = existing.checkInTime || existing.inTime || '09:00';
    const shiftCalc = calculateShiftAttendanceStatus({
      checkInTime: checkInTimeStr,
      checkOutTime,
      shiftStartTime: body.shiftStartTime || DEFAULT_SHIFT_START_TIME,
      gracePeriodMinutes:
        body.gracePeriodMinutes !== undefined
          ? Number(body.gracePeriodMinutes)
          : DEFAULT_GRACE_PERIOD_MINUTES,
      standardDailyHours: Number(body.standardDailyHours) || 8,
    });

    const updatedRecord: AttendanceRecord = {
      ...existing,
      outTime: checkOutTime,
      checkOutTime,
      workHours: shiftCalc.totalWorkingHours,
      overtimeHours: shiftCalc.overtimeHours,
      status: shiftCalc.status,
      isLate: existing.isLate ?? shiftCalc.isLate,
      lateMinutes: existing.lateMinutes ?? shiftCalc.lateDurationMinutes,
      lateDurationMinutes: existing.lateDurationMinutes ?? shiftCalc.lateDurationMinutes,
      checkOutLatitude: empLat,
      checkOutLongitude: empLng,
      checkOutDistanceMeters: validation.distanceMeters,
      checkOutGpsAccuracyMeters: gpsAccuracy,
      checkOutLocationText: `${empLat.toFixed(6)}, ${empLng.toFixed(6)}`,
      gpsValidationStatus: 'Accepted',
      validationReason: validation.reason,
      remarks: `${existing.remarks || ''} | Check-Out Accepted (${validation.distanceMeters}m)`.replace(/^\s*\|\s*/, ''),
      updatedAt: new Date().toISOString(),
    };

    await persistAcceptedAttendance(updatedRecord);

    return res.status(200).json({
      accepted: true,
      distanceMeters: validation.distanceMeters,
      allowedRadiusMeters: validation.allowedRadiusMeters,
      gpsValidationStatus: 'Accepted',
      reason: validation.reason,
      record: updatedRecord,
    });
  });

  app.get('/api/attendance/records', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canView =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'payroll', 'view') ||
      hasPageAction(caller, 'mobile-field', 'view') ||
      hasPageAction(caller, 'field-tracker', 'view');
    if (!canView) {
      return res.status(403).json({ error: 'Forbidden: Attendance view permission required.' });
    }
    res.json({
      records: Array.from(attendanceRecordsStore.values()),
      rejectedAttempts: rejectedAttemptsStore,
    });
  });

  app.post('/api/attendance/sync', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canSync =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'payroll', 'create') ||
      hasPageAction(caller, 'payroll', 'edit');
    if (!canSync) {
      return res.status(403).json({ error: 'Forbidden: Attendance write permission required.' });
    }
    const records = Array.isArray(req.body?.records) ? req.body.records : [];
    for (const r of records) {
      if (r && r.employeeId && r.date) {
        attendanceRecordsStore.set(`${r.employeeId}_${r.date}`, r);
      }
    }
    res.json({ synced: attendanceRecordsStore.size });
  });

  // ============================================================================
  // ERP AUTHENTICATION, EMPLOYEE RESOLUTION & AUTHORIZED DOMAIN GATEWAYS
  // ============================================================================
  const fieldForceRepsCache = new Map<string, FieldForceRep>();
  const mfgOrdersCache = new Map<string, any>();
  const mfgIssuesCache = new Map<string, any>();
  const mfgRawMaterialsCache = new Map<string, any>();
  const mfgBatchesCache = new Map<string, any>();
  const overtimeRequestsCache = new Map<string, any>();
  const overtimeAttendancesCache = new Map<string, any>();
  const overtimePoliciesCache = new Map<string, any>();
  const mobileTransactionsStore = {
    orders: [] as any[],
    customers: [] as any[],
    tada: [] as any[],
    warranty: [] as any[],
    visits: [] as any[],
    leaves: [] as any[],
    crmLeads: [] as any[],
  };

  const indexFieldForceRepInCache = (rep: any) => {
    if (!rep || typeof rep !== 'object' || !rep.id) return;
    fieldForceRepsCache.set(String(rep.id), rep as FieldForceRep);
  };

  const mapSupabaseFieldForceRow = (row: any): FieldForceRep => ({
    id: String(row.id),
    userId: row.user_id ? String(row.user_id) : undefined,
    code: row.code || '',
    pin: row.pin || undefined,
    name: row.name || '',
    phone: row.phone || '',
    email: row.email || undefined,
    designation: row.designation || 'Territory Sales Officer',
    fieldForceType: row.field_force_type || undefined,
    department: row.department || undefined,
    region: row.region || '',
    area: row.area || '',
    territory: row.territory || '',
    branchWorkplace: row.branch_workplace || undefined,
    tadaApproverId: row.tada_approver_id || undefined,
    tadaApproverName: row.tada_approver_name || undefined,
    monthlyTargetBDT: Number(row.monthly_target_bdt) || 0,
    monthlyAchievedBDT: Number(row.monthly_achieved_bdt) || 0,
    assignedOfficeId: row.assigned_office_id || undefined,
    assignedOfficeName: row.assigned_office_name || row.branch_workplace || undefined,
    officeLatitude:
      row.office_latitude !== null && row.office_latitude !== undefined
        ? Number(row.office_latitude)
        : undefined,
    officeLongitude:
      row.office_longitude !== null && row.office_longitude !== undefined
        ? Number(row.office_longitude)
        : undefined,
    allowedRadiusMeters: Number(row.allowed_radius_meters) || undefined,
    officeAddress: row.office_address || undefined,
    locationStatus: row.location_status === 'Inactive' ? 'Inactive' : 'Active',
    shiftStartTime: row.shift_start_time || undefined,
    shiftEndTime: row.shift_end_time || undefined,
    gracePeriodMinutes:
      row.grace_period_minutes !== null && row.grace_period_minutes !== undefined
        ? Number(row.grace_period_minutes)
        : undefined,
    isActive: row.is_active !== false,
    status: row.is_active === false ? 'Inactive' : 'Active',
  });

  const resolveEmployeeProfileForCaller = async (
    caller: any
  ): Promise<ResolvedMobileEmployeeProfile | null> => {
    if (!caller) return null;
    const mergedMap = new Map<string, FieldForceRep>(fieldForceRepsCache);

    if (getDb()) {
      try {
        const { data } = await getDb()
          .from('field_force_reps')
          .select('*')
          .order('id', { ascending: true });
        if (Array.isArray(data)) {
          for (const row of data) {
            const mapped = mapSupabaseFieldForceRow(row);
            const cached = mergedMap.get(mapped.id);
            mergedMap.set(mapped.id, {
              ...mapped,
              ...(cached?.userId && !mapped.userId ? { userId: cached.userId } : {}),
            });
          }
        }
      } catch {
        // Use in-memory cache fallback
      }
    }

    return resolveEmployeeForERPUser(
      caller,
      Array.from(mergedMap.values()),
      Array.from(officeLocationsStore.values())
    );
  };

  const handleSyncContext = async (req: express.Request, res: express.Response) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ ok: false, error: 'Authentication required.' });
    }
    const body = req.body || {};
    // Only operational read caches (never users/passwords) may be hydrated when authenticated
    if (Array.isArray(body.fieldForceReps) && (caller.role === 'Super Admin' || hasPageAction(caller, 'basic-data-field-force', 'view') || hasPageAction(caller, 'mobile-field', 'view'))) {
      for (const rep of body.fieldForceReps) {
        indexFieldForceRepInCache(rep);
      }
    }
    if (Array.isArray(body.productionOrders) && (caller.role === 'Super Admin' || hasPageAction(caller, 'manufacturing', 'view'))) {
      for (const po of body.productionOrders) {
        if (po && (po.id || po.orderNumber)) {
          mfgOrdersCache.set(String(po.id || po.orderNumber), po);
        }
      }
    }
    if (Array.isArray(body.materialIssues) && (caller.role === 'Super Admin' || hasPageAction(caller, 'manufacturing', 'view'))) {
      for (const mi of body.materialIssues) {
        if (mi && (mi.id || mi.productionOrderId)) {
          mfgIssuesCache.set(String(mi.id || mi.productionOrderId), mi);
        }
      }
    }
    if (Array.isArray(body.rawMaterials) && (caller.role === 'Super Admin' || hasPageAction(caller, 'raw-material-inventory', 'view') || hasPageAction(caller, 'manufacturing', 'view'))) {
      for (const rm of body.rawMaterials) {
        if (rm && (rm.id || rm.code)) {
          mfgRawMaterialsCache.set(String(rm.id || rm.code), rm);
        }
      }
    }
    if (Array.isArray(body.inventoryBatches) && (caller.role === 'Super Admin' || hasPageAction(caller, 'raw-material-inventory', 'view') || hasPageAction(caller, 'manufacturing', 'view'))) {
      for (const b of body.inventoryBatches) {
        if (b && (b.id || b.batchNumber)) {
          mfgBatchesCache.set(String(b.id || b.batchNumber), b);
        }
      }
    }
    if (Array.isArray(body.overtimeRequests) && (caller.role === 'Super Admin' || hasPageAction(caller, 'overtime-management', 'view'))) {
      for (const reqItem of body.overtimeRequests) {
        if (reqItem && (reqItem.id || reqItem.requestNumber)) {
          overtimeRequestsCache.set(String(reqItem.id || reqItem.requestNumber), reqItem);
        }
      }
    }
    if (Array.isArray(body.overtimeAttendances) && (caller.role === 'Super Admin' || hasPageAction(caller, 'overtime-management', 'view'))) {
      for (const att of body.overtimeAttendances) {
        if (att && att.id) {
          overtimeAttendancesCache.set(String(att.id), att);
        }
      }
    }
    if (Array.isArray(body.overtimePolicies) && (caller.role === 'Super Admin' || hasPageAction(caller, 'overtime-management', 'view'))) {
      for (const pol of body.overtimePolicies) {
        if (pol && pol.id) {
          overtimePoliciesCache.set(String(pol.id), pol);
        }
      }
    }
    res.json({ ok: true });
  };

  app.post('/api/manufacturing/sync-state', handleSyncContext);
  app.post('/api/erp/sync-context', handleSyncContext);

  // Authoritative Backend Login (bcrypt + controlled plaintext->bcrypt migration + HttpOnly cookie)
  app.post('/api/auth/login', async (req, res) => {
    const body = req.body || {};
    const identifier = String(body.identifier || body.userId || body.email || '').trim();
    const password = String(body.password || '');

    if (!identifier) {
      return res.status(400).json({
        authenticated: false,
        code: 'MISSING_IDENTIFIER',
        error: 'Please enter your User ID or Email.',
      });
    }
    if (!password) {
      return res.status(400).json({
        authenticated: false,
        code: 'MISSING_PASSWORD',
        error: 'Please enter your Password.',
      });
    }

    const rateKey = `login:${getClientIpKey(req)}:${identifier.toLowerCase()}`;
    if (isAuthRateLimited(rateKey)) {
      return res.status(429).json({
        authenticated: false,
        code: 'TOO_MANY_ATTEMPTS',
        error: 'Too many failed login attempts. Please try again later.',
      });
    }

    const found = await findRawUserRecordByIdentifier(identifier);
    if (!found.user) {
      if (found.lookupStatus === 'db_unconfigured') {
        return res.status(503).json({
          authenticated: false,
          code: 'DATABASE_NOT_CONFIGURED',
          error:
            'Database authentication service is not configured on this server (missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY). Please configure server environment secrets or sign in via the configured app environment.',
        });
      }
      if (found.lookupStatus === 'db_error') {
        return res.status(503).json({
          authenticated: false,
          code: 'DATABASE_AUTH_UNAVAILABLE',
          error: `Unable to reach user directory database (${found.lookupError || 'query failed'}). Verify SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY on the server.`,
        });
      }
      recordAuthFailure(rateKey);
      return res.status(401).json({
        authenticated: false,
        code: found.lookupStatus === 'db_empty' ? 'USER_DIRECTORY_EMPTY' : 'INVALID_CREDENTIALS',
        error:
          found.lookupStatus === 'db_empty'
            ? 'Access Denied: No user accounts are registered in the database users table.'
            : 'Access Denied: Invalid User ID or Email. No registered account found.',
      });
    }

    if (found.user.status === 'Blocked' || found.user.status === 'Inactive') {
      return res.status(403).json({
        authenticated: false,
        code: 'ACCOUNT_INACTIVE',
        error: `Access Denied: This account is currently marked as ${found.user.status}. Contact your Administrator.`,
      });
    }

    const verification = await verifyPasswordAndMigrateHash({
      inputPassword: password,
      storedPassword: found.storedPassword,
      rawRow: found.rawRow,
      user: found.user,
    });

    if (!verification.valid) {
      recordAuthFailure(rateKey);
      recordDbAuditEvent({
        eventType: 'AUTH_LOGIN_FAILED',
        actorId: found.user.id,
        actorName: found.user.name,
        actorRole: found.user.role,
        outcome: 'error',
        details: `Failed login attempt for account ${found.user.userId}.`,
      });
      return res.status(401).json({
        authenticated: false,
        code: 'INVALID_PASSWORD',
        error: 'Access Denied: Incorrect password. Please try again.',
      });
    }

    clearAuthFailures(rateKey);

    // Rotate any existing session token to prevent session fixation
    const previousToken = extractSessionToken(req);
    const { token, expiresAt } = createSessionForUser(found.user, previousToken || null);
    const csrfToken = setSessionCookie(res, req, token);
    indexUserInAuthCache(found.user);

    const employee = await resolveEmployeeProfileForCaller(found.user);
    recordDbAuditEvent({
      eventType: 'AUTH_LOGIN_SUCCESS',
      actorId: found.user.id,
      actorName: found.user.name,
      actorRole: found.user.role,
      outcome: 'success',
      details: `Authenticated session established for ${found.user.userId}.`,
    });

    return res.status(200).json({
      authenticated: true,
      user: sanitizeUserForClient(found.user),
      employee,
      expiresAt,
      csrfToken,
    });
  });

  // Legacy client-supplied snapshot endpoint permanently disabled
  app.post('/api/auth/session', (_req, res) => {
    return res.status(410).json({
      authenticated: false,
      code: 'SNAPSHOT_SESSION_DISABLED',
      error: 'Client-supplied session snapshots are disabled. Please sign in via POST /api/auth/login.',
    });
  });

  app.post('/api/auth/change-password', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    const currentPassword = req.body?.currentPassword ? String(req.body.currentPassword) : '';
    const newPassword = String(req.body?.newPassword || '').trim();
    if (!currentPassword) {
      return res.status(400).json({ success: false, code: 'CURRENT_PASSWORD_REQUIRED', error: 'Current password is required.' });
    }
    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ success: false, error: 'New password must be at least 4 characters long.' });
    }

    const found = await findRawUserRecordByIdentifier(caller.userId || caller.email || caller.id);
    if (!found.user) {
      return res.status(404).json({ success: false, error: 'Authenticated account could not be resolved.' });
    }

    const check = await verifyPasswordAndMigrateHash({
      inputPassword: currentPassword,
      storedPassword: found.storedPassword,
      rawRow: found.rawRow,
      user: found.user,
    });
    if (!check.valid) {
      return res.status(403).json({ success: false, error: 'Current password is incorrect.' });
    }

    const newHash = await hashPassword(newPassword);
    indexUserInAuthCache(caller, newHash);
    if (getDb() && found.rawRow) {
      const { error } = await getDb()
        .from('users')
        .update({ password: newHash, updated_at: new Date().toISOString() })
        .eq('id', found.rawRow.id);
      if (error) {
        return res.status(400).json({ success: false, error: sanitizeDatabaseError(error.message) });
      }
    }

    // Rotate active session token & revoke any older sessions for this user
    const previousToken = extractSessionToken(req);
    const { token } = createSessionForUser(caller, previousToken || null);
    revokeAllSessionsForUser([caller.id, caller.userId, caller.email], token);
    const csrfToken = setSessionCookie(res, req, token);

    recordDbAuditEvent({
      eventType: 'PASSWORD_CHANGED',
      actorId: caller.id,
      actorName: caller.name,
      actorRole: caller.role,
      outcome: 'success',
      details: `User ${caller.userId} changed their password and rotated active sessions.`,
    });

    return res.status(200).json({ success: true, csrfToken });
  });

  app.post('/api/auth/reset-password', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const identifier = String(req.body?.identifier || '').trim();
    const currentPassword = String(req.body?.currentPassword || '');
    const newPassword = String(req.body?.newPassword || '').trim();

    if (!identifier || !newPassword || newPassword.length < 4) {
      return res.status(400).json({
        success: false,
        error: 'Valid User ID/Email and a new password (min 4 characters) are required.',
      });
    }

    const rateKey = `reset:${getClientIpKey(req)}:${identifier.toLowerCase()}`;
    if (isAuthRateLimited(rateKey)) {
      return res.status(429).json({
        success: false,
        code: 'TOO_MANY_ATTEMPTS',
        error: 'Too many failed password reset attempts. Please try again later.',
      });
    }

    const found = await findRawUserRecordByIdentifier(identifier);
    if (!found.user) {
      if (found.lookupStatus === 'db_unconfigured' || found.lookupStatus === 'db_error') {
        return res.status(503).json({
          success: false,
          code: 'DATABASE_AUTH_UNAVAILABLE',
          error:
            found.lookupError ||
            'Database authentication service is not configured on this server.',
        });
      }
      recordAuthFailure(rateKey);
      return res.status(404).json({
        success: false,
        error: `Account "${identifier}" not found.`,
      });
    }

    const isAdminReset =
      caller &&
      (caller.role === 'Super Admin' ||
        hasPageAction(caller, 'users-permissions', 'reset_password') ||
        hasPageAction(caller, 'users-permissions', 'edit'));

    if (isAdminReset && found.user.role === 'Super Admin' && caller.role !== 'Super Admin') {
      return res.status(403).json({
        success: false,
        code: 'SUPER_ADMIN_PASSWORD_FORBIDDEN',
        error: 'Forbidden: Only a Super Admin can reset a Super Admin account password.',
      });
    }

    if (!isAdminReset) {
      if (!currentPassword) {
        return res.status(403).json({
          success: false,
          code: 'PASSWORD_RESET_AUTHORIZATION_REQUIRED',
          error:
            'Self-service password change requires your Current Password, or ask your System Administrator to reset it in User Management.',
        });
      }
      const verified = await verifyPasswordAndMigrateHash({
        inputPassword: currentPassword,
        storedPassword: found.storedPassword,
        rawRow: found.rawRow,
        user: found.user,
      });
      if (!verified.valid) {
        recordAuthFailure(rateKey);
        return res.status(403).json({
          success: false,
          error: 'Current password verification failed.',
        });
      }
    }

    clearAuthFailures(rateKey);

    const newHash = await hashPassword(newPassword);
    indexUserInAuthCache(found.user, newHash);
    if (getDb() && found.rawRow) {
      const { error } = await getDb()
        .from('users')
        .update({ password: newHash, updated_at: new Date().toISOString() })
        .eq('id', found.rawRow.id);
      if (error) {
        return res.status(400).json({ success: false, error: sanitizeDatabaseError(error.message) });
      }
    }

    revokeAllSessionsForUser([found.user.id, found.user.userId, found.user.email]);
    recordDbAuditEvent({
      eventType: 'PASSWORD_CHANGED',
      actorId: caller?.id || found.user.id,
      actorName: caller?.name || found.user.name,
      actorRole: caller?.role || found.user.role,
      outcome: 'success',
      details: `Password reset completed for account ${found.user.userId}.`,
    });

    return res.status(200).json({ success: true });
  });

  app.get('/api/auth/me', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        authenticated: false,
        error: 'Session expired or not authenticated.',
      });
    }
    const employee = await resolveEmployeeProfileForCaller(caller);
    const cookies = parseCookies(req.headers.cookie);
    const csrfToken = cookies[CSRF_COOKIE_NAME] || undefined;
    return res.status(200).json({
      authenticated: true,
      user: sanitizeUserForClient(caller),
      employee,
      ...(csrfToken ? { csrfToken } : {}),
    });
  });

  app.post('/api/auth/logout', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const token = extractSessionToken(req) || String(req.body?.token || '').trim();
    if (token) {
      revokeSessionToken(token);
    }
    if (caller) {
      recordDbAuditEvent({
        eventType: 'AUTH_LOGOUT',
        actorId: caller.id,
        actorName: caller.name,
        actorRole: caller.role,
        outcome: 'success',
        details: `Session logged out for ${caller.userId}.`,
      });
    }
    clearSessionCookie(res, req);
    res.json({ ok: true, loggedOut: true });
  });

  app.get('/api/mobile-field/me', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        authenticated: false,
        error: 'Session expired or not authenticated. Please log into Ensec ERP.',
      });
    }
    const employee = await resolveEmployeeProfileForCaller(caller);
    if (!employee) {
      return res.status(403).json({
        authenticated: false,
        error: 'No active employee profile could be resolved for this user.',
      });
    }
    return res.status(200).json({
      authenticated: true,
      user: {
        id: caller.id,
        userId: caller.userId,
        name: caller.name,
        email: caller.email,
        phone: caller.phone,
        role: caller.role,
        designation: caller.designation,
        department: caller.department,
        status: caller.status,
      },
      employee,
    });
  });

  app.get('/api/manufacturing/permissions', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ authenticated: false, error: 'Authentication required.' });
    }
    const permissions = resolveManufacturingCostPermissions(caller);
    res.json({ authenticated: true, permissions });
  });

  app.get('/api/manufacturing/production-orders', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (caller.role !== 'Super Admin' && !hasPageAction(caller, 'manufacturing', 'view')) {
      return res.status(403).json({ error: 'Forbidden: Manufacturing view permission required.' });
    }
    const permissions = resolveManufacturingCostPermissions(caller);

    let orders: any[] = Array.from(mfgOrdersCache.values());
    if (getDb()) {
      try {
        const { data } = await getDb()
          .from('production_orders')
          .select('*')
          .order('id', { ascending: false });
        if (Array.isArray(data) && data.length > 0) {
          orders = data.map((row: any) => ({
            id: String(row.id),
            orderNumber: row.order_number || row.orderNumber || `PO-${row.id}`,
            batchNumber: row.batch_number || row.batchNumber || '',
            productId: row.product_id || row.productId || '',
            productName: row.product_name || row.productName || '',
            model: row.model || '',
            plannedQty: Number(row.planned_qty ?? row.plannedQty ?? 0),
            completedQty: Number(row.completed_qty ?? row.completedQty ?? 0),
            rawMaterialCostBDT: Number(row.raw_material_cost_bdt ?? row.rawMaterialCostBDT ?? 0),
            conversionCostBDT: Number(row.conversion_cost_bdt ?? row.conversionCostBDT ?? 0),
            optimumLaborCostBDT: Number(row.optimum_labor_cost_bdt ?? row.optimumLaborCostBDT ?? 0),
            factoryOverheadBDT: Number(row.factory_overhead_bdt ?? row.factoryOverheadBDT ?? 0),
            costPerUnitBDT: Number(row.cost_per_unit_bdt ?? row.costPerUnitBDT ?? 0),
            totalProductionCostBDT: Number(row.total_production_cost_bdt ?? row.totalProductionCostBDT ?? 0),
            wastagePercent: Number(row.wastage_percent ?? row.wastagePercent ?? 0),
            scrapKg: Number(row.scrap_kg ?? row.scrapKg ?? 0),
            status: row.status || 'In Production',
            date: row.date || row.start_date || '',
            fgReceivingStatus: row.fg_receiving_status || row.fgReceivingStatus,
            receivedFgQty: row.received_fg_qty ?? row.receivedFgQty,
          }));
        }
      } catch {
        // Use in-memory cache fallback
      }
    }

    const sanitizedOrders = orders.map((order) => sanitizeProductionOrderForUser(order, caller));
    res.json({ permissions, orders: sanitizedOrders });
  });

  app.get('/api/manufacturing/cost-sheet/:orderId', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ allowed: false, code: 'UNAUTHORIZED', error: 'Authentication required.' });
    }
    const auth = authorizeCostSheetForUser(caller);
    if (!auth.allowed) {
      return res.status(403).json({
        allowed: false,
        code: 'COST_SHEET_FORBIDDEN',
        error: auth.reason || 'Forbidden: View Cost Sheet permission is disabled.',
      });
    }

    const rawOrderId = String(req.params.orderId || '').trim();
    const targetLower = rawOrderId.toLowerCase();

    let order = Array.from(mfgOrdersCache.values()).find(
      (po) =>
        String(po.id || '').toLowerCase() === targetLower ||
        String(po.orderNumber || '').toLowerCase() === targetLower ||
        String(po.batchNumber || '').toLowerCase() === targetLower
    );

    if (!order && getDb()) {
      try {
        const { data } = await getDb().from('production_orders').select('*');
        if (Array.isArray(data)) {
          const hit = data.find(
            (row: any) =>
              String(row.id || '').toLowerCase() === targetLower ||
              String(row.order_number || '').toLowerCase() === targetLower ||
              String(row.batch_number || '').toLowerCase() === targetLower
          );
          if (hit) {
            order = {
              id: String(hit.id),
              orderNumber: hit.order_number || `PO-${hit.id}`,
              batchNumber: hit.batch_number || '',
              productId: hit.product_id || '',
              productName: hit.product_name || '',
              model: hit.model || '',
              plannedQty: Number(hit.planned_qty ?? 0),
              completedQty: Number(hit.completed_qty ?? 0),
              rawMaterialCostBDT: Number(hit.raw_material_cost_bdt ?? 0),
              conversionCostBDT: Number(hit.conversion_cost_bdt ?? 0),
              optimumLaborCostBDT: Number(hit.optimum_labor_cost_bdt ?? 0),
              factoryOverheadBDT: Number(hit.factory_overhead_bdt ?? 0),
              costPerUnitBDT: Number(hit.cost_per_unit_bdt ?? 0),
              totalProductionCostBDT: Number(hit.total_production_cost_bdt ?? 0),
              status: hit.status || 'In Production',
              date: hit.date || hit.start_date || '',
            };
          }
        }
      } catch {
        // Ignore if table unavailable
      }
    }

    if (!order) {
      return res.status(404).json({
        allowed: true,
        error: `Production order or batch "${rawOrderId}" not found.`,
      });
    }

    return res.status(200).json({
      allowed: true,
      order,
    });
  });

  app.get('/api/manufacturing/material-issue-context/:orderId', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    const canView =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'manufacturing', 'view') ||
      hasPageAction(caller, 'manufacturing', 'issue_materials');
    if (!canView) {
      return res.status(403).json({ error: 'Forbidden: Manufacturing material issue view permission required.' });
    }
    const rawOrderId = String(req.params.orderId || '').trim();
    const targetLower = rawOrderId.toLowerCase();

    const orders = Array.from(mfgOrdersCache.values());
    const order =
      orders.find(
        (po) =>
          String(po.id || '').toLowerCase() === targetLower ||
          String(po.orderNumber || '').toLowerCase() === targetLower ||
          String(po.batchNumber || '').toLowerCase() === targetLower
      ) || { id: rawOrderId, orderNumber: rawOrderId };

    const issues = Array.from(mfgIssuesCache.values());
    const existingIssue =
      issues.find(
        (mi) =>
          String(mi.productionOrderId || '').toLowerCase() === String(order.id || targetLower).toLowerCase() ||
          String(mi.productionOrderNumber || '').toLowerCase() === String(order.orderNumber || targetLower).toLowerCase()
      ) || null;

    let rawMaterials = Array.from(mfgRawMaterialsCache.values());
    let batches = Array.from(mfgBatchesCache.values());

    if (getDb() && rawMaterials.length === 0) {
      try {
        const { data: rmRows } = await getDb().from('raw_materials').select('*');
        if (Array.isArray(rmRows)) {
          rawMaterials = rmRows.map((r: any) => ({
            id: String(r.id),
            code: r.code,
            name: r.name,
            unit: r.unit,
            category: r.category,
            stockKushtia: Number(r.stock_kushtia ?? r.stock ?? 0),
            lastPurchaseUnitCostBDT: Number(r.last_purchase_unit_cost_bdt ?? r.unit_cost ?? 0),
            standardCostBDT: Number(r.standard_cost_bdt ?? 0),
          }));
        }
      } catch {
        // Ignore if unavailable
      }
    }

    if (getDb() && batches.length === 0) {
      try {
        const { data: batchRows } = await getDb().from('inventory_batches').select('*');
        if (Array.isArray(batchRows)) {
          batches = batchRows.map((b: any) => ({
            id: String(b.id),
            batchNumber: b.batch_number || b.batchNumber,
            batchBarcode: b.batch_barcode || b.batchBarcode,
            materialId: String(b.material_id || b.materialId || ''),
            materialCode: b.material_code || b.materialCode || '',
            materialName: b.material_name || b.materialName || '',
            unitPurchaseRate: Number(b.unit_purchase_rate ?? b.unitPurchaseRate ?? 0),
            availableQty: Number(b.available_qty ?? b.availableQty ?? 0),
            receivedQty: Number(b.received_qty ?? b.receivedQty ?? 0),
            issuedQty: Number(b.issued_qty ?? b.issuedQty ?? 0),
            status: b.status || 'Active',
          }));
        }
      } catch {
        // Ignore if unavailable
      }
    }

    const itemsSource = existingIssue?.items || [];
    const totalVal = itemsSource.reduce(
      (sum: number, it: any) => sum + (Number(it.totalMaterialCostBDT) || (Number(it.issuedQty || it.quantity || 0) * Number(it.unitCostBDT || it.unitCost || 0))),
      0
    );

    const sanitized = sanitizeMaterialIssueContextForUser(
      {
        order,
        existingIssue,
        items: itemsSource,
        batches,
        rawMaterials,
        totalMaterialIssueValue: existingIssue?.totalMaterialCostBDT ?? totalVal,
      },
      caller
    );

    return res.status(200).json(sanitized);
  });

  app.post('/api/manufacturing/material-issues', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }
    if (caller.role !== 'Super Admin' && !hasPageAction(caller, 'manufacturing', 'issue_materials')) {
      return res.status(403).json({ success: false, error: 'Forbidden: Issue Raw Materials permission required.' });
    }

    const body = req.body || {};
    const items = Array.isArray(body.items) ? body.items : [];
    const batches = Array.from(mfgBatchesCache.values());
    const rawMaterials = Array.from(mfgRawMaterialsCache.values());

    // Authoritative server-side costing resolution (works even when user lacks View Batch Rate permission)
    let totalCost = 0;
    let totalQty = 0;
    const processedItems = items.map((item: any, idx: number) => {
      const qty = Math.max(0, Number(item.quantity) || 0);
      const batch = batches.find(
        (b) =>
          (item.batchId && String(b.id) === String(item.batchId)) ||
          (item.batchNumber && String(b.batchNumber) === String(item.batchNumber))
      );
      const rm = rawMaterials.find(
        (r) =>
          String(r.id) === String(item.materialId) ||
          (item.materialCode && String(r.code) === String(item.materialCode))
      );
      const authoritativeRate =
        Number(batch?.unitPurchaseRate) ||
        Number(rm?.lastPurchaseUnitCostBDT) ||
        Number(rm?.standardCostBDT) ||
        Number(item.unitCostBDT) ||
        0;
      const lineCost = qty * authoritativeRate;
      totalCost += lineCost;
      totalQty += qty;

      if (batch) {
        const nextAvail = Math.max(0, Number(batch.availableQty || 0) - qty);
        const nextIssued = Number(batch.issuedQty || 0) + qty;
        mfgBatchesCache.set(String(batch.id || batch.batchNumber), {
          ...batch,
          availableQty: nextAvail,
          issuedQty: nextIssued,
          status: nextAvail === 0 ? 'Depleted' : 'Active',
        });
      }

      return {
        id: `mii-srv-${Date.now()}-${idx}`,
        materialId: String(item.materialId || rm?.id || ''),
        materialCode: item.materialCode || rm?.code || '',
        materialName: item.materialName || rm?.name || '',
        batchNumber: item.batchNumber || batch?.batchNumber || '',
        batchBarcode: item.batchBarcode || batch?.batchBarcode || '',
        issuedQty: qty,
        unitCostBDT: authoritativeRate,
        totalMaterialCostBDT: lineCost,
      };
    });

    const issueRecord = {
      id: body.issueId || `mi-srv-${Date.now()}`,
      issueNumber: body.issueNumber || `MI-SRV-${Date.now().toString().slice(-4)}`,
      productionOrderId: String(body.productionOrderId || ''),
      productionOrderNumber: String(body.productionOrderNumber || ''),
      issuedBy: String(body.issuedBy || caller?.name || 'Production Supervisor'),
      issueDate: new Date().toISOString().slice(0, 10),
      totalIssuedQty: totalQty,
      totalMaterialCostBDT: totalCost,
      items: processedItems,
      status: 'Issued',
    };

    mfgIssuesCache.set(String(issueRecord.id), issueRecord);

    // Strip restricted financial fields from API response based on caller's permissions
    const sanitizedIssue = sanitizeMaterialIssueRecordForUser(issueRecord, caller);
    return res.status(200).json({
      success: true,
      issue: sanitizedIssue,
    });
  });

  // ============================================================================
  // OVERTIME MANAGEMENT HUB — PAGE-WISE AUTHORIZATION & API ROUTES
  // ============================================================================
  const loadAuthoritativeOvertimeRequests = async (): Promise<any[]> => {
    let list: any[] = Array.from(overtimeRequestsCache.values());
    if (getDb()) {
      try {
        const [{ data: reqRows }, { data: allocRows }] = await Promise.all([
          getDb().from('overtime_requests').select('*').order('created_at', { ascending: false }),
          getDb().from('overtime_batch_allocations').select('*').order('created_at', { ascending: true }),
        ]);
        if (Array.isArray(reqRows) && reqRows.length > 0) {
          const allocByReq = new Map<string, any[]>();
          if (Array.isArray(allocRows)) {
            for (const a of allocRows) {
              const arr = allocByReq.get(String(a.request_id)) || [];
              arr.push({
                id: String(a.id),
                productionOrderId: a.production_order_id || '',
                productionOrderNumber: a.production_order_number || '',
                productionBatchNumber: a.production_batch_number || '',
                productId: a.product_id || undefined,
                productName: a.product_name || '',
                processType: a.process_type || 'Spot Welding & Busbar',
                allocatedHours: Number(a.allocated_hours) || 0,
                hourlyRateBDT: Number(a.hourly_rate_bdt) || 0,
                allocatedCostBDT: Number(a.allocated_cost_bdt) || 0,
                isOverhead: Boolean(a.is_overhead),
                notes: a.notes || undefined,
              });
              allocByReq.set(String(a.request_id), arr);
            }
          }
          list = reqRows.map((r: any) => ({
            id: String(r.id),
            requestNumber: r.request_number,
            employeeId: String(r.employee_id),
            employeeCode: r.employee_code || '',
            employeeName: r.employee_name || '',
            department: r.department || '',
            designation: r.designation || '',
            employeeCategory: r.employee_category || undefined,
            overtimeDate: String(r.overtime_date),
            purposeCategory: r.purpose_category || 'Direct Production',
            productionOrderId: r.production_order_id || undefined,
            productionOrderNumber: r.production_order_number || undefined,
            productionBatchNumber: r.production_batch_number || undefined,
            productName: r.product_name || undefined,
            projectPurpose: r.project_purpose || '',
            expectedStartTime: r.expected_start_time || '18:00',
            expectedEndTime: r.expected_end_time || '22:00',
            expectedHours: Number(r.expected_hours) || 0,
            actualOvertimeHours: r.actual_overtime_hours !== null && r.actual_overtime_hours !== undefined ? Number(r.actual_overtime_hours) : undefined,
            overtimeReason: r.overtime_reason || '',
            requestedBy: r.requested_by || '',
            requestedAt: r.requested_at || r.created_at || new Date().toISOString(),
            status: r.status || 'Pending Supervisor',
            basicSalaryBDT: Number(r.basic_salary_bdt) || 0,
            hourlyRateBDT: Number(r.hourly_rate_bdt) || 0,
            overtimeMultiplier: r.overtime_multiplier !== null && r.overtime_multiplier !== undefined ? Number(r.overtime_multiplier) : 2.0,
            calculatedOvertimeAmountBDT: Number(r.calculated_overtime_amount_bdt) || 0,
            batchAllocations: allocByReq.get(String(r.id)) || [],
            isPayrollProcessed: Boolean(r.is_payroll_processed),
            isCostingAllocated: Boolean(r.is_costing_allocated),
          }));
        }
      } catch {
        // Fallback to in-memory cache
      }
    }
    return list;
  };

  app.get('/api/overtime/permissions', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const permissions = resolveOvertimePermissions(caller);
    res.json({ authenticated: Boolean(caller), permissions });
  });

  app.get('/api/overtime/requests', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'requests');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_REQUESTS_FORBIDDEN', error: auth.reason });
    }
    const requests = (await loadAuthoritativeOvertimeRequests()).map((r) => sanitizeOvertimeRecordForUser(r, caller));
    res.json({ allowed: true, requests });
  });

  app.post('/api/overtime/requests', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'requests');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_REQUESTS_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.createRequest) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_CREATE_FORBIDDEN', error: 'Forbidden: Create OT Request permission required.' });
    }
    const record = { ...(req.body || {}), id: req.body?.id || `otr-srv-${Date.now()}` };
    overtimeRequestsCache.set(String(record.id), record);
    return res.status(200).json({ allowed: true, request: sanitizeOvertimeRecordForUser(record, caller) });
  });

  app.put('/api/overtime/requests/:id', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'requests');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_REQUESTS_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.editRequest) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_EDIT_FORBIDDEN', error: 'Forbidden: Edit OT Request permission required.' });
    }
    const id = String(req.params.id || '');
    const existing = overtimeRequestsCache.get(id) || {};
    const updated = { ...existing, ...(req.body || {}), id, updatedAt: new Date().toISOString() };
    overtimeRequestsCache.set(id, updated);
    return res.status(200).json({ allowed: true, request: sanitizeOvertimeRecordForUser(updated, caller) });
  });

  app.delete('/api/overtime/requests/:id', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'requests');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_REQUESTS_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.editRequest && !perms.approveFinal) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_DELETE_FORBIDDEN', error: 'Forbidden: Edit or Final Approval clearance required to delete OT requests.' });
    }
    const id = String(req.params.id || '');
    overtimeRequestsCache.delete(id);
    if (getDb()) {
      try {
        await getDb().from('overtime_requests').delete().eq('id', id);
      } catch {
        // Ignore if unavailable
      }
    }
    return res.status(200).json({ allowed: true, deletedId: id });
  });

  app.post('/api/overtime/requests/:id/workflow', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'requests');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_REQUESTS_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    const step = String(req.body?.step || '').toUpperCase();
    const stepOk =
      (step === 'SUPERVISOR' && (perms.approveSupervisor || perms.approveFinal)) ||
      (step === 'PRODUCTION' && (perms.approveProduction || perms.approveFinal)) ||
      (step === 'HR' && (perms.verifyHrAccounts || perms.approveFinal)) ||
      (step === 'FINAL' && perms.approveFinal);
    if (!stepOk) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_WORKFLOW_FORBIDDEN', error: `Forbidden: Missing approval clearance for step ${step || 'UNKNOWN'}.` });
    }
    const id = String(req.params.id || '');
    const existing = overtimeRequestsCache.get(id) || { id };
    return res.status(200).json({ allowed: true, request: sanitizeOvertimeRecordForUser(existing, caller) });
  });

  app.get('/api/overtime/attendances', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'attendance');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_ATTENDANCE_FORBIDDEN', error: auth.reason });
    }
    let attendances: any[] = Array.from(overtimeAttendancesCache.values());
    if (getDb()) {
      try {
        const { data } = await getDb().from('overtime_attendances').select('*').order('date', { ascending: false });
        if (Array.isArray(data) && data.length > 0) {
          attendances = data.map((a: any) => ({
            id: String(a.id),
            requestId: a.request_id || undefined,
            requestNumber: a.request_number || undefined,
            employeeId: String(a.employee_id),
            employeeCode: a.employee_code || '',
            employeeName: a.employee_name || '',
            department: a.department || '',
            designation: a.designation || '',
            date: String(a.date),
            overtimeCheckInTime: a.overtime_check_in_time || '',
            overtimeCheckOutTime: a.overtime_check_out_time || '',
            isOvernight: Boolean(a.is_overnight),
            actualOvertimeHours: Number(a.actual_overtime_hours) || 0,
            isVerified: Boolean(a.is_verified),
            verifiedBy: a.verified_by || undefined,
            syncSource: a.sync_source || 'Manual',
          }));
        }
      } catch {
        // Fallback to cache
      }
    }
    res.json({ allowed: true, attendances });
  });

  app.post('/api/overtime/attendances', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'attendance');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_ATTENDANCE_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.recordAttendance) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_RECORD_ATTENDANCE_FORBIDDEN', error: 'Forbidden: Record OT Attendance permission required.' });
    }
    const record = { ...(req.body || {}), id: req.body?.id || `ot-att-srv-${Date.now()}` };
    overtimeAttendancesCache.set(String(record.id), record);
    return res.status(200).json({ allowed: true, attendance: record });
  });

  app.post('/api/overtime/attendances/:id/verify', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'attendance');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_ATTENDANCE_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.verifyAttendance) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_VERIFY_ATTENDANCE_FORBIDDEN', error: 'Forbidden: Verify Biometric OT Punch permission required.' });
    }
    const id = String(req.params.id || '');
    const existing = overtimeAttendancesCache.get(id) || { id };
    const updated = { ...existing, isVerified: true, verifiedBy: caller?.name || 'Supervisor', verificationDate: new Date().toISOString() };
    overtimeAttendancesCache.set(id, updated);
    return res.status(200).json({ allowed: true, attendance: updated });
  });

  app.get('/api/overtime/batch-allocations', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'batch_allocation');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_BATCH_ALLOCATION_FORBIDDEN', error: auth.reason });
    }
    const requests = (await loadAuthoritativeOvertimeRequests()).map((r) => sanitizeOvertimeRecordForUser(r, caller));
    res.json({ allowed: true, requests });
  });

  app.put('/api/overtime/batch-allocations/:requestId', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'batch_allocation');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_BATCH_ALLOCATION_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.allocateBatch) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_ALLOCATE_BATCH_FORBIDDEN', error: 'Forbidden: Allocate Overtime to Batches permission required.' });
    }
    const requestId = String(req.params.requestId || '');
    const allocations = Array.isArray(req.body?.allocations) ? req.body.allocations : [];
    const existing = overtimeRequestsCache.get(requestId) || { id: requestId };
    const updated = { ...existing, batchAllocations: allocations, isCostingAllocated: allocations.length > 0, updatedAt: new Date().toISOString() };
    overtimeRequestsCache.set(requestId, updated);
    return res.status(200).json({ allowed: true, request: sanitizeOvertimeRecordForUser(updated, caller) });
  });

  app.get('/api/overtime/payroll-sync', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'payroll_costing_sync');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_PAYROLL_SYNC_FORBIDDEN', error: auth.reason });
    }
    const requests = (await loadAuthoritativeOvertimeRequests())
      .filter((r) => r.status === 'Final Approved')
      .map((r) => sanitizeOvertimeRecordForUser(r, caller));
    res.json({ allowed: true, requests });
  });

  app.get('/api/overtime/policies', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'policies');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_POLICIES_FORBIDDEN', error: auth.reason });
    }
    let policies: any[] = Array.from(overtimePoliciesCache.values());
    if (getDb() && policies.length === 0) {
      try {
        const { data } = await getDb().from('overtime_policies').select('*').order('created_at', { ascending: true });
        if (Array.isArray(data)) policies = data;
      } catch {
        // Fallback to cache
      }
    }
    res.json({ allowed: true, policies });
  });

  app.put('/api/overtime/policies/:id', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'policies');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_POLICIES_FORBIDDEN', error: auth.reason });
    }
    const perms = resolveOvertimePermissions(caller);
    if (!perms.configurePolicy) {
      return res.status(403).json({ allowed: false, code: 'OVERTIME_CONFIGURE_POLICY_FORBIDDEN', error: 'Forbidden: Configure OT Policy permission required.' });
    }
    const id = String(req.params.id || '');
    const existing = overtimePoliciesCache.get(id) || {};
    const updated = { ...existing, ...(req.body || {}), id, updatedAt: new Date().toISOString(), updatedBy: caller?.name };
    overtimePoliciesCache.set(id, updated);
    return res.status(200).json({ allowed: true, policy: updated });
  });

  app.get('/api/overtime/reports', async (req, res) => {
    const caller = await resolveRequestUser(req);
    const auth = authorizeOvertimeSubPage(caller, 'reports');
    if (!auth.allowed) {
      return res.status(caller ? 403 : 401).json({ allowed: false, code: 'OVERTIME_REPORTS_FORBIDDEN', error: auth.reason });
    }
    const requests = (await loadAuthoritativeOvertimeRequests()).map((r) => sanitizeOvertimeRecordForUser(r, caller));
    res.json({ allowed: true, requests });
  });

  // Authenticated Mobile Field Force Transaction Endpoints (Enforces active ERP User <-> Employee Identity)
  const authorizeMobileTransaction = async (req: express.Request, res: express.Response) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      res.status(401).json({
        ok: false,
        errorCode: 'UNAUTHORIZED',
        error: 'Authentication required. Please log in to Ensec ERP.',
      });
      return null;
    }
    const employee = await resolveEmployeeProfileForCaller(caller);
    if (!employee) {
      res.status(403).json({
        ok: false,
        errorCode: 'EMPLOYEE_UNRESOLVED',
        error: 'No active employee profile found for authenticated ERP user.',
      });
      return null;
    }
    const body = req.body || {};
    const identityCheck = verifyTransactionIdentityMatchesUser(
      {
        userId: body.userId,
        employeeId: body.employeeId,
        fieldForceId: body.fieldForceId,
        employeeCode: body.employeeCode,
        salespersonId: body.salespersonId,
        assignedSalespersonId: body.assignedSalespersonId,
        repId: body.repId,
        ffCode: body.ffCode,
        employee: body.employee && typeof body.employee === 'object' ? body.employee : undefined,
      },
      employee
    );
    if (!identityCheck.valid) {
      res.status(403).json({
        ok: false,
        errorCode: 'IDENTITY_MISMATCH',
        error: identityCheck.reason,
      });
      return null;
    }
    return { caller, employee, body };
  };

  app.post('/api/orders', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `so-srv-${Date.now()}`,
      userId: caller.id,
      userLoginId: caller.userId || employee.userLoginId,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      salespersonId: employee.employeeId,
      salespersonName: employee.name,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.orders.unshift(record);
    return res.status(200).json({ ok: true, order: record });
  });

  app.post('/api/customers', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `cust-srv-${Date.now()}`,
      userId: caller.id,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      assignedSalespersonId: employee.employeeId,
      assignedSalespersonName: employee.name,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.customers.unshift(record);
    return res.status(200).json({ ok: true, customer: record });
  });

  app.post('/api/tada', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `tada-srv-${Date.now()}`,
      userId: caller.id,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      ffCode: employee.employeeCode,
      ffName: employee.name,
      repId: employee.employeeId,
      repName: employee.name,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.tada.unshift(record);
    return res.status(200).json({ ok: true, tada: record });
  });

  app.post('/api/warranty', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `war-srv-${Date.now()}`,
      userId: caller.id,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      complaintReceivedBy: employee.name,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.warranty.unshift(record);
    return res.status(200).json({ ok: true, ticket: record });
  });

  app.post('/api/visits', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `visit-srv-${Date.now()}`,
      userId: caller.id,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      repId: employee.employeeId,
      repName: employee.name,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.visits.unshift(record);
    return res.status(200).json({ ok: true, visit: record });
  });

  app.post('/api/leaves', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `leave-srv-${Date.now()}`,
      userId: caller.id,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      employeeName: employee.name,
      department: employee.department,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.leaves.unshift(record);
    return res.status(200).json({ ok: true, leave: record });
  });

  app.post('/api/crm-leads', async (req, res) => {
    const auth = await authorizeMobileTransaction(req, res);
    if (!auth) return;
    const { caller, employee, body } = auth;
    const record = {
      ...body,
      id: body.id || `crm-srv-${Date.now()}`,
      userId: caller.id,
      employeeId: employee.employeeId,
      employeeCode: employee.employeeCode,
      salespersonId: employee.employeeId,
      salespersonName: employee.name,
      assignedRepName: employee.name,
      recordedAt: new Date().toISOString(),
    };
    mobileTransactionsStore.crmLeads.unshift(record);
    return res.status(200).json({ ok: true, lead: record });
  });

  // --------------------------------------------------------------------------
  // Register Centralized Domain DB Gateway (58 tables) & Real-time SSE Events
  // --------------------------------------------------------------------------
  registerEventsRoutes(app);
  registerSystemSettingsRoutes(app);
  registerErpGatewayRoutes(app);

  // --------------------------------------------------------------------------
  // Super Admin Database Status, Schema Verification & Audit Endpoints (Phase 1)
  // Strictly requires a verified signed session (HttpOnly cookie or Bearer token)
  // for an Active Super Admin. Never exposes URLs, API keys, or secrets.
  // --------------------------------------------------------------------------
  const requireSuperAdminSession = async (
    req: express.Request,
    res: express.Response
  ): Promise<any | null> => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      res.status(401).json({
        ok: false,
        code: 'ADMIN_DB_UNAUTHENTICATED',
        error: 'Valid signed ERP session is required.',
      });
      return null;
    }

    if (caller.role !== 'Super Admin') {
      res.status(403).json({
        ok: false,
        code: 'ADMIN_DB_FORBIDDEN',
        error: 'Forbidden: Super Admin privileges are required to inspect database status or schema.',
      });
      return null;
    }

    return caller;
  };

  const initialDbSummary = getPublicSafeDatabaseSummary();
  recordDbAuditEvent({
    eventType: 'DB_CONFIG_LOADED',
    actorId: 'system',
    actorName: 'Server Startup',
    actorRole: 'System',
    outcome: initialDbSummary.configured ? 'success' : 'warning',
    details: initialDbSummary.configured
      ? `Centralized server DB configuration loaded (authMode=${initialDbSummary.authMode}).`
      : 'Server started without SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY configured.',
  });

  app.get('/api/admin/db/status', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;
    const status = await checkServerDatabaseStatus({
      id: admin.id,
      name: admin.name,
      role: admin.role,
    });
    return res.status(status.configured ? (status.reachable ? 200 : 503) : 200).json(status);
  });

  app.post('/api/admin/db/verify-schema', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;
    const verification = await verifyDatabaseSchema({
      id: admin.id,
      name: admin.name,
      role: admin.role,
    });
    return res.status(200).json(verification);
  });

  app.get('/api/admin/db/audit-logs', async (req, res) => {
    const admin = await requireSuperAdminSession(req, res);
    if (!admin) return;
    const limit = Math.max(1, Math.min(Number(req.query.limit) || 50, 100));
    return res.status(200).json({
      ok: true,
      summary: getPublicSafeDatabaseSummary(),
      events: getDbAuditEvents(limit),
    });
  });

  registerDbSwitchCacheResetHook(() => {
    clearUserLookupCache();
    officeLocationsStore.clear();
    DEFAULT_OFFICE_LOCATIONS.forEach((loc) => officeLocationsStore.set(loc.id, loc));
    attendanceRecordsStore.clear();
    rejectedAttemptsStore.length = 0;
    lastEmployeeGpsPing.clear();
    fieldForceRepsCache.clear();
    mfgOrdersCache.clear();
    mfgIssuesCache.clear();
    mfgRawMaterialsCache.clear();
    mfgBatchesCache.clear();
    overtimeRequestsCache.clear();
    overtimeAttendancesCache.clear();
    overtimePoliciesCache.clear();
    mobileTransactionsStore.orders.length = 0;
    mobileTransactionsStore.customers.length = 0;
    mobileTransactionsStore.tada.length = 0;
    mobileTransactionsStore.warranty.length = 0;
    mobileTransactionsStore.visits.length = 0;
    mobileTransactionsStore.leaves.length = 0;
    mobileTransactionsStore.crmLeads.length = 0;
  });

  registerDatabaseMigrationRoutes(app, requireSuperAdminSession);

  return app;
}

async function startServer() {
  const app = createAppServer();
  const httpServer = http.createServer(app);
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const isHmrDisabled = process.env.DISABLE_HMR === 'true';
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        allowedHosts: true,
        ws: { server: httpServer },
        hmr: isHmrDisabled ? false : {},
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Ensec ERP Server running on http://0.0.0.0:${PORT}`);
  });
}

// Start server only when executed directly (allows unit testing createAppServer cleanly)
const isDirectRun =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(__filename);

if (isDirectRun) {
  startServer().catch((err) => {
    console.error('Failed to start Ensec ERP Server:', err);
    process.exit(1);
  });
}
