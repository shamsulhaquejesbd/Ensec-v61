/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 4 Comprehensive Automated Test Suite
 * Tests Centralized DB Config, Encrypted Store, Target Connection Validation,
 * 114-Table Schema Compatibility Validator, Pre-Flight Checklist, Dependency-Ordered
 * Batched Migration with Retry & Idempotency, Sequence Sync, Storage/Auth Inspection,
 * Concurrency Lock, Atomic Cutover, Divergence-Guarded Rollback, and Strict RBAC (401/403).
 * Runs strictly against isolated in-memory HTTP PostgREST/Storage mock servers — zero production impact.
 */

import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import bcrypt from 'bcryptjs';

import { EXPECTED_ERP_TABLES, MIGRATION_TABLE_ORDER } from '../server/db/schemaRegistry.ts';
import {
  clearAuthCacheForTest,
  createSessionForUser,
  hashPassword,
  indexUserInAuthCache,
} from '../server/auth/authService.ts';
import {
  getPublicSafeDatabaseSummary,
  getServerDbConfig,
  getServerSupabase,
  resetServerSupabaseClient,
  resetStoreCacheForTest,
  sortSelfReferencingRows,
} from '../server/db/index.ts';
import { createAppServer } from '../server.ts';

interface MockDbOptions {
  name: string;
  serviceRoleKey: string;
  anonKey?: string;
  missingTables?: Set<string>;
  columnOverrides?: Record<string, Record<string, { type: string; format: string; required?: boolean }>>;
  extraTables?: string[];
  enablePostgresInspectorRpc?: boolean;
  failFirstUpsertForTable?: string;
  rejectWrites?: boolean;
  buckets?: Array<{ name: string; public: boolean; files: Record<string, string> }>;
  seedRows?: Record<string, Array<Record<string, any>>>;
}

class MockSupabaseServer {
  public server!: http.Server;
  public baseUrl = '';
  public tables = new Map<string, Array<Record<string, any>>>();
  public sequenceValues = new Map<string, number>();
  public upsertFailRemaining = new Map<string, number>();
  public buckets: Array<{ name: string; public: boolean; files: Record<string, string> }> = [];
  public opts: MockDbOptions;

  constructor(opts: MockDbOptions) {
    this.opts = opts;
    this.buckets = (opts.buckets || []).map((b) => ({ ...b, files: { ...b.files } }));
    for (const spec of EXPECTED_ERP_TABLES) {
      this.tables.set(spec.name, [...(opts.seedRows?.[spec.name] || [])]);
      if (spec.hasSequence) {
        this.sequenceValues.set(spec.name, 1);
      }
    }
    if (opts.failFirstUpsertForTable) {
      this.upsertFailRemaining.set(opts.failFirstUpsertForTable, 1);
    }
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => this.handleRequest(req, res));
    await new Promise<void>((resolve) => {
      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server.address() as { port: number };
        this.baseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private buildOpenApiSpec() {
    const definitions: Record<string, any> = {};
    for (const spec of EXPECTED_ERP_TABLES) {
      if (this.opts.missingTables?.has(spec.name)) continue;
      const props: Record<string, any> = {};
      const required: string[] = [spec.primaryKey];
      for (const col of spec.expectedColumns) {
        const override = this.opts.columnOverrides?.[spec.name]?.[col];
        let desc = '';
        if (col === spec.primaryKey) desc = '<pk/>';
        if (col === 'distributor_id' && spec.parentTables.includes('distributors')) {
          desc = "<fk table='distributors' col='id'/>";
        }
        if (col === 'warehouse_id' && spec.parentTables.includes('warehouses')) {
          desc = "<fk table='warehouses' col='id'/>";
        }
        if (col === 'customer_id' && spec.parentTables.includes('customers')) {
          desc = "<fk table='customers' col='id'/>";
        }
        if (col === 'product_id' && spec.parentTables.includes('products')) {
          desc = "<fk table='products' col='id'/>";
        }
        if (col === 'order_id' && spec.parentTables.includes('retailer_orders')) {
          desc = "<fk table='retailer_orders' col='id'/>";
        }
        props[col] = {
          type: override?.type || (col === 'id' && spec.hasSequence ? 'integer' : 'string'),
          format: override?.format || (col === 'id' && spec.hasSequence ? 'bigint' : 'text'),
          description: desc || undefined,
        };
        if (override?.required) required.push(col);
      }
      definitions[spec.name] = { type: 'object', required, properties: props };
    }
    for (const extra of this.opts.extraTables || []) {
      definitions[extra] = {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string', format: 'text', description: '<pk/>' } },
      };
    }
    return { swagger: '2.0', info: { title: this.opts.name }, definitions };
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url || '/', this.baseUrl);
    const apiKey = String(req.headers['apikey'] || '');
    const authHeader = String(req.headers['authorization'] || '');
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : apiKey;

    if (token !== this.opts.serviceRoleKey && token !== this.opts.anonKey) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Invalid API key' }));
      return;
    }

    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(Buffer.from(c));
    const bodyText = Buffer.concat(chunks).toString('utf8');
    let bodyJson: any = null;
    if (bodyText) {
      try {
        bodyJson = JSON.parse(bodyText);
      } catch {
        bodyJson = null;
      }
    }

    // OpenAPI spec
    if (url.pathname === '/rest/v1/' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/openapi+json' });
      res.end(JSON.stringify(this.buildOpenApiSpec()));
      return;
    }

    // Storage Buckets API mock
    if (url.pathname === '/storage/v1/bucket' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.buckets.map((b) => ({ id: b.name, name: b.name, public: b.public }))));
      return;
    }
    if (url.pathname === '/storage/v1/bucket' && req.method === 'POST') {
      const name = String(bodyJson?.name || bodyJson?.id || '');
      if (name && !this.buckets.some((b) => b.name === name)) {
        this.buckets.push({ name, public: Boolean(bodyJson?.public), files: {} });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ name }));
      return;
    }
    if (url.pathname.startsWith('/storage/v1/object/list/')) {
      const bucketName = decodeURIComponent(url.pathname.replace('/storage/v1/object/list/', ''));
      const bucket = this.buckets.find((b) => b.name === bucketName);
      const list = bucket
        ? Object.keys(bucket.files).map((f) => ({ name: f, id: `obj-${f}` }))
        : [];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(list));
      return;
    }
    if (url.pathname.startsWith('/storage/v1/object/')) {
      const rest = url.pathname.replace('/storage/v1/object/', '');
      const [bucketName, ...fileParts] = rest.split('/');
      const fileName = decodeURIComponent(fileParts.join('/'));
      const bucket = this.buckets.find((b) => b.name === bucketName);
      if (req.method === 'GET') {
        const content = bucket?.files[fileName];
        if (content === undefined) {
          res.writeHead(404);
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(content);
        return;
      }
      if (req.method === 'POST' || req.method === 'PUT') {
        if (bucket && fileName) {
          bucket.files[fileName] = bodyText;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ Key: `${bucketName}/${fileName}` }));
        return;
      }
    }

    // RPC routes
    if (url.pathname.startsWith('/rest/v1/rpc/')) {
      const rpcName = url.pathname.replace('/rest/v1/rpc/', '');
      if (rpcName === 'ensec_phase4_inspect_metadata') {
        if (!this.opts.enablePostgresInspectorRpc) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Function not found' }));
          return;
        }
        const tables = EXPECTED_ERP_TABLES.filter((s) => !this.opts.missingTables?.has(s.name)).map((s) => ({
          table: s.name,
          rlsEnabled: true,
        }));
        const sequences = EXPECTED_ERP_TABLES.filter((s) => s.hasSequence).map((s) => ({
          name: `${s.name}_id_seq`,
          lastValue: this.sequenceValues.get(s.name) || 1,
          startValue: 1,
        }));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            inspectedAt: new Date().toISOString(),
            extensions: [{ name: 'uuid-ossp', version: '1.1' }],
            tables,
            views: [{ name: 'safe_users' }],
            indexes: Array.from({ length: 102 }, (_, idx) => ({
              table: 'users',
              name: `idx_mock_${idx}`,
              unique: false,
            })),
            sequences,
            policies: [],
            constraints: EXPECTED_ERP_TABLES.map((s) => ({
              table: s.name,
              name: `${s.name}_pkey`,
              type: 'PRIMARY KEY',
            })),
          })
        );
        return;
      }

      if (rpcName === 'ensec_phase4_sync_sequence') {
        if (!this.opts.enablePostgresInspectorRpc) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Function not found' }));
          return;
        }
        const tbl = String(bodyJson?.p_table_name || '');
        const rows = this.tables.get(tbl) || [];
        const maxId = rows.reduce((m, r) => Math.max(m, Number(r.id) || 0), 0);
        this.sequenceValues.set(tbl, Math.max(1, maxId));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, table: tbl, maxId, setvalResult: maxId }));
        return;
      }
    }

    // Table REST API
    if (url.pathname.startsWith('/rest/v1/')) {
      const tableName = decodeURIComponent(url.pathname.replace('/rest/v1/', ''));
      if (this.opts.missingTables?.has(tableName) || !this.tables.has(tableName)) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ code: 'PGRST205', message: `Could not find the table 'public.${tableName}'` }));
        return;
      }

      let rows = [...(this.tables.get(tableName) || [])];

      if (req.method === 'HEAD' || req.method === 'GET') {
        // Basic eq / ilike filter support
        for (const [k, v] of url.searchParams.entries()) {
          if (['select', 'order', 'limit', 'offset'].includes(k)) continue;
          if (v.startsWith('eq.')) {
            const targetVal = v.slice(3);
            rows = rows.filter((r) => String(r[k] ?? '') === targetVal);
          } else if (v.startsWith('ilike.')) {
            const targetVal = v.slice(6).replace(/%/g, '').toLowerCase();
            rows = rows.filter((r) => String(r[k] ?? '').toLowerCase() === targetVal);
          }
        }
        const orderParam = url.searchParams.get('order');
        if (orderParam) {
          const [col, dir] = orderParam.split('.');
          const asc = dir !== 'desc';
          rows.sort((a, b) => {
            const av = a[col];
            const bv = b[col];
            if (typeof av === 'number' && typeof bv === 'number') return asc ? av - bv : bv - av;
            return asc
              ? String(av ?? '').localeCompare(String(bv ?? ''))
              : String(bv ?? '').localeCompare(String(av ?? ''));
          });
        }

        const totalCount = rows.length;
        const rangeHdr = String(req.headers['range'] || '');
        let start = 0;
        let end = rows.length - 1;
        if (rangeHdr) {
          const m = rangeHdr.match(/^(\d+)-(\d+)$/);
          if (m) {
            start = Number(m[1]);
            end = Number(m[2]);
            rows = rows.slice(start, end + 1);
          }
        }
        const rawLimit = url.searchParams.get('limit');
        if (rawLimit !== null && rawLimit !== '') {
          const limitParam = Number(rawLimit);
          if (!Number.isNaN(limitParam) && limitParam >= 0) {
            rows = rows.slice(0, limitParam);
          }
        }

        const prefer = String(req.headers['prefer'] || '');
        const isHead = req.method === 'HEAD';
        const accept = String(req.headers['accept'] || '');
        const wantsSingle = accept.includes('application/vnd.pgrst.object+json');

        res.setHeader('Content-Range', `${rows.length ? start : 0}-${rows.length ? start + rows.length - 1 : 0}/${totalCount}`);
        if (prefer.includes('count=exact') && isHead) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end();
          return;
        }
        if (wantsSingle) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(rows[0] ?? null));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(rows));
        return;
      }

      if (req.method === 'DELETE') {
        if (this.opts.rejectWrites || token === this.opts.anonKey) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ code: '42501', message: 'permission denied for table' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([]));
        return;
      }

      if (req.method === 'POST' || req.method === 'PATCH') {
        if (this.opts.rejectWrites || token === this.opts.anonKey) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ code: '42501', message: 'permission denied for table' }));
          return;
        }
        const remainingFails = this.upsertFailRemaining.get(tableName) || 0;
        if (remainingFails > 0) {
          this.upsertFailRemaining.set(tableName, remainingFails - 1);
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Transient target overload' }));
          return;
        }
        const incoming = Array.isArray(bodyJson) ? bodyJson : bodyJson ? [bodyJson] : [];
        const existing = this.tables.get(tableName) || [];
        const byId = new Map(existing.map((r) => [String(r.id), r]));
        for (const row of incoming) {
          byId.set(String(row.id), { ...(byId.get(String(row.id)) || {}), ...row });
        }
        this.tables.set(tableName, Array.from(byId.values()));
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(incoming));
        return;
      }
    }

    res.writeHead(404);
    res.end();
  }
}

async function httpJson(
  baseUrl: string,
  method: string,
  route: string,
  options: {
    cookie?: string;
    csrf?: string;
    body?: any;
  } = {}
): Promise<{ status: number; json: any; rawText: string }> {
  const headers: Record<string, string> = {};
  if (options.cookie) headers['Cookie'] = options.cookie;
  if (options.csrf) headers['X-CSRF-Token'] = options.csrf;
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
  });
  const rawText = await res.text();
  let json: any = null;
  try {
    json = rawText ? JSON.parse(rawText) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json, rawText };
}

describe('Phase 4 Centralized Database Migration & Switching Control Plane', () => {
  let tempDir = '';
  let stateFile = '';
  let sourceDb!: MockSupabaseServer;
  let targetDb!: MockSupabaseServer;
  let incompleteTargetDb!: MockSupabaseServer;
  let appServer!: http.Server;
  let appBaseUrl = '';

  let adminCookie = '';
  let adminCsrf = 'test-csrf-admin-token-1234';
  let staffCookie = '';
  let staffCsrf = 'test-csrf-staff-token-5678';

  const SOURCE_SERVICE_KEY = 'sb_secret_source_mock_key_abcdefghijklmnopqrstuvwxyz123456';
  const TARGET_SERVICE_KEY = 'sb_secret_target_mock_key_abcdefghijklmnopqrstuvwxyz654321';
  const TARGET_ANON_KEY = 'sb_publishable_anon_key_should_be_rejected_123456';
  let adminBcryptHash = '';

  before(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ensec-phase4-test-'));
    stateFile = path.join(tempDir, 'db-control.enc.json');
    process.env.ENSEC_DB_STATE_PATH = stateFile;
    process.env.ERP_SESSION_SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeeff';

    adminBcryptHash = await hashPassword('AdminPass!2026');
    const staffHash = await hashPassword('StaffPass!2026');

    sourceDb = new MockSupabaseServer({
      name: 'source-prod',
      serviceRoleKey: SOURCE_SERVICE_KEY,
      enablePostgresInspectorRpc: true,
      buckets: [
        { name: 'warranty-photos', public: false, files: { 'claim-001.txt': 'sample-battery-photo-bytes' } },
      ],
      seedRows: {
        users: [
          {
            id: 1,
            uid: 'u-admin-1',
            user_id: 'ADMIN',
            name: 'Super Admin',
            email: 'admin@ensecbd.com',
            password: adminBcryptHash,
            role: 'Super Admin',
            status: 'Active',
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-02T00:00:00Z',
          },
          {
            id: 2,
            uid: 'u-staff-1',
            user_id: 'STAFF01',
            name: 'Regional Manager',
            email: 'rm@ensecbd.com',
            password: staffHash,
            role: 'Regional Manager',
            status: 'Active',
            created_at: '2026-01-03T00:00:00Z',
          },
        ],
        warehouses: [
          { id: 1, code: 'WH-DHK', name: 'Dhaka Central', created_at: '2026-01-01T00:00:00Z' },
        ],
        distributors: [
          { id: 10, code: 'DIST-01', name: 'Green Energy Dist', warehouse_id: 1 },
        ],
        customers: [
          { id: 100, code: 'CUST-01', name: 'Dhaka Mobility', distributor_id: 10 },
        ],
        products: [
          { id: 5, code: 'EV-60V45', name: 'Ensec 60V 45Ah LiFePO4' },
        ],
        sales_orders: [
          { id: 500, order_number: 'SO-2026-500', customer_id: 100, warehouse_id: 1, total_amount: 125000 },
        ],
        org_hierarchy: [
          { id: 2, node_id: 'n-child', code: 'ZONE-1', name: 'Zone 1', level: 2, parent_id: '1' },
          { id: 1, node_id: 'n-root', code: 'HQ', name: 'Headquarters', level: 1, parent_id: null },
        ],
        chart_of_accounts: [
          { id: 'coa-child', code: '1100', name: 'Cash at Bank', parent_id: 'coa-root' },
          { id: 'coa-root', code: '1000', name: 'Assets', parent_id: null },
        ],
      },
    });

    targetDb = new MockSupabaseServer({
      name: 'target-staging',
      serviceRoleKey: TARGET_SERVICE_KEY,
      anonKey: TARGET_ANON_KEY,
      enablePostgresInspectorRpc: true,
      failFirstUpsertForTable: 'warehouses', // Test transient retry recovery
      extraTables: ['legacy_temp_notes'],
    });

    incompleteTargetDb = new MockSupabaseServer({
      name: 'target-incomplete',
      serviceRoleKey: TARGET_SERVICE_KEY,
      missingTables: new Set(['general_ledger_entries', 'overtime_requests']),
      columnOverrides: {
        users: { email: { type: 'integer', format: 'int4' } },
      },
      enablePostgresInspectorRpc: false,
    });

    await Promise.all([sourceDb.start(), targetDb.start(), incompleteTargetDb.start()]);

    process.env.SUPABASE_URL = sourceDb.baseUrl;
    process.env.SUPABASE_SERVICE_ROLE_KEY = SOURCE_SERVICE_KEY;
    resetStoreCacheForTest();
    resetServerSupabaseClient();
    clearAuthCacheForTest();

    const adminUser = {
      id: 'u-admin-1',
      userId: 'ADMIN',
      name: 'Super Admin',
      email: 'admin@ensecbd.com',
      role: 'Super Admin',
      status: 'Active',
      permissions: { allowedModules: ['dashboard', 'users-permissions'], features: {} },
    };
    const staffUser = {
      id: 'u-staff-1',
      userId: 'STAFF01',
      name: 'Regional Manager',
      email: 'rm@ensecbd.com',
      role: 'Regional Manager',
      status: 'Active',
      permissions: { allowedModules: ['dashboard'], features: {} },
    };
    indexUserInAuthCache(adminUser as any, adminBcryptHash);
    indexUserInAuthCache(staffUser as any, staffHash);

    const adminSess = createSessionForUser(adminUser as any);
    const staffSess = createSessionForUser(staffUser as any);
    adminCookie = `ensec_erp_session=${encodeURIComponent(adminSess.token)}; ensec_csrf_token=${adminCsrf}`;
    staffCookie = `ensec_erp_session=${encodeURIComponent(staffSess.token)}; ensec_csrf_token=${staffCsrf}`;

    const app = createAppServer();
    appServer = http.createServer(app);
    await new Promise<void>((resolve) => {
      appServer.listen(0, '127.0.0.1', () => {
        const addr = appServer.address() as { port: number };
        appBaseUrl = `http://127.0.0.1:${addr.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await Promise.all([
      sourceDb?.stop(),
      targetDb?.stop(),
      incompleteTargetDb?.stop(),
      appServer ? new Promise<void>((resolve) => appServer.close(() => resolve())) : Promise.resolve(),
    ]);
    fs.rmSync(tempDir, { recursive: true, force: true });
    delete process.env.ENSEC_DB_STATE_PATH;
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    resetStoreCacheForTest();
    resetServerSupabaseClient();
  });

  test('1 & 2. Centralized DB config masks secrets & reuses singleton server client', () => {
    const cfg = getServerDbConfig();
    assert.equal(cfg.isConfigured, true);
    assert.equal(cfg.configVersion, 1);

    const c1 = getServerSupabase();
    const c2 = getServerSupabase();
    assert.ok(c1);
    assert.strictEqual(c1, c2, 'Centralized server client must reuse singleton');

    const safe = getPublicSafeDatabaseSummary();
    assert.equal(safe.configured, true);
    assert.equal(safe.hasServiceRoleKey, true);
    assert.equal(JSON.stringify(safe).includes(SOURCE_SERVICE_KEY), false);
  });

  test('15. Unauthenticated (401) & non-Super-Admin (403) access denied on all DB migration endpoints', async () => {
    const unauth = await httpJson(appBaseUrl, 'GET', '/api/admin/db/overview');
    assert.equal(unauth.status, 401);

    const staffOverview = await httpJson(appBaseUrl, 'GET', '/api/admin/db/overview', {
      cookie: staffCookie,
    });
    assert.equal(staffOverview.status, 403);

    const staffTargetSave = await httpJson(appBaseUrl, 'POST', '/api/admin/db/config/target', {
      cookie: staffCookie,
      csrf: staffCsrf,
      body: { supabaseUrl: targetDb.baseUrl, serviceRoleKey: TARGET_SERVICE_KEY },
    });
    assert.equal(staffTargetSave.status, 403);
  });

  test('3 & 4. Save target DB encrypted server-side without switching active DB + validate failure & success', async () => {
    // Reject anon key
    const anonTry = await httpJson(appBaseUrl, 'POST', '/api/admin/db/config/target', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        provider: 'supabase',
        environment: 'Staging',
        supabaseUrl: targetDb.baseUrl,
        serviceRoleKey: TARGET_ANON_KEY,
      },
    });
    assert.equal(anonTry.status, 400);
    assert.equal(anonTry.json.code, 'ANON_KEY_REJECTED');

    // Save incomplete target first and test connection failure
    const saveIncomplete = await httpJson(appBaseUrl, 'POST', '/api/admin/db/config/target', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        provider: 'supabase',
        environment: 'Staging',
        supabaseUrl: incompleteTargetDb.baseUrl,
        serviceRoleKey: TARGET_SERVICE_KEY,
      },
    });
    assert.equal(saveIncomplete.status, 200);
    assert.equal(saveIncomplete.rawText.includes(TARGET_SERVICE_KEY), false);
    assert.equal(fs.readFileSync(stateFile, 'utf8').includes(TARGET_SERVICE_KEY), false, 'Encrypted file must NOT store plaintext key');

    const failTest = await httpJson(appBaseUrl, 'POST', '/api/admin/db/config/test', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { useSavedTarget: true },
    });
    assert.equal(failTest.status, 200);
    assert.equal(failTest.json.ok, false);
    assert.equal(failTest.json.validation.missingTablesCount, 2);

    // Save healthy target and verify active DB did NOT switch yet
    const saveHealthy = await httpJson(appBaseUrl, 'POST', '/api/admin/db/config/target', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        provider: 'supabase',
        environment: 'Staging',
        supabaseUrl: targetDb.baseUrl,
        serviceRoleKey: TARGET_SERVICE_KEY,
      },
    });
    assert.equal(saveHealthy.status, 200);
    assert.equal(getServerDbConfig().supabaseUrl, sourceDb.baseUrl, 'Saving target must NOT alter active DB');

    const okTest = await httpJson(appBaseUrl, 'POST', '/api/admin/db/config/test', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { useSavedTarget: true },
    });
    assert.equal(okTest.status, 200);
    assert.equal(okTest.json.ok, true);
    assert.equal(okTest.json.validation.verifiedTablesCount, 114);
    assert.equal(okTest.json.validation.writePrivilegeOk, true);
  });

  test('5. Schema Compatibility Validator detects mismatches on incomplete target & compatibility on healthy target', async () => {
    const mismatchRes = await httpJson(appBaseUrl, 'POST', '/api/admin/db/schema/compare', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        useSavedTarget: false,
        supabaseUrl: incompleteTargetDb.baseUrl,
        serviceRoleKey: TARGET_SERVICE_KEY,
      },
    });
    assert.equal(mismatchRes.status, 200);
    assert.equal(mismatchRes.json.report.migrationEligible, false);
    assert.ok(mismatchRes.json.report.summary.missing >= 2);
    assert.ok(mismatchRes.json.report.summary.different >= 1);

    const healthyRes = await httpJson(appBaseUrl, 'POST', '/api/admin/db/schema/compare', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { useSavedTarget: true },
    });
    assert.equal(healthyRes.status, 200);
    assert.equal(healthyRes.json.report.migrationEligible, true);
    assert.equal(healthyRes.json.report.summary.targetTablesPresent, 114);
    assert.deepEqual(healthyRes.json.report.summary.extraTablesOnTarget, ['legacy_temp_notes']);
    assert.ok(healthyRes.json.report.markdownReport.includes('# Ensec ERP Schema Compatibility Report'));
  });

  test('6 & 7. Pre-migration validation blocks without backup or overwrite confirmation when target has data', async () => {
    // Missing backup confirmation
    const noBackup = await httpJson(appBaseUrl, 'POST', '/api/admin/db/migration/start', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { confirmSourceBackupTaken: false, waitForCompletion: true },
    });
    assert.equal(noBackup.status, 400);
    assert.equal(noBackup.json.code, 'PREFLIGHT_BLOCKED');

    // Target has existing data check
    targetDb.tables.set('banks', [{ id: 99, code: 'BNK-PRE', name: 'Existing Bank' }]);
    const preflightWarn = await httpJson(appBaseUrl, 'POST', '/api/admin/db/migration/preflight', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { confirmSourceBackupTaken: true, confirmTargetExistingData: false },
    });
    assert.equal(preflightWarn.status, 200);
    assert.equal(preflightWarn.json.preflight.targetExistingDataDetected, true);
    assert.equal(preflightWarn.json.preflight.canStartMigration, false);

    // Clear extra pre-seed row for clean count match assertion below
    targetDb.tables.set('banks', []);
  });

  test('8, 9, 10, 11 & 12. Self-ref ordering, 114-table topological order, batch retry, Storage/Auth/Sequences, Cutover guardrails & Cutover', async () => {
    // Verify self-referencing row sorter preserves parent before child
    const sortedOrg = sortSelfReferencingRows(
      sourceDb.tables.get('org_hierarchy')!,
      'id',
      'parent_id'
    );
    assert.equal(sortedOrg[0].id, 1, 'Parent org_hierarchy node must precede child');
    assert.equal(sortedOrg[1].id, 2);

    // Verify parent tables always precede children in MIGRATION_TABLE_ORDER
    const orderIdx = new Map(MIGRATION_TABLE_ORDER.map((t, i) => [t.name, i]));
    for (const spec of MIGRATION_TABLE_ORDER) {
      for (const p of spec.parentTables) {
        assert.ok(
          orderIdx.get(p)! < orderIdx.get(spec.name)!,
          `Parent ${p} must come before ${spec.name}`
        );
      }
    }

    // Attempt cutover BEFORE migration completes -> must fail cleanly
    const earlyCutover = await httpJson(appBaseUrl, 'POST', '/api/admin/db/cutover', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { confirmationPhrase: 'CUTOVER TO TARGET', confirmChecklist: true },
    });
    assert.equal(earlyCutover.status, 400);
    assert.equal(earlyCutover.json.code, 'NO_COMPLETED_MIGRATION');

    // Run full migration (with waitForCompletion=true for deterministic test)
    const migRes = await httpJson(appBaseUrl, 'POST', '/api/admin/db/migration/start', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { confirmSourceBackupTaken: true, waitForCompletion: true },
    });
    assert.equal(migRes.status, 200);
    assert.equal(migRes.json.ok, true);
    const run = migRes.json.run;
    assert.equal(run.status, 'Completed');
    assert.equal(run.completedTables, 114);
    assert.equal(run.failedTables, 0);
    assert.equal(run.countVerificationPassed, true);
    assert.equal(run.sequenceSyncMode, 'rpc');
    assert.equal(run.storageSummary.migratedBuckets, 1);
    assert.equal(run.storageSummary.migratedObjects, 1);

    // Check transient batch retry on warehouses succeeded without duplicate rows
    const whProgress = run.tableResults.find((t: any) => t.table === 'warehouses');
    assert.ok(whProgress.retriesUsed >= 1);
    assert.equal(targetDb.tables.get('warehouses')!.length, 1);

    // Check bcrypt password hash, PK, timestamps & storage content preserved verbatim
    const targetAdmin = targetDb.tables.get('users')!.find((u) => u.user_id === 'ADMIN');
    assert.ok(targetAdmin);
    assert.equal(targetAdmin.id, 1);
    assert.equal(targetAdmin.created_at, '2026-01-01T00:00:00Z');
    assert.equal(await bcrypt.compare('AdminPass!2026', targetAdmin.password), true);
    assert.ok(targetDb.buckets[0].files['claim-001.txt'].includes('sample-battery-photo-bytes'));

    // Execute Cutover (wrong phrase rejected first)
    const badPhraseCutover = await httpJson(appBaseUrl, 'POST', '/api/admin/db/cutover', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { migrationId: run.id, confirmationPhrase: 'WRONG', confirmChecklist: true },
    });
    assert.equal(badPhraseCutover.status, 400);

    const cutoverRes = await httpJson(appBaseUrl, 'POST', '/api/admin/db/cutover', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { migrationId: run.id, confirmationPhrase: 'CUTOVER TO TARGET', confirmChecklist: true },
    });
    assert.equal(cutoverRes.status, 200);
    assert.equal(cutoverRes.json.ok, true);
    assert.equal(cutoverRes.json.newConfigVersion, 2);
    assert.equal(getServerDbConfig().supabaseUrl, targetDb.baseUrl, 'Active server DB must now be targetDb');
    assert.equal(cutoverRes.rawText.includes(TARGET_SERVICE_KEY), false);
    assert.equal(cutoverRes.rawText.includes(SOURCE_SERVICE_KEY), false);
  });

  test('13 & 14. Active ERP reads newly switched DB + Controlled Rollback detects divergence & reverts safely', async () => {
    // Add a post-cutover row ONLY on targetDb and verify active ERP Gateway queries targetDb!
    targetDb.tables.get('banks')!.push({ id: 77, code: 'BNK-POST', name: 'Post Cutover Bank' });
    const gwRead = await httpJson(appBaseUrl, 'POST', '/api/erp/db/banks', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { operation: 'select', select: '*' },
    });
    assert.equal(gwRead.status, 200);
    assert.ok(
      gwRead.json.data.some((b: any) => b.code === 'BNK-POST'),
      'Express backend must query the switched active database immediately'
    );

    // Attempt rollback WITHOUT acknowledgeDataDivergence -> must return 409 DATA_DIVERGENCE_DETECTED
    const blockedRollback = await httpJson(appBaseUrl, 'POST', '/api/admin/db/rollback', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        reason: 'Post-cutover verification anomaly',
        confirmationPhrase: 'ROLLBACK TO PREVIOUS',
        acknowledgeDataDivergence: false,
      },
    });
    assert.equal(blockedRollback.status, 409);
    assert.equal(blockedRollback.json.code, 'DATA_DIVERGENCE_DETECTED');
    assert.ok(blockedRollback.json.divergentTables.some((d: any) => d.table === 'banks'));

    // Execute rollback WITH divergence acknowledgement -> reverts active DB back to sourceDb
    const rollbackRes = await httpJson(appBaseUrl, 'POST', '/api/admin/db/rollback', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        reason: 'Post-cutover verification anomaly',
        confirmationPhrase: 'ROLLBACK TO PREVIOUS',
        acknowledgeDataDivergence: true,
      },
    });
    assert.equal(rollbackRes.status, 200);
    assert.equal(rollbackRes.json.ok, true);
    assert.equal(rollbackRes.json.restoredConfigVersion, 3);
    assert.equal(getServerDbConfig().supabaseUrl, sourceDb.baseUrl, 'Active DB must revert to sourceDb');
    // Verify targetDb post-cutover row was NOT destroyed during rollback
    assert.ok(targetDb.tables.get('banks')!.some((b) => b.code === 'BNK-POST'));
  });

  test('11b. Concurrency lock prevents simultaneous migrations and mid-run failure retries idempotently', async () => {
    const { acquireDbOperationLock, releaseDbOperationLock } = await import('../server/db/store.ts');
    const lock = acquireDbOperationLock('migration', 'mig-lock-test', 'Super Admin');
    assert.equal(lock.acquired, true);
    try {
      const blocked = await httpJson(appBaseUrl, 'POST', '/api/admin/db/migration/start', {
        cookie: adminCookie,
        csrf: adminCsrf,
        body: { confirmSourceBackupTaken: true, confirmTargetExistingData: true },
      });
      assert.equal(blocked.status, 409);
      assert.equal(blocked.json.code, 'MIGRATION_LOCKED');
    } finally {
      releaseDbOperationLock();
    }

    // Simulate deterministic mid-run failure exceeding 3 retries on 'sales_orders', then recover & retry
    targetDb.upsertFailRemaining.set('sales_orders', 5);
    const failRun = await httpJson(appBaseUrl, 'POST', '/api/admin/db/migration/start', {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: {
        confirmSourceBackupTaken: true,
        confirmTargetExistingData: true,
        waitForCompletion: true,
      },
    });
    assert.equal(failRun.status, 500);
    assert.equal(failRun.json.ok, false);
    assert.equal(failRun.json.run.status, 'Failed');
    const failedRunId = failRun.json.run.id;

    // Clear fault & resume failed run idempotently
    targetDb.upsertFailRemaining.set('sales_orders', 0);
    const retryRes = await httpJson(appBaseUrl, 'POST', `/api/admin/db/migration/${failedRunId}/retry`, {
      cookie: adminCookie,
      csrf: adminCsrf,
      body: { waitForCompletion: true },
    });
    assert.equal(retryRes.status, 200);
    assert.equal(retryRes.json.ok, true);
    assert.equal(retryRes.json.run.status, 'Completed');
    assert.equal(retryRes.json.run.completedTables, 114);
    assert.equal(targetDb.tables.get('sales_orders')!.length, 1, 'Retry must not create duplicate rows');
  });
});
