import assert from 'node:assert/strict';
import test from 'node:test';
import {
  TABLE_RBAC_CONFIG,
  authorizeTableOperation,
  canReadErpTable,
} from '../src/lib/tableRbac.ts';
import {
  TABLE_RBAC_CONFIG as GATEWAY_TABLE_RBAC_CONFIG,
  authorizeTableOperation as gatewayAuthorizeTableOperation,
} from '../server/routes/erpGateway.ts';

const PREVIOUSLY_403_TABLES_FOR_RESTRICTED_USER = [
  'warehouses',
  'raw_materials',
  'products',
  'stock_transfers',
  'stock_cid_receipts',
  'product_categories',
  'raw_material_categories',
  'product_brands',
  'customer_categories',
  'distributors',
  'customers',
  'installment_plans',
  'installment_schedules',
  'installment_payments',
  'sales_orders',
  'chart_of_accounts',
  'financial_years',
  'accounting_vouchers',
  'general_ledger_entries',
];

const OVERTIME_ONLY_USER = {
  id: 'u-ot-1',
  role: 'Staff',
  status: 'Active',
  permissions: {
    allowedModules: ['overtime-management'],
    pagePermissions: {
      'overtime-management': {
        view: true,
        view_reports: true,
      },
    },
  },
};

test('erpGateway re-exports exact shared TABLE_RBAC_CONFIG and authorizeTableOperation', () => {
  assert.strictEqual(GATEWAY_TABLE_RBAC_CONFIG, TABLE_RBAC_CONFIG);
  assert.strictEqual(gatewayAuthorizeTableOperation, authorizeTableOperation);
  assert.equal(Object.keys(TABLE_RBAC_CONFIG).length, 59);
});

test('Overtime-only user can read overtime & supporting tables while restricted tables return false (no 403 prefetch)', () => {
  // Permitted overtime & supporting tables
  const permittedTables = [
    'production_orders',
    'departments',
    'field_force_reps',
    'office_locations',
    'employee_attendances',
    'overtime_requests',
    'overtime_attendance_logs',
    'overtime_policies',
    'overtime_audit_logs',
    'employee_overtimes',
  ];

  for (const table of permittedTables) {
    assert.equal(
      canReadErpTable(OVERTIME_ONLY_USER, table),
      true,
      `Expected overtime user to be allowed to read ${table}`
    );
  }

  // Non-permitted tables must return false before fetching
  for (const table of PREVIOUSLY_403_TABLES_FOR_RESTRICTED_USER) {
    assert.equal(
      canReadErpTable(OVERTIME_ONLY_USER, table),
      false,
      `Expected overtime user NOT to prefetch restricted table ${table}`
    );
    assert.equal(
      authorizeTableOperation(OVERTIME_ONLY_USER, table, 'select').allowed,
      false
    );
  }
});

test('Unauthenticated / guest user is denied on all 59 tables (no pre-auth 401 prefetch)', () => {
  const unauthenticatedVariants = [null, undefined, { id: '', role: 'Super Admin', status: 'Active' }, { id: 'guest', role: 'Super Admin', status: 'Active' }];
  for (const candidate of unauthenticatedVariants) {
    for (const table of Object.keys(TABLE_RBAC_CONFIG)) {
      assert.equal(
        canReadErpTable(candidate, table),
        false,
        `Expected unauthenticated user to be denied read on ${table}`
      );
      assert.equal(
        authorizeTableOperation(candidate, table, 'select').allowed,
        false
      );
    }
  }
});

test('Blocked or Inactive user is denied on all tables even with permissions', () => {
  for (const status of ['Blocked', 'Inactive']) {
    const blockedUser = {
      ...OVERTIME_ONLY_USER,
      status,
    };
    for (const table of Object.keys(TABLE_RBAC_CONFIG)) {
      assert.equal(canReadErpTable(blockedUser, table), false);
      assert.equal(authorizeTableOperation(blockedUser, table, 'select').allowed, false);
    }
  }
});

test('Super Admin retains access to all 59 registered tables', () => {
  const superAdmin = {
    id: 'sa-1',
    role: 'Super Admin',
    status: 'Active',
  };
  for (const table of Object.keys(TABLE_RBAC_CONFIG)) {
    assert.equal(
      canReadErpTable(superAdmin, table),
      true,
      `Expected Super Admin to be allowed to read ${table}`
    );
  }
});
