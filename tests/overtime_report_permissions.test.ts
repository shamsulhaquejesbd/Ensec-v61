import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ALL_ERP_PAGES,
  OVERTIME_REPORT_ACTION_KEYS,
  PERMISSION_TEMPLATES,
  hasPageAction,
} from '../src/types/pagePermissions.ts';
import { resolveOvertimePermissions } from '../src/lib/overtimePermissions.ts';

const EXPECTED_REPORT_LABELS = [
  'Employee-wise Monthly Overtime Report',
  'Daily Factory Overtime Bill Report',
  'Production Batch-wise Overtime Cost Report',
  'Production Order-wise Overtime Cost Report',
  'Monthly Overtime Payroll Reconciliation Report',
  'Pending Overtime Approval Workflow Report',
  'Overtime Hours vs Production Output Report',
];

test('Overtime Management Hub includes Reports section with all 7 report checkboxes', () => {
  const otPage = ALL_ERP_PAGES.find((p) => p.id === 'overtime-management');
  assert.ok(otPage, 'overtime-management page definition must exist');

  const reportActions = otPage.actions.filter((a) => a.subsection === 'Reports');
  assert.equal(reportActions.length, 7);
  assert.deepEqual(
    reportActions.map((a) => a.label),
    EXPECTED_REPORT_LABELS
  );
  assert.deepEqual(
    reportActions.map((a) => a.key),
    [...OVERTIME_REPORT_ACTION_KEYS]
  );
});

test('hasPageAction and resolveOvertimePermissions enforce granular per-report access', () => {
  const selectiveUser = {
    id: 'u-1',
    role: 'Accounts / Finance',
    status: 'Active',
    permissions: {
      allowedModules: ['overtime-management'],
      pagePermissions: {
        'overtime-management': {
          view: true,
          view_reports: true,
          view_report_employee_monthly: true,
          view_report_daily_factory_bill: false,
          view_report_production_batch: true,
          view_report_production_order: false,
          view_report_payroll_reconciliation: false,
          view_report_pending_workflow: true,
          view_report_hours_vs_output: false,
        },
      },
    },
  };

  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_employee_monthly'), true);
  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_daily_factory_bill'), false);
  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_production_batch'), true);
  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_production_order'), false);
  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_payroll_reconciliation'), false);
  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_pending_workflow'), true);
  assert.equal(hasPageAction(selectiveUser, 'overtime-management', 'view_report_hours_vs_output'), false);

  const resolved = resolveOvertimePermissions(selectiveUser);
  assert.equal(resolved.viewReports, true);
  assert.equal(resolved.viewReportEmployeeMonthly, true);
  assert.equal(resolved.viewReportDailyFactoryBill, false);
  assert.equal(resolved.viewReportProductionBatch, true);
  assert.equal(resolved.viewReportProductionOrder, false);
  assert.equal(resolved.viewReportPayrollReconciliation, false);
  assert.equal(resolved.viewReportPendingWorkflow, true);
  assert.equal(resolved.viewReportHoursVsOutput, false);
});

test('Denying view_reports revokes all 7 individual Overtime reports even if sub-keys were true', () => {
  const revokedTabUser = {
    id: 'u-2',
    role: 'Factory Manager',
    status: 'Active',
    permissions: {
      allowedModules: ['overtime-management'],
      pagePermissions: {
        'overtime-management': {
          view: true,
          view_reports: false,
          view_report_employee_monthly: true,
          view_report_daily_factory_bill: true,
        },
      },
    },
  };

  for (const key of OVERTIME_REPORT_ACTION_KEYS) {
    assert.equal(hasPageAction(revokedTabUser, 'overtime-management', key), false);
  }
});

test('Legacy users with view_reports=true and undefined sub-keys retain report access', () => {
  const legacyUser = {
    id: 'u-3',
    role: 'Accounts / Finance',
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

  for (const key of OVERTIME_REPORT_ACTION_KEYS) {
    assert.equal(hasPageAction(legacyUser, 'overtime-management', key), true);
  }
});

test('Super Admin and Auditor template grant all 7 Overtime report permissions', () => {
  const superAdmin = { id: 'sa', role: 'Super Admin', status: 'Active' };
  for (const key of OVERTIME_REPORT_ACTION_KEYS) {
    assert.equal(hasPageAction(superAdmin, 'overtime-management', key), true);
  }

  const auditorTpl = PERMISSION_TEMPLATES.find((t) => t.id === 'template-auditor');
  assert.ok(auditorTpl);
  for (const key of OVERTIME_REPORT_ACTION_KEYS) {
    assert.equal(auditorTpl.permissions['overtime-management']?.[key], true);
  }
});
