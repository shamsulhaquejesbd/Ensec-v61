-- ============================================================================
-- Ensec ERP & Distribution Management Platform
-- Phase 3 Migration: Strict RLS Hardening, Least-Privilege Access & Lock-Down
-- ============================================================================
--
-- PURPOSE:
--   1. Enable Row Level Security (RLS) on ALL 114 public ERP tables.
--   2. Remove all 59 permissive/unrestricted "Allow public ..." policies
--      (USING (true) / WITH CHECK (true)) and dynamically sweep any other
--      permissive anon/authenticated/public policies in schema `public`.
--   3. Revoke all direct REST API (PostgREST) / Data API privileges from
--      `PUBLIC`, `anon`, and `authenticated` roles across all tables, views,
--      sequences, and routines in schema `public`.
--   4. Harden `public.safe_users` view (`security_invoker = true`) and
--      remove ERP tables from `supabase_realtime` publication (realtime
--      updates are served exclusively via authenticated Express SSE).
--   5. Preserve 100% of existing tables, columns, constraints, indexes,
--      and business records (ZERO DROP TABLE / DROP COLUMN / TRUNCATE / DELETE).
--
-- ARCHITECTURE NOTE:
--   The Express backend connects exclusively via SUPABASE_SERVICE_ROLE_KEY
--   (server-only secret). In Supabase PostgreSQL, `service_role` carries the
--   BYPASSRLS attribute and retains full backend operational access, while
--   Express enforces HttpOnly cookie authentication, CSRF/Origin checks,
--   59-table RBAC, action-level permissions, and field sanitization.
--
-- PRE-DEPLOYMENT BACKUP PROCEDURE (Run before applying in production):
--   1. In Supabase Dashboard -> Database -> Backups, verify or trigger a
--      manual backup / point-in-time snapshot.
--   2. Export current policy & privilege state via pg_dump or SQL Editor:
--        pg_dump --schema-only --schema=public "$DATABASE_URL" > pre_phase3_schema_backup.sql
--      Or snapshot policies in SQL Editor:
--        SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
--        FROM pg_policies WHERE schemaname = 'public' ORDER BY tablename, policyname;
--
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- SECTION 1: Drop All 59 Known Permissive Policies from supabase_schema.sql
-- ----------------------------------------------------------------------------
-- Auth, Master Data, Sales, TA/DA, Warranty, Attendance, Cash Book
DROP POLICY IF EXISTS "Allow public access" ON public.users;
DROP POLICY IF EXISTS "Allow public access" ON public.warehouses;
DROP POLICY IF EXISTS "Allow public access" ON public.distributors;
DROP POLICY IF EXISTS "Allow public access" ON public.customers;
DROP POLICY IF EXISTS "Allow public access" ON public.products;
DROP POLICY IF EXISTS "Allow public access" ON public.raw_material_classifications;
DROP POLICY IF EXISTS "Allow public access" ON public.raw_material_categories;
DROP POLICY IF EXISTS "Allow public access" ON public.raw_materials;
DROP POLICY IF EXISTS "Allow public access" ON public.sales_orders;
DROP POLICY IF EXISTS "Allow public access" ON public.tada_claims;
DROP POLICY IF EXISTS "Allow public access" ON public.warranty_tickets;
DROP POLICY IF EXISTS "Allow public access" ON public.attendance_logs;
DROP POLICY IF EXISTS "Allow public access" ON public.cash_book_entries;
DROP POLICY IF EXISTS "Allow public access" ON public.product_categories;
DROP POLICY IF EXISTS "Allow public access" ON public.product_brands;
DROP POLICY IF EXISTS "Allow public access" ON public.customer_categories;
DROP POLICY IF EXISTS "Allow public access" ON public.org_hierarchy;
DROP POLICY IF EXISTS "Allow public access" ON public.departments;
DROP POLICY IF EXISTS "Allow public access" ON public.banks;
DROP POLICY IF EXISTS "Allow public access" ON public.units_of_measurement;
DROP POLICY IF EXISTS "Allow public access" ON public.field_force_reps;
DROP POLICY IF EXISTS "Allow public access" ON public.offers_promotions;

-- CRM Agreements (4 separate permissive policies)
DROP POLICY IF EXISTS "Allow public read access to crm_agreements" ON public.crm_agreements;
DROP POLICY IF EXISTS "Allow public insert to crm_agreements" ON public.crm_agreements;
DROP POLICY IF EXISTS "Allow public update to crm_agreements" ON public.crm_agreements;
DROP POLICY IF EXISTS "Allow public delete to crm_agreements" ON public.crm_agreements;

-- Installments, Collections & SMS
DROP POLICY IF EXISTS "Allow public all installment_plans" ON public.installment_plans;
DROP POLICY IF EXISTS "Allow public all installment_schedules" ON public.installment_schedules;
DROP POLICY IF EXISTS "Allow public all installment_payments" ON public.installment_payments;
DROP POLICY IF EXISTS "Allow public all installment_payment_allocations" ON public.installment_payment_allocations;
DROP POLICY IF EXISTS "Allow public all installment_notifications" ON public.installment_notifications;
DROP POLICY IF EXISTS "Allow public all installment_settings" ON public.installment_settings;
DROP POLICY IF EXISTS "Allow public all installment_audit_logs" ON public.installment_audit_logs;
DROP POLICY IF EXISTS "Allow public all collection_assignments" ON public.collection_assignments;
DROP POLICY IF EXISTS "Allow public all collection_followups" ON public.collection_followups;
DROP POLICY IF EXISTS "Allow public all collection_escalations" ON public.collection_escalations;
DROP POLICY IF EXISTS "Allow public all sms_templates" ON public.sms_templates;
DROP POLICY IF EXISTS "Allow public all sms_automation_rules" ON public.sms_automation_rules;
DROP POLICY IF EXISTS "Allow public all sms_logs" ON public.sms_logs;
DROP POLICY IF EXISTS "Allow public all sms_gateway_settings" ON public.sms_gateway_settings;

-- Manufacturing Costing & Expenses
DROP POLICY IF EXISTS "Allow public access" ON public.expense_entries;
DROP POLICY IF EXISTS "Allow public access" ON public.production_cost_allocations;

-- Overtime & Attendance Geofencing
DROP POLICY IF EXISTS "Allow public all employee_overtimes" ON public.employee_overtimes;
DROP POLICY IF EXISTS "Allow public all overtime_policies" ON public.overtime_policies;
DROP POLICY IF EXISTS "Allow public all overtime_requests" ON public.overtime_requests;
DROP POLICY IF EXISTS "Allow public all overtime_attendances" ON public.overtime_attendances;
DROP POLICY IF EXISTS "Allow public all overtime_batch_allocations" ON public.overtime_batch_allocations;
DROP POLICY IF EXISTS "Allow public all overtime_audit_logs" ON public.overtime_audit_logs;
DROP POLICY IF EXISTS "Allow public all office_locations" ON public.office_locations;
DROP POLICY IF EXISTS "Allow public all attendance_rejected_attempts" ON public.attendance_rejected_attempts;

-- General Ledger & Accounting
DROP POLICY IF EXISTS "Allow public all chart_of_accounts" ON public.chart_of_accounts;
DROP POLICY IF EXISTS "Allow public all financial_years" ON public.financial_years;
DROP POLICY IF EXISTS "Allow public all accounting_periods" ON public.accounting_periods;
DROP POLICY IF EXISTS "Allow public all accounting_vouchers" ON public.accounting_vouchers;
DROP POLICY IF EXISTS "Allow public all accounting_voucher_lines" ON public.accounting_voucher_lines;
DROP POLICY IF EXISTS "Allow public all general_ledger_entries" ON public.general_ledger_entries;
DROP POLICY IF EXISTS "Allow public all account_opening_balances" ON public.account_opening_balances;
DROP POLICY IF EXISTS "Allow public all accounting_settings" ON public.accounting_settings;
DROP POLICY IF EXISTS "Allow public all account_audit_logs" ON public.account_audit_logs;

-- Defensive sweep: drop any remaining public/anon/authenticated policies in schema `public`
-- so no legacy or ad-hoc permissive policy can bypass default-deny RLS.
DO $$
DECLARE
  pol RECORD;
BEGIN
  FOR pol IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND (
        roles && ARRAY['public', 'anon', 'authenticated']::name[]
        OR LOWER(COALESCE(qual, '')) = 'true'
        OR LOWER(COALESCE(with_check, '')) = 'true'
      )
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I;', pol.policyname, pol.schemaname, pol.tablename);
  END LOOP;
END $$;


-- ----------------------------------------------------------------------------
-- SECTION 2: Enable Row Level Security (Default-Deny) on ALL 114 ERP Tables
-- ----------------------------------------------------------------------------
-- Note: With RLS enabled and zero policies for `anon` / `authenticated` / `public`,
-- PostgreSQL denies all direct REST API reads and writes by default.

-- 2A. Auth & Security (2)
ALTER TABLE IF EXISTS public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.audit_logs ENABLE ROW LEVEL SECURITY;

-- 2B. Basic Data & Master Setup (17)
ALTER TABLE IF EXISTS public.warehouses ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.distributors ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.products ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.product_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.product_brands ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.customer_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.raw_material_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.raw_material_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.raw_materials ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.org_hierarchy ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.banks ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.units_of_measurement ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.field_force_reps ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.offers_promotions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.office_locations ENABLE ROW LEVEL SECURITY;

-- 2C. Sales, Distribution & CRM (9)
ALTER TABLE IF EXISTS public.sales_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.retailer_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.retailer_order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.retailer_delivery_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.retailer_cancellations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.market_hierarchies ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.crm_agreements ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.visit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.tada_claims ENABLE ROW LEVEL SECURITY;

-- 2D. Stock & Warehouse Inventory (14)
ALTER TABLE IF EXISTS public.stock_cid_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_cid_receipt_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_opening_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_issue_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_primary_returns ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_damage_returns ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_transfer_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_adjustments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.requisitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.requisition_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.stock_ledger ENABLE ROW LEVEL SECURITY;

-- 2E. Procurement, Raw Materials & Manufacturing (18)
ALTER TABLE IF EXISTS public.suppliers ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.import_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.import_order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.raw_material_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.raw_material_receipt_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.inventory_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.inventory_movements ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.bill_of_materials ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.bom_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.production_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.material_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.material_issue_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.production_consumption ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.production_costs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.finished_goods_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.optimum_statement ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.expense_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.production_cost_allocations ENABLE ROW LEVEL SECURITY;

-- 2F. Installments, Collections & SMS (14)
ALTER TABLE IF EXISTS public.installment_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.installment_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.installment_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.installment_payment_allocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.installment_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.installment_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.installment_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.collection_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.collection_followups ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.collection_escalations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.sms_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.sms_automation_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.sms_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.sms_gateway_settings ENABLE ROW LEVEL SECURITY;

-- 2G. Warranty & Service (7)
ALTER TABLE IF EXISTS public.warranty_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.battery_receiving_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.technical_inspections ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.service_job_cards ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.service_invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.service_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.warranty_delivery_dispatches ENABLE ROW LEVEL SECURITY;

-- 2H. Payroll, HR, Attendance & Overtime (17)
ALTER TABLE IF EXISTS public.attendance_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.employee_salary_structures ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.employee_attendances ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.attendance_rejected_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.employee_leaves ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.employee_advances_loans ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.employee_overtimes ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.employee_bonuses ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.monthly_payroll_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.salary_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.payroll_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.payroll_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.overtime_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.overtime_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.overtime_attendances ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.overtime_batch_allocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.overtime_audit_logs ENABLE ROW LEVEL SECURITY;

-- 2I. Finance, Cash/Bank & General Ledger (16)
ALTER TABLE IF EXISTS public.cash_book_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.cash_bank_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.cash_bank_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.opening_balance_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.expense_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.service_income_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.chart_of_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.financial_years ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.accounting_periods ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.accounting_vouchers ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.accounting_voucher_lines ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.general_ledger_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.account_opening_balances ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.accounting_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.account_audit_logs ENABLE ROW LEVEL SECURITY;

-- Safety loop: also enable RLS on any additional tables present in `public`
DO $$
DECLARE
  tbl RECORD;
BEGIN
  FOR tbl IN
    SELECT schemaname, tablename
    FROM pg_tables
    WHERE schemaname = 'public'
      AND rowsecurity = false
  LOOP
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY;', tbl.schemaname, tbl.tablename);
  END LOOP;
END $$;


-- ----------------------------------------------------------------------------
-- SECTION 3: Least-Privilege Grants & Revocation of Public / Anon / Auth Access
-- ----------------------------------------------------------------------------
-- Revoke all table, view, sequence, routine, and schema usage grants from
-- PUBLIC, `anon`, and `authenticated` roles so direct Supabase REST / Data API
-- requests using publishable/anon keys or unprivileged user JWTs are rejected.

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM PUBLIC, anon, authenticated;
REVOKE USAGE, CREATE ON SCHEMA public FROM PUBLIC, anon, authenticated;

-- Override permissive ALTER DEFAULT PRIVILEGES from supabase_schema.sql
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON ROUTINES FROM PUBLIC, anon, authenticated;

-- Preserve required privileges exclusively for `postgres` and `service_role`
GRANT USAGE ON SCHEMA public TO postgres, service_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres, service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres, service_role;
GRANT ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public TO postgres, service_role;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO postgres, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO postgres, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON ROUTINES TO postgres, service_role;


-- ----------------------------------------------------------------------------
-- SECTION 4: View & Realtime Publication Hardening
-- ----------------------------------------------------------------------------
-- Ensure `public.safe_users` executes with invoker privileges (PG 15+) and is
-- inaccessible to `anon` / `authenticated` / `PUBLIC`.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_views WHERE schemaname = 'public' AND viewname = 'safe_users') THEN
    EXECUTE 'ALTER VIEW public.safe_users SET (security_invoker = true);';
    EXECUTE 'REVOKE ALL PRIVILEGES ON public.safe_users FROM PUBLIC, anon, authenticated;';
    EXECUTE 'GRANT SELECT ON public.safe_users TO postgres, service_role;';
  END IF;
END $$;

-- Phase 2 replaced direct client Supabase Realtime subscriptions with
-- authenticated Express Server-Sent Events (/api/erp/events).
-- Remove ERP tables from `supabase_realtime` publication if present so no
-- unauthenticated/direct realtime WAL stream exposes ERP mutations.
DO $$
DECLARE
  pub_tbl RECORD;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime' AND puballtables = false
  ) THEN
    FOR pub_tbl IN
      SELECT schemaname, tablename
      FROM pg_publication_tables
      WHERE pubname = 'supabase_realtime'
        AND schemaname = 'public'
    LOOP
      EXECUTE format('ALTER PUBLICATION supabase_realtime DROP TABLE %I.%I;', pub_tbl.schemaname, pub_tbl.tablename);
    END LOOP;
  END IF;
END $$;

COMMIT;


-- ============================================================================
-- SECTION 5: Post-Migration Verification Queries (Run Read-Only in SQL Editor)
-- ============================================================================
-- 1) Verify ALL tables in `public` have RLS enabled (expect 0 rows with rowsecurity = false):
--    SELECT tablename, rowsecurity
--    FROM pg_tables
--    WHERE schemaname = 'public' AND rowsecurity = false
--    ORDER BY tablename;
--
-- 2) Verify ZERO permissive policies remain for public / anon / authenticated:
--    SELECT tablename, policyname, roles, cmd, qual, with_check
--    FROM pg_policies
--    WHERE schemaname = 'public'
--    ORDER BY tablename, policyname;
--
-- 3) Verify ZERO privileges remain for `anon` or `authenticated` on `public` tables:
--    SELECT grantee, table_name, privilege_type
--    FROM information_schema.role_table_grants
--    WHERE table_schema = 'public'
--      AND grantee IN ('PUBLIC', 'anon', 'authenticated')
--    ORDER BY table_name, grantee, privilege_type;
--
-- 4) Verify `service_role` retains required privileges:
--    SELECT COUNT(DISTINCT table_name) AS service_role_accessible_tables
--    FROM information_schema.role_table_grants
--    WHERE table_schema = 'public' AND grantee = 'service_role';


-- ============================================================================
-- SECTION 6: Emergency Rollback Procedure (Manual Execution Only)
-- ============================================================================
-- Only run this rollback block if an unexpected external client dependency
-- requires temporary restoration while migrating to the Express backend:
--
-- BEGIN;
--   GRANT USAGE ON SCHEMA public TO anon, authenticated;
--   GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;
--   GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
--   GRANT ALL ON ALL ROUTINES IN SCHEMA public TO anon, authenticated;
--   -- Optionally restore `pre_phase3_schema_backup.sql` policies from backup.
-- COMMIT;
-- ============================================================================
