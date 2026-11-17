-- ============================================================================
-- Ensec ERP - Phase 4 Optional Database Migration & Schema Inspection Helpers
-- ============================================================================
-- Execute this SQL in the Supabase SQL Editor (Source & Target projects) ONLY
-- if you want live PostgreSQL catalog verification for indexes, sequences,
-- views, extensions, RLS status, policies, and automated sequence sync.
--
-- Security Model (Phase 3 Compatible):
-- - All functions run as SECURITY DEFINER in public schema with locked search_path
-- - EXECUTE is strictly REVOKED from PUBLIC, anon, and authenticated roles
-- - EXECUTE is granted EXCLUSIVELY to service_role (used by Express backend)
-- - Arbitrary SQL execution from clients is NEVER permitted
-- ============================================================================

CREATE OR REPLACE FUNCTION public.ensec_phase4_inspect_metadata()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  result jsonb;
BEGIN
  result := jsonb_build_object(
    'inspectedAt', now(),
    'extensions', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('name', e.extname, 'version', e.extversion) ORDER BY e.extname)
      FROM pg_extension e
    ), '[]'::jsonb),
    'tables', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'table', t.tablename,
        'rlsEnabled', t.rowsecurity
      ) ORDER BY t.tablename)
      FROM pg_tables t
      WHERE t.schemaname = 'public'
    ), '[]'::jsonb),
    'views', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('name', v.viewname) ORDER BY v.viewname)
      FROM pg_views v
      WHERE v.schemaname = 'public'
    ), '[]'::jsonb),
    'indexes', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'table', i.tablename,
        'name', i.indexname,
        'unique', (i.indexdef ILIKE 'CREATE UNIQUE INDEX%')
      ) ORDER BY i.tablename, i.indexname)
      FROM pg_indexes i
      WHERE i.schemaname = 'public'
    ), '[]'::jsonb),
    'sequences', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'name', s.sequencename,
        'lastValue', s.last_value,
        'startValue', s.start_value
      ) ORDER BY s.sequencename)
      FROM pg_sequences s
      WHERE s.schemaname = 'public'
    ), '[]'::jsonb),
    'policies', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'table', p.tablename,
        'name', p.policyname,
        'permissive', p.permissive,
        'roles', p.roles,
        'cmd', p.cmd,
        'qual', p.qual,
        'withCheck', p.with_check
      ) ORDER BY p.tablename, p.policyname)
      FROM pg_policies p
      WHERE p.schemaname = 'public'
    ), '[]'::jsonb),
    'constraints', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'table', tc.table_name,
        'name', tc.constraint_name,
        'type', tc.constraint_type
      ) ORDER BY tc.table_name, tc.constraint_name)
      FROM information_schema.table_constraints tc
      WHERE tc.table_schema = 'public'
        AND tc.constraint_type IN ('PRIMARY KEY', 'FOREIGN KEY', 'UNIQUE')
    ), '[]'::jsonb)
  );
  RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION public.ensec_phase4_sync_sequence(
  p_table_name text,
  p_column_name text DEFAULT 'id'
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  v_seq_name text;
  v_max_id bigint;
  v_next_val bigint;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_tables
    WHERE schemaname = 'public' AND tablename = p_table_name
  ) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'Unknown public table');
  END IF;

  v_seq_name := pg_get_serial_sequence(format('public.%I', p_table_name), p_column_name);
  IF v_seq_name IS NULL THEN
    RETURN jsonb_build_object('ok', true, 'skipped', true, 'reason', 'No serial sequence bound');
  END IF;

  EXECUTE format('SELECT COALESCE(MAX(%I), 0)::bigint FROM public.%I', p_column_name, p_table_name)
    INTO v_max_id;

  IF v_max_id <= 0 THEN
    v_next_val := setval(v_seq_name, 1, false);
  ELSE
    v_next_val := setval(v_seq_name, v_max_id, true);
  END IF;

  RETURN jsonb_build_object(
    'ok', true,
    'table', p_table_name,
    'sequence', v_seq_name,
    'maxId', v_max_id,
    'setvalResult', v_next_val
  );
END;
$$;

REVOKE ALL ON FUNCTION public.ensec_phase4_inspect_metadata() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ensec_phase4_inspect_metadata() TO service_role;

REVOKE ALL ON FUNCTION public.ensec_phase4_sync_sequence(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ensec_phase4_sync_sequence(text, text) TO service_role;
