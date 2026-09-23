-- 사이트 B 테스트용 계정 및 사이트 등록
-- 실행: supabase db execute --local < scripts/seed-site-b.sql

BEGIN;

-- 1. 두 번째 멤버 등록
INSERT INTO private.identity_members (id, handle, display_name, status)
VALUES (
  'b1000000-0000-4000-8000-000000000002',
  'alice',
  '앨리스',
  'active'
)
ON CONFLICT (id) DO NOTHING;

-- 2. 두 번째 사이트 등록 (포트 8081)
INSERT INTO private.identity_sites (
  id,
  member_id,
  origin,
  base_path,
  homepage_url,
  login_url,
  supabase_project_ref,
  status
)
VALUES (
  'b2000000-0000-4000-8000-000000000002',
  'b1000000-0000-4000-8000-000000000002',
  'http://127.0.0.1:8081',
  '/',
  'http://127.0.0.1:8081/',
  'http://127.0.0.1:8081/login',
  'localdev456',
  'active'
)
ON CONFLICT (id) DO NOTHING;

COMMIT;
