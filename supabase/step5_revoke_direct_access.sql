-- 5단계 검토용 SQL: public.learning_notes 한 테이블만 대상으로 합니다.
-- 사용자가 Supabase SQL Editor에서 검토 후 직접 실행하세요.

-- 1) 적용 전 확인
select grantee, privilege_type
from information_schema.table_privileges
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select
  has_table_privilege('anon', 'public.learning_notes', 'SELECT') as anon_select,
  has_table_privilege('anon', 'public.learning_notes', 'INSERT') as anon_insert,
  has_table_privilege('anon', 'public.learning_notes', 'UPDATE') as anon_update,
  has_table_privilege('anon', 'public.learning_notes', 'DELETE') as anon_delete,
  has_table_privilege('authenticated', 'public.learning_notes', 'SELECT') as authenticated_select,
  has_table_privilege('authenticated', 'public.learning_notes', 'INSERT') as authenticated_insert,
  has_table_privilege('authenticated', 'public.learning_notes', 'UPDATE') as authenticated_update,
  has_table_privilege('authenticated', 'public.learning_notes', 'DELETE') as authenticated_delete;

-- 2) 이 테이블의 직접 클라이언트 권한만 회수
begin;
revoke all privileges on table public.learning_notes from public, anon, authenticated;
commit;

-- 3) 적용 후 확인: 첫 쿼리는 0행, 아래 8개 값은 모두 false여야 합니다.
select grantee, privilege_type
from information_schema.table_privileges
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select
  has_table_privilege('anon', 'public.learning_notes', 'SELECT') as anon_select,
  has_table_privilege('anon', 'public.learning_notes', 'INSERT') as anon_insert,
  has_table_privilege('anon', 'public.learning_notes', 'UPDATE') as anon_update,
  has_table_privilege('anon', 'public.learning_notes', 'DELETE') as anon_delete,
  has_table_privilege('authenticated', 'public.learning_notes', 'SELECT') as authenticated_select,
  has_table_privilege('authenticated', 'public.learning_notes', 'INSERT') as authenticated_insert,
  has_table_privilege('authenticated', 'public.learning_notes', 'UPDATE') as authenticated_update,
  has_table_privilege('authenticated', 'public.learning_notes', 'DELETE') as authenticated_delete;

-- service_role 권한, RLS, 정책, 다른 테이블/스키마 권한은 변경하지 않습니다.
