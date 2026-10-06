-- 5단계 검토용 SQL: public.learning_notes 한 테이블만 대상으로 합니다.
-- 사용자가 Supabase SQL Editor에서 검토 후 직접 실행하세요.
-- 서버 함수의 service_role 권한, RLS 정책, 다른 테이블/스키마는 변경하지 않습니다.

-- 1) 적용 전: 명시적 grant 확인.
-- table_privileges는 PUBLIC grant를 포함할 수 있고, role_table_grants는 PUBLIC을 통한 접근을 의도적으로 생략합니다.
select grantee, privilege_type
from information_schema.table_privileges
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('anon', 'authenticated')
order by grantee, privilege_type;

-- 2) 적용 전: effective CRUD 권한 확인.
-- has_table_privilege의 PUBLIC pseudo-role은 문자열 'public'로 지정합니다.
select
  has_table_privilege('public', 'public.learning_notes', 'SELECT') as public_select,
  has_table_privilege('public', 'public.learning_notes', 'INSERT') as public_insert,
  has_table_privilege('public', 'public.learning_notes', 'UPDATE') as public_update,
  has_table_privilege('public', 'public.learning_notes', 'DELETE') as public_delete,
  has_table_privilege('anon', 'public.learning_notes', 'SELECT') as anon_select,
  has_table_privilege('anon', 'public.learning_notes', 'INSERT') as anon_insert,
  has_table_privilege('anon', 'public.learning_notes', 'UPDATE') as anon_update,
  has_table_privilege('anon', 'public.learning_notes', 'DELETE') as anon_delete,
  has_table_privilege('authenticated', 'public.learning_notes', 'SELECT') as authenticated_select,
  has_table_privilege('authenticated', 'public.learning_notes', 'INSERT') as authenticated_insert,
  has_table_privilege('authenticated', 'public.learning_notes', 'UPDATE') as authenticated_update,
  has_table_privilege('authenticated', 'public.learning_notes', 'DELETE') as authenticated_delete,
  has_table_privilege('service_role', 'public.learning_notes', 'SELECT') as service_select,
  has_table_privilege('service_role', 'public.learning_notes', 'INSERT') as service_insert,
  has_table_privilege('service_role', 'public.learning_notes', 'UPDATE') as service_update,
  has_table_privilege('service_role', 'public.learning_notes', 'DELETE') as service_delete;

-- 3) learning_notes의 직접 클라이언트 권한만 회수.
begin;
revoke all privileges on table public.learning_notes from public, anon, authenticated;
commit;

-- 4) 적용 후: PUBLIC·anon·authenticated 명시적 grant는 0행이어야 합니다.
select grantee, privilege_type
from information_schema.table_privileges
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated')
order by grantee, privilege_type;

select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('anon', 'authenticated')
order by grantee, privilege_type;

-- 5) 적용 후 기대값:
-- public/anon/authenticated의 CRUD 12개는 모두 false,
-- service_role의 CRUD 4개는 모두 true여야 서버 함수 동작을 보존합니다.
select
  has_table_privilege('public', 'public.learning_notes', 'SELECT') as public_select,
  has_table_privilege('public', 'public.learning_notes', 'INSERT') as public_insert,
  has_table_privilege('public', 'public.learning_notes', 'UPDATE') as public_update,
  has_table_privilege('public', 'public.learning_notes', 'DELETE') as public_delete,
  has_table_privilege('anon', 'public.learning_notes', 'SELECT') as anon_select,
  has_table_privilege('anon', 'public.learning_notes', 'INSERT') as anon_insert,
  has_table_privilege('anon', 'public.learning_notes', 'UPDATE') as anon_update,
  has_table_privilege('anon', 'public.learning_notes', 'DELETE') as anon_delete,
  has_table_privilege('authenticated', 'public.learning_notes', 'SELECT') as authenticated_select,
  has_table_privilege('authenticated', 'public.learning_notes', 'INSERT') as authenticated_insert,
  has_table_privilege('authenticated', 'public.learning_notes', 'UPDATE') as authenticated_update,
  has_table_privilege('authenticated', 'public.learning_notes', 'DELETE') as authenticated_delete,
  has_table_privilege('service_role', 'public.learning_notes', 'SELECT') as service_select,
  has_table_privilege('service_role', 'public.learning_notes', 'INSERT') as service_insert,
  has_table_privilege('service_role', 'public.learning_notes', 'UPDATE') as service_update,
  has_table_privilege('service_role', 'public.learning_notes', 'DELETE') as service_delete;
