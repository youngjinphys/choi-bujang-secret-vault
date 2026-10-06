-- 4단계 RLS/최소 권한 제안 SQL
-- public.learning_notes 한 테이블만 대상으로 합니다.
-- 사용자가 검토한 뒤 Supabase SQL Editor에서 직접 실행하세요.

-- 1) 적용 전 확인
select grantee, privilege_type
from information_schema.role_table_grants
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

-- 2) learning_notes에만 최소 권한 + owner RLS 적용
begin;

revoke all on table public.learning_notes from public, anon, authenticated;
grant select, insert, update, delete on table public.learning_notes to authenticated;

alter table public.learning_notes enable row level security;

drop policy if exists learning_notes_owner_select on public.learning_notes;
drop policy if exists learning_notes_owner_insert on public.learning_notes;
drop policy if exists learning_notes_owner_update on public.learning_notes;
drop policy if exists learning_notes_owner_delete on public.learning_notes;

create policy learning_notes_owner_select
on public.learning_notes
for select
to authenticated
using ((select auth.uid()) = owner_id);

create policy learning_notes_owner_insert
on public.learning_notes
for insert
to authenticated
with check ((select auth.uid()) = owner_id);

create policy learning_notes_owner_update
on public.learning_notes
for update
to authenticated
using ((select auth.uid()) = owner_id)
with check ((select auth.uid()) = owner_id);

create policy learning_notes_owner_delete
on public.learning_notes
for delete
to authenticated
using ((select auth.uid()) = owner_id);

commit;

-- 3) 적용 후 확인
-- 기대값: anon 4개 false, authenticated 4개 true.
select grantee, privilege_type
from information_schema.role_table_grants
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

select policyname, cmd, roles
from pg_policies
where schemaname = 'public'
  and tablename = 'learning_notes'
order by policyname;
