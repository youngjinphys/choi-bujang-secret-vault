-- 4단계 학습용 소유자 seed SQL
-- 실제 이메일을 Git에 넣지 않기 위해 아래 두 placeholder는 의도적으로 남겨 둡니다.
-- Supabase SQL Editor에서 실행하기 전에 [A_EMAIL], [B_EMAIL]을 실습 계정 이메일로 바꾸세요.
-- 이 스크립트는 현재 4개의 미소유 가상 메모가 있을 때만 실행되며 다른 상태에서는 중단합니다.

begin;

do $$
declare
  v_a_email text := '[A_EMAIL]';
  v_b_email text := '[B_EMAIL]';
  v_a_id uuid;
  v_b_id uuid;
  v_a_count integer;
  v_b_count integer;
  v_total integer;
  v_unowned integer;
begin
  if v_a_email in ('', '[A_EMAIL]') or v_b_email in ('', '[B_EMAIL]') then
    raise exception 'A/B 이메일 placeholder를 실제 실습 계정 이메일로 바꿔 주세요.';
  end if;
  if lower(v_a_email) = lower(v_b_email) then
    raise exception 'A와 B는 서로 다른 계정이어야 합니다.';
  end if;

  select count(*), min(id::text)::uuid
    into v_a_count, v_a_id
  from auth.users
  where lower(email) = lower(v_a_email);

  select count(*), min(id::text)::uuid
    into v_b_count, v_b_id
  from auth.users
  where lower(email) = lower(v_b_email);

  if v_a_count <> 1 or v_b_count <> 1 then
    raise exception 'A/B 이메일은 auth.users에서 각각 정확히 한 계정과 일치해야 합니다.';
  end if;

  select count(*), count(*) filter (where owner_id is null)
    into v_total, v_unowned
  from public.learning_notes;

  if v_total <> 4 or v_unowned <> 4 then
    raise exception '예상한 4개의 미소유 가상 메모 상태가 아닙니다. 현재 자료를 먼저 확인하세요.';
  end if;

  with ranked as (
    select id, row_number() over (order by created_at, id) as rn
    from public.learning_notes
    where owner_id is null
  )
  update public.learning_notes as n
  set
    owner_id = case when ranked.rn <= 3 then v_a_id else v_b_id end,
    title = case when ranked.rn = 4 then 'B 소유 시험 메모' else n.title end,
    content = case when ranked.rn = 4
      then '4단계 소유자 격리 확인을 위한 공개 가능한 가상 시험 메모입니다.'
      else n.content end
  from ranked
  where n.id = ranked.id;
end
$$;

commit;

-- 적용 뒤 확인: A는 3건, B는 1건이어야 하고 owner_id가 NULL인 행은 없어야 합니다.
with identities as (
  select 'A' as label, id
  from auth.users
  where lower(email) = lower('[A_EMAIL]')
  union all
  select 'B' as label, id
  from auth.users
  where lower(email) = lower('[B_EMAIL]')
)
select
  identities.label,
  identities.id as owner_id,
  count(notes.id) as note_count
from identities
left join public.learning_notes as notes on notes.owner_id = identities.id
group by identities.label, identities.id
order by identities.label;

select count(*) as unowned_note_count
from public.learning_notes
where owner_id is null;
