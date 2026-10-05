begin;

do $$
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'learning_notes'
      and column_name = 'id'
      and data_type = 'bigint'
  ) then
    alter table public.learning_notes
      alter column id drop identity if exists;
    alter table public.learning_notes
      alter column id drop default;
    alter table public.learning_notes
      alter column id type uuid using gen_random_uuid();
    alter table public.learning_notes
      alter column id set default gen_random_uuid();
  end if;
end
$$;

create index if not exists learning_notes_owner_id_idx
  on public.learning_notes (owner_id);

alter table public.learning_notes enable row level security;
revoke all on table public.learning_notes from anon, authenticated;
grant select, insert, update, delete on table public.learning_notes to service_role;

commit;

-- Step 3 intentionally does not add owner-based RLS policies.
-- The Vercel server verifies login, records owner_id on POST, and still permits
-- authenticated cross-owner item access so the BOLA gap remains visible for step 4.
