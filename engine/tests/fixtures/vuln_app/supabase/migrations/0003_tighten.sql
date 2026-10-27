create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text
);

alter table public.notes enable row level security;

create policy "notes_select_all" on public.notes for select using (true);

drop policy "notes_select_all" on public.notes;

create policy "notes_select_own" on public.notes for select using (auth.uid() = user_id);
