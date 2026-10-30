-- Heist's own database: cached analyses and the daily model spend.
-- Only the engine reads or writes it, server side, with the service role key. Nothing here is
-- for the browser: RLS is on with no policies, and anon, authenticated and public get no
-- grants at all, so the public anon key opens nothing.

create table public.analyses (
  id text primary key,
  repo text not null,
  sha text not null,
  status text not null check (status in ('running', 'done', 'error')),
  scene jsonb,
  error text,
  created_at timestamptz not null default now(),
  finished_at timestamptz
);

-- One finished analysis per repo and commit: the cache key.
create unique index analyses_done_repo_sha on public.analyses (repo, sha) where status = 'done';

create table public.spend_daily (
  day date primary key,
  usd numeric not null default 0 check (usd >= 0)
);

alter table public.analyses enable row level security;
alter table public.spend_daily enable row level security;

-- Adds to a day's spend in one statement, so concurrent runs never lose an update.
create function public.add_spend(day date, usd numeric)
returns numeric
language sql
security invoker
set search_path = ''
as $$
  insert into public.spend_daily as s (day, usd)
  values ($1, greatest($2, 0))
  on conflict on constraint spend_daily_pkey do update set usd = s.usd + excluded.usd
  returning s.usd;
$$;

revoke all on table public.analyses from public, anon, authenticated;
revoke all on table public.spend_daily from public, anon, authenticated;
revoke all on function public.add_spend(date, numeric) from public, anon, authenticated;

grant select, insert, update, delete on table public.analyses to service_role;
grant select, insert, update, delete on table public.spend_daily to service_role;
grant execute on function public.add_spend(date, numeric) to service_role;
