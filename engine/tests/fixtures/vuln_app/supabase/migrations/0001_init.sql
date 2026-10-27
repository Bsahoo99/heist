create table public.profiles (
  id uuid primary key references auth.users(id),
  display_name text
);

alter table public.profiles enable row level security;

create policy "profiles_own" on public.profiles for select using (auth.uid() = id);

create table public.pets (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  species text,
  photo_url text
);

alter table public.pets enable row level security;

-- HEIST-FIXTURE: m3 (pets, low)
create policy "pets_select_all" on public.pets for select using (true);

create table public.adoption_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  email text,
  phone text,
  message text,
  status text default 'pending'
);

alter table public.adoption_requests enable row level security;

-- HEIST-FIXTURE: m3 (adoption_requests, critical)
create policy "requests_select_authed" on public.adoption_requests for select using (auth.uid() is not null);

-- HEIST-FIXTURE: m3 (messages, critical, RLS never enabled)
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid references auth.users(id),
  body text
);
