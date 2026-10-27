create table public.profiles (
  id uuid primary key references auth.users(id),
  display_name text
);

alter table public.profiles enable row level security;

create policy "profiles_own" on public.profiles for select using (auth.uid() = id);

create table public.pets (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  name text not null,
  species text,
  photo_url text
);

alter table public.pets enable row level security;

create policy "pets_select_own" on public.pets for select using (auth.uid() = owner_id);

create table public.adoption_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  email text,
  phone text,
  message text,
  status text default 'pending'
);

alter table public.adoption_requests enable row level security;

create policy "requests_select_own" on public.adoption_requests for select using (auth.uid() = user_id);

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id),
  body text
);

alter table public.messages enable row level security;

create policy "messages_select_own" on public.messages for select using (auth.uid() = sender_id);
