-- What Supabase provides before a project's own migrations run, trimmed to what RLS needs.
-- Runs as a superuser in a fresh, throwaway database. Two settings come with it:
-- heist.migrator_password and heist.prober_password.
--
-- heist_migrator applies the repo's migrations and seeds the fake rows. It owns every schema
-- below and may bypass RLS to seed, but it is not a superuser, so dynamic SQL inside a
-- migration cannot reach the server (COPY PROGRAM, untrusted languages, files).
-- heist_prober only switches to anon or authenticated to read the rows back.

do $$
declare
  r text;
begin
  foreach r in array array[
    'anon', 'authenticated', 'service_role', 'authenticator', 'supabase_admin',
    'supabase_auth_admin', 'supabase_storage_admin', 'dashboard_user'
  ] loop
    if not exists (select 1 from pg_roles where rolname = r) then
      execute format('create role %I nologin noinherit', r);
    end if;
  end loop;
  if not exists (select 1 from pg_roles where rolname = 'heist_migrator') then
    create role heist_migrator;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'heist_prober') then
    create role heist_prober;
  end if;
  execute format(
    'alter role heist_migrator login nosuperuser nocreatedb nocreaterole noreplication bypassrls password %L',
    current_setting('heist.migrator_password')
  );
  execute format(
    'alter role heist_prober login nosuperuser nocreatedb nocreaterole noreplication nobypassrls noinherit password %L',
    current_setting('heist.prober_password')
  );
  execute format('alter database %I set search_path = "$user", public, extensions', current_database());
  execute format('grant create, connect on database %I to heist_migrator', current_database());
end
$$;

grant anon, authenticated to heist_prober;
grant authenticated to authenticator;
grant anon to authenticator;

alter schema public owner to heist_migrator;
grant usage on schema public to anon, authenticated, service_role;

create schema if not exists extensions authorization heist_migrator;
grant usage on schema extensions to anon, authenticated, service_role;

-- auth
create schema auth authorization heist_migrator;
grant usage on schema auth to anon, authenticated, service_role;

create table auth.users (
  instance_id uuid,
  id uuid primary key,
  aud varchar(255),
  role varchar(255),
  email varchar(255),
  encrypted_password varchar(255),
  email_confirmed_at timestamptz,
  phone text,
  raw_app_meta_data jsonb default '{}'::jsonb,
  raw_user_meta_data jsonb default '{}'::jsonb,
  is_anonymous boolean not null default false,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
alter table auth.users owner to heist_migrator;

create function auth.uid() returns uuid language sql stable as $f$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'
  )::uuid
$f$;

create function auth.role() returns text language sql stable as $f$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'
  )::text
$f$;

create function auth.email() returns text language sql stable as $f$
  select coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email'
  )::text
$f$;

create function auth.jwt() returns jsonb language sql stable as $f$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$f$;

alter function auth.uid() owner to heist_migrator;
alter function auth.role() owner to heist_migrator;
alter function auth.email() owner to heist_migrator;
alter function auth.jwt() owner to heist_migrator;
grant execute on all functions in schema auth to anon, authenticated, service_role;

-- storage
create schema storage authorization heist_migrator;
grant usage on schema storage to anon, authenticated, service_role;

create table storage.buckets (
  id text primary key,
  name text not null,
  owner uuid,
  public boolean default false,
  avif_autodetection boolean default false,
  file_size_limit bigint,
  allowed_mime_types text[],
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets (id),
  name text,
  owner uuid,
  owner_id text,
  metadata jsonb,
  path_tokens text[] generated always as (string_to_array(name, '/')) stored,
  version text,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  last_accessed_at timestamptz default now()
);

create function storage.foldername(name text) returns text[] language sql immutable as $f$
  select (string_to_array(name, '/'))[1:array_length(string_to_array(name, '/'), 1) - 1]
$f$;

create function storage.filename(name text) returns text language sql immutable as $f$
  select (string_to_array(name, '/'))[array_length(string_to_array(name, '/'), 1)]
$f$;

create function storage.extension(name text) returns text language sql immutable as $f$
  select reverse(split_part(reverse(storage.filename(name)), '.', 1))
$f$;

alter table storage.buckets owner to heist_migrator;
alter table storage.objects owner to heist_migrator;
alter table storage.objects enable row level security;
alter table storage.buckets enable row level security;
alter function storage.foldername(text) owner to heist_migrator;
alter function storage.filename(text) owner to heist_migrator;
alter function storage.extension(text) owner to heist_migrator;
grant all on all tables in schema storage to anon, authenticated, service_role;
grant execute on all functions in schema storage to anon, authenticated, service_role;

-- Supabase's default grants, which are exactly why RLS matters: every new table in public is
-- readable and writable by anon and authenticated until RLS says otherwise.
alter default privileges for role heist_migrator in schema public
  grant all on tables to anon, authenticated, service_role;
alter default privileges for role heist_migrator in schema public
  grant all on sequences to anon, authenticated, service_role;
alter default privileges for role heist_migrator in schema public
  grant execute on functions to anon, authenticated, service_role;
