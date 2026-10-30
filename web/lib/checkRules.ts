// The read-only query the missing-rules card asks people to paste into Supabase.
// A copy of shared/check_rules.sql; checkRules.test.ts keeps the two byte for byte equal.
export const CHECK_RULES_SQL = `-- Heist: a read-only look at your database rules. It changes nothing.
-- One row per rule on each table in the public schema (RLS off means anyone with
-- your public key can read it), then one row per storage bucket.
-- RLS on with no rule means nobody can read the table through the API.
select
  'table' as kind,
  c.relname as name,
  case when c.relrowsecurity then 'RLS on' else 'RLS off' end as status,
  p.policyname as policy,
  p.cmd as command,
  array_to_string(p.roles, ', ') as roles,
  p.qual as using_rule,
  p.with_check as check_rule
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join pg_policies p on p.schemaname = n.nspname and p.tablename = c.relname
where n.nspname = 'public' and c.relkind in ('r', 'p')
union all
select
  'bucket',
  b.name,
  case when b.public then 'public' else 'private' end,
  null, null, null, null, null
from storage.buckets b
order by kind desc, name, policy;
`;
