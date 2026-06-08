-- One-time migration: expose recent signups for the daily digest job.
--
-- auth.users is managed by Supabase Auth and is not reachable via PostgREST
-- by default. This view in the public schema lets the daily_signups.py
-- script read signup data with a normal apikey/Authorization header.
--
-- security_invoker=true => the view runs with the *caller's* RLS, not the
-- view-owner's. With service_role (which bypasses RLS anyway) this is the
-- safe default and avoids accidental privilege escalation if we ever grant
-- this view to a less-privileged role.
--
-- Run this once in Supabase Studio -> SQL Editor against the dev project,
-- then again against staging/prod when promoting.

create or replace view public.recent_signups
with (security_invoker = true) as
select
    u.id,
    u.email,
    u.created_at,
    u.email_confirmed_at,
    u.last_sign_in_at,
    u.raw_user_meta_data->>'full_name'  as full_name,
    u.raw_user_meta_data->>'provider'   as signup_provider
from auth.users u;

grant select on public.recent_signups to service_role;

-- Optional v2 once we confirm public.profiles column names:
--
--   create or replace view public.recent_signups
--   with (security_invoker = true) as
--   select u.id, u.email, u.created_at, u.email_confirmed_at,
--          u.last_sign_in_at, p.full_name, p.org_id
--   from   auth.users u
--   left   join public.profiles p on p.id = u.id;
