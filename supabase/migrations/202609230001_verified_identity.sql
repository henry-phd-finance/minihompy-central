-- Central identity v2: verified ownership and atomic, browser-bound exchanges.
begin;
alter table private.identity_sites
  add column verification_status text not null default 'needs_reverification'
    check (verification_status in ('needs_reverification', 'verified')),
  add column supabase_publishable_key text,
  add column verified_at timestamptz;
-- Old UUID-only sessions are not trusted after upgrading.
update private.identity_members set session_version = session_version + 1;

create table private.identity_registrations (
  id uuid primary key default gen_random_uuid(),
  existing_site_id uuid references private.identity_sites(id),
  proposal jsonb not null,
  owner_user_id uuid not null,
  challenge_hash text not null check (challenge_hash ~ '^[A-Za-z0-9_-]{43}$'),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
create table private.identity_login_attempts (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references private.identity_members(id),
  site_id uuid not null references private.identity_sites(id),
  owner_user_id uuid not null,
  session_version integer not null,
  return_site_id uuid not null references private.identity_sites(id),
  return_path text not null,
  code_challenge text not null check (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  intent_expires_at timestamptz not null default now() + interval '5 minutes',
  activation_id uuid unique,
  activation_expires_at timestamptz,
  activated_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now()
);
alter table private.identity_registrations enable row level security;
alter table private.identity_login_attempts enable row level security;
revoke all on private.identity_registrations, private.identity_login_attempts from public, anon, authenticated;
grant all on private.identity_registrations, private.identity_login_attempts to service_role;

-- Called only after the API has checked both the Auth proof and Pages challenge.
-- A row lock consumes one registration; every member/site/binding write rolls back together.
create function private.identity_verify_registration(p_registration_id uuid, p_owner uuid)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  r private.identity_registrations;
  s private.identity_sites;
  b private.identity_bindings;
  m private.identity_members;
  p jsonb;
begin
  select * into r from private.identity_registrations where id = p_registration_id for update;
  if not found or r.consumed_at is not null or r.expires_at <= clock_timestamp() or r.owner_user_id <> p_owner then return null; end if;
  p := r.proposal;
  if r.existing_site_id is null then
    insert into private.identity_members(handle, display_name) values (p->>'handle', p->>'display_name') returning * into m;
    insert into private.identity_sites(member_id, origin, base_path, homepage_url, login_url, supabase_project_ref,
      supabase_publishable_key, verification_status, verified_at)
    values (m.id, p->>'origin', p->>'base_path', p->>'homepage_url', p->>'login_url', p->>'supabase_project_ref',
      p->>'supabase_publishable_key', 'verified', now()) returning * into s;
    insert into private.identity_bindings(site_id, member_id, local_user_id) values (s.id, m.id, p_owner);
  else
    select * into s from private.identity_sites where id = r.existing_site_id for update;
    if not found or s.status <> 'active' then return null; end if;
    select * into m from private.identity_members where id = s.member_id for update;
    if not found or m.status <> 'active' then return null; end if;
    if s.origin <> p->>'origin' or s.base_path <> p->>'base_path' or s.homepage_url <> p->>'homepage_url'
      or s.login_url <> p->>'login_url' or s.supabase_project_ref <> p->>'supabase_project_ref' or m.handle <> p->>'handle' then return null; end if;
    select * into b from private.identity_bindings where site_id = s.id for update;
    if found then
      if b.local_user_id <> p_owner or b.member_id <> m.id or b.status <> 'active' then return null; end if;
    else
      insert into private.identity_bindings(site_id, member_id, local_user_id) values (s.id, m.id, p_owner);
    end if;
    update private.identity_sites set supabase_publishable_key = p->>'supabase_publishable_key',
      verification_status = 'verified', verified_at = now(), updated_at = now() where id = s.id;
    update private.identity_members set session_version = session_version + 1, updated_at = now() where id = m.id;
  end if;
  update private.identity_registrations set consumed_at = now() where id = r.id;
  return jsonb_build_object('status', 'verified', 'member_id', m.id, 'site_id', s.id, 'handle', m.handle);
end;
$$;

create function private.identity_create_login_attempt(p_member uuid, p_site uuid, p_return_site uuid, p_return_path text, p_challenge text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare a private.identity_login_attempts;
begin
  insert into private.identity_login_attempts(member_id, site_id, owner_user_id, session_version, return_site_id, return_path, code_challenge)
  select m.id, s.id, b.local_user_id, m.session_version, rs.id, p_return_path, p_challenge
  from private.identity_members m
  join private.identity_sites s on s.member_id = m.id
  join private.identity_bindings b on b.member_id = m.id and b.site_id = s.id
  join private.identity_sites rs on rs.id = p_return_site
  where m.id = p_member and s.id = p_site and m.status = 'active' and s.status = 'active'
    and s.verification_status = 'verified' and b.status = 'active'
    and rs.status = 'active' and rs.verification_status = 'verified'
  returning * into a;
  if not found then return null; end if;
  return to_jsonb(a);
end;
$$;

create function private.identity_activate_login_attempt(p_id uuid, p_member uuid, p_site uuid, p_owner uuid)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare a private.identity_login_attempts;
begin
  update private.identity_login_attempts a0
  set activated_at = clock_timestamp(), activation_id = gen_random_uuid(), activation_expires_at = clock_timestamp() + interval '2 minutes'
  from private.identity_members m, private.identity_sites s, private.identity_bindings b, private.identity_sites rs
  where a0.id = p_id and a0.member_id = p_member and a0.site_id = p_site and a0.owner_user_id = p_owner
    and a0.activated_at is null and a0.intent_expires_at > clock_timestamp()
    and m.id = a0.member_id and m.status = 'active' and m.session_version = a0.session_version
    and s.id = a0.site_id and s.member_id = m.id and s.status = 'active' and s.verification_status = 'verified'
    and b.site_id = s.id and b.member_id = m.id and b.local_user_id = p_owner and b.status = 'active'
    and rs.id = a0.return_site_id and rs.status = 'active' and rs.verification_status = 'verified'
  returning a0.* into a;
  if not found then return null; end if;
  return to_jsonb(a);
end;
$$;

create function private.identity_complete_login_attempt(p_activation_id uuid, p_member uuid, p_site uuid, p_challenge text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare a private.identity_login_attempts; result jsonb;
begin
  update private.identity_login_attempts a0 set completed_at = clock_timestamp()
  from private.identity_members m, private.identity_sites s, private.identity_bindings b, private.identity_sites rs
  where a0.activation_id = p_activation_id and a0.member_id = p_member and a0.site_id = p_site
    and a0.code_challenge = p_challenge and a0.completed_at is null and a0.activation_expires_at > clock_timestamp()
    and m.id = a0.member_id and m.status = 'active' and m.session_version = a0.session_version
    and s.id = a0.site_id and s.member_id = m.id and s.status = 'active' and s.verification_status = 'verified'
    and b.site_id = s.id and b.member_id = m.id and b.local_user_id = a0.owner_user_id and b.status = 'active'
    and rs.id = a0.return_site_id and rs.status = 'active' and rs.verification_status = 'verified'
  returning a0.* into a;
  if not found then return null; end if;
  select to_jsonb(a) || jsonb_build_object('handle', m.handle, 'display_name', m.display_name, 'return_origin', rs.origin)
    into result from private.identity_members m, private.identity_sites rs where m.id = a.member_id and rs.id = a.return_site_id;
  return result;
end;
$$;

revoke all on function private.identity_verify_registration(uuid, uuid) from public, anon, authenticated;
revoke all on function private.identity_create_login_attempt(uuid, uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function private.identity_activate_login_attempt(uuid, uuid, uuid, uuid) from public, anon, authenticated;
revoke all on function private.identity_complete_login_attempt(uuid, uuid, uuid, text) from public, anon, authenticated;
grant execute on function private.identity_verify_registration(uuid, uuid) to service_role;
grant execute on function private.identity_create_login_attempt(uuid, uuid, uuid, text, text) to service_role;
grant execute on function private.identity_activate_login_attempt(uuid, uuid, uuid, uuid) to service_role;
grant execute on function private.identity_complete_login_attempt(uuid, uuid, uuid, text) to service_role;
commit;
