begin;
create table private.identity_sessions (
  id uuid primary key,
  member_id uuid not null references private.identity_members(id),
  site_id uuid not null references private.identity_sites(id),
  session_version integer not null,
  owner_user_id uuid not null,
  issued_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create table private.identity_writing_proofs (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null references private.identity_sessions(id),
  target_site_id uuid not null references private.identity_sites(id),
  code_challenge text not null check (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  return_path text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz
);
create table private.identity_writing_grants (
  grant_hash text primary key check (grant_hash ~ '^[A-Za-z0-9_-]{43}$'),
  proof_id uuid not null unique references private.identity_writing_proofs(id),
  session_id uuid not null references private.identity_sessions(id),
  target_site_id uuid not null references private.identity_sites(id),
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create index identity_writing_proofs_session on private.identity_writing_proofs(session_id);
create index identity_writing_grants_session on private.identity_writing_grants(session_id);
alter table private.identity_sessions enable row level security;
alter table private.identity_writing_proofs enable row level security;
alter table private.identity_writing_grants enable row level security;
revoke all on private.identity_sessions, private.identity_writing_proofs, private.identity_writing_grants from public, anon, authenticated;
grant all on private.identity_sessions, private.identity_writing_proofs, private.identity_writing_grants to service_role;

-- Preserve the existing atomic completion checks and create the server session in
-- the same transaction. The completed login attempt ID is the unique login SID.
alter function private.identity_complete_login_attempt(uuid,uuid,uuid,text) rename to identity_complete_login_attempt_v2;
create function private.identity_complete_login_attempt(p_activation_id uuid, p_member uuid, p_site uuid, p_challenge text)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare a jsonb; s private.identity_sessions;
begin
  a := private.identity_complete_login_attempt_v2(p_activation_id,p_member,p_site,p_challenge);
  if a is null then return null; end if;
  insert into private.identity_sessions(id,member_id,site_id,session_version,owner_user_id,expires_at)
    values((a->>'id')::uuid,p_member,p_site,(a->>'session_version')::integer,(a->>'owner_user_id')::uuid,date_trunc('second',clock_timestamp()+interval '30 days')) returning * into s;
  return a || jsonb_build_object('central_session_id',s.id,'session_expires_at',s.expires_at);
end;
$$;
revoke all on function private.identity_complete_login_attempt(uuid,uuid,uuid,text) from public,anon,authenticated;
grant execute on function private.identity_complete_login_attempt(uuid,uuid,uuid,text) to service_role;

-- Service-only transaction boundary. Session-row locking serializes redemption,
-- grant inspection and revocation against logout. Secrets stored here are hashes.
create function private.identity_writing_action(p_action text, p_args jsonb)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare s private.identity_sessions; p private.identity_writing_proofs; g private.identity_writing_grants;
  m private.identity_members; home private.identity_sites; target private.identity_sites;
  sid uuid; expiry timestamptz;
begin
  if p_action in ('check','revoke') then
    select * into g from private.identity_writing_grants where grant_hash=p_args->>'grant_hash';
    if not found then
      if p_action='revoke' then return jsonb_build_object('revoked',true); end if;
      return jsonb_build_object('failure','SESSION_REVOKED');
    end if;
    sid := g.session_id;
  elsif p_action='redeem' then
    select * into p from private.identity_writing_proofs where id=(p_args->>'proof_id')::uuid;
    if not found then return jsonb_build_object('failure','AUTH_REQUIRED'); end if;
    sid := p.session_id;
  elsif p_action in ('issue','session','logout') then sid := (p_args->>'session_id')::uuid;
  else return jsonb_build_object('failure','BAD_REQUEST'); end if;
  select * into s from private.identity_sessions where id=sid for update;
  if not found then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
  if p_action in ('issue','session','logout','redeem') and
    (s.member_id is distinct from (p_args->>'member_id')::uuid or s.session_version is distinct from (p_args->>'session_version')::integer)
    then return jsonb_build_object('failure','AUTH_REQUIRED'); end if;
  if p_action='logout' then
    update private.identity_sessions set revoked_at=coalesce(revoked_at,clock_timestamp()) where id=s.id;
    update private.identity_writing_grants set revoked_at=coalesce(revoked_at,clock_timestamp()) where session_id=s.id;
    return jsonb_build_object('revoked',true);
  end if;
  if p_action='revoke' then
    update private.identity_writing_grants set revoked_at=coalesce(revoked_at,clock_timestamp()) where grant_hash=g.grant_hash;
    return jsonb_build_object('revoked',true);
  end if;
  if s.revoked_at is not null then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
  if s.expires_at <= clock_timestamp() then return jsonb_build_object('failure','SESSION_EXPIRED'); end if;
  select * into m from private.identity_members where id=s.member_id;
  select * into home from private.identity_sites where id=s.site_id and member_id=s.member_id;
  if m.id is null or m.status<>'active' or m.session_version<>s.session_version
    or home.id is null or home.status<>'active' or home.verification_status<>'verified'
    or not exists(select 1 from private.identity_bindings b where b.site_id=home.id and b.member_id=m.id and b.status='active' and b.local_user_id=s.owner_user_id)
    then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
  if p_action='session' then return jsonb_build_object('active',true); end if;
  select * into target from private.identity_sites where id=(p_args->>'site_id')::uuid;
  if target.id is null or target.status<>'active' or target.verification_status<>'verified'
    or not exists(select 1 from private.identity_members tm where tm.id=target.member_id and tm.status='active')
    or not exists(select 1 from private.identity_bindings tb where tb.site_id=target.id and tb.member_id=target.member_id and tb.status='active')
    then return jsonb_build_object('failure','TARGET_MISMATCH'); end if;
  if p_action='issue' then
    insert into private.identity_writing_proofs(session_id,target_site_id,code_challenge,return_path,expires_at)
      values(s.id,target.id,p_args->>'code_challenge',p_args->>'return_path',least(clock_timestamp()+interval '60 seconds',s.expires_at)) returning * into p;
    return to_jsonb(p) || jsonb_build_object('member_id',m.id,'session_version',s.session_version);
  end if;
  if p_action='redeem' then
    select * into p from private.identity_writing_proofs where id=p.id for update;
    if p.session_id is distinct from (p_args->>'session_id')::uuid or p.target_site_id<>target.id then return jsonb_build_object('failure','TARGET_MISMATCH'); end if;
    if p.consumed_at is not null then return jsonb_build_object('failure','PROOF_USED'); end if;
    if p.expires_at<=clock_timestamp() then return jsonb_build_object('failure','SESSION_EXPIRED'); end if;
    if p.code_challenge is distinct from p_args->>'code_challenge' then return jsonb_build_object('failure','FORBIDDEN'); end if;
    expiry := least(clock_timestamp()+interval '15 minutes',s.expires_at);
    insert into private.identity_writing_grants(grant_hash,proof_id,session_id,target_site_id,expires_at)
      values(p_args->>'grant_hash',p.id,s.id,target.id,expiry) returning * into g;
    update private.identity_writing_proofs set consumed_at=clock_timestamp() where id=p.id;
  elsif p_action='check' then
    select * into g from private.identity_writing_grants where grant_hash=p_args->>'grant_hash';
    if g.target_site_id<>target.id then return jsonb_build_object('failure','TARGET_MISMATCH'); end if;
    if g.revoked_at is not null then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
    if g.expires_at<=clock_timestamp() then return jsonb_build_object('failure','SESSION_EXPIRED'); end if;
  end if;
  return jsonb_build_object('active',true,'proof_id',g.proof_id,'central_session_id',s.id,'site_id',target.id,'expires_at',g.expires_at,
    'member',jsonb_build_object('id',m.id,'display_name',left(m.display_name,20),'homepage_url',home.homepage_url),
    'home_origin',home.origin,'home_base_path',home.base_path);
end;
$$;
revoke all on function private.identity_writing_action(text,jsonb) from public,anon,authenticated;
grant execute on function private.identity_writing_action(text,jsonb) to service_role;
commit;
