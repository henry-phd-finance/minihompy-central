begin;
alter table private.identity_writing_proofs add column protocol integer not null default 1 check(protocol in (1,2)), add column attempt_id text;
alter table private.identity_writing_proofs add constraint writing_attempt_v2 check(protocol=1 or (attempt_id is not null and length(attempt_id) between 1 and 128));
create table private.identity_writing_delegations (
 delegation_hash text primary key check(delegation_hash ~ '^[A-Za-z0-9_-]{43}$'),
 proof_id uuid not null unique references private.identity_writing_proofs(id),
 session_id uuid not null references private.identity_sessions(id),
 target_site_id uuid not null references private.identity_sites(id),
 expires_at timestamptz not null, revoked_at timestamptz, last_renewed_at timestamptz
);
create index identity_delegations_session on private.identity_writing_delegations(session_id);
alter table private.identity_writing_delegations enable row level security;
revoke all on private.identity_writing_delegations from public,anon,authenticated;
grant all on private.identity_writing_delegations to service_role;
alter table private.identity_writing_grants drop constraint identity_writing_grants_proof_id_key;
alter table private.identity_writing_grants add column delegation_hash text references private.identity_writing_delegations(delegation_hash);
create index identity_grants_delegation on private.identity_writing_grants(delegation_hash);
create unique index identity_v1_grant_proof on private.identity_writing_grants(proof_id) where delegation_hash is null;
create or replace function private.identity_writing_action(p_action text, p_args jsonb)
returns jsonb language plpgsql security invoker set search_path = '' as $$
declare s private.identity_sessions; p private.identity_writing_proofs; g private.identity_writing_grants;
  m private.identity_members; home private.identity_sites; target private.identity_sites;
  sid uuid; expiry timestamptz; d private.identity_writing_delegations;
begin
  if p_action in ('renew','revoke_delegation') then
    select * into d from private.identity_writing_delegations where delegation_hash=p_args->>'delegation_hash';
    if not found then
      if p_action='revoke_delegation' then return jsonb_build_object('revoked',true); end if;
      return jsonb_build_object('failure','SESSION_REVOKED');
    end if;
    sid := d.session_id;
  elsif p_action in ('check','revoke') then
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
  if p_action='revoke_delegation' then
    update private.identity_writing_delegations set revoked_at=coalesce(revoked_at,clock_timestamp()) where delegation_hash=d.delegation_hash;
    update private.identity_writing_grants set revoked_at=coalesce(revoked_at,clock_timestamp()) where delegation_hash=d.delegation_hash;
    return jsonb_build_object('revoked',true);
  end if;
  if p_action='logout' then
    update private.identity_writing_delegations set revoked_at=coalesce(revoked_at,clock_timestamp()) where session_id=s.id;
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
  if p_action='renew' then
    select * into d from private.identity_writing_delegations where delegation_hash=d.delegation_hash;
    if d.target_site_id<>target.id then return jsonb_build_object('failure','TARGET_MISMATCH'); end if;
    if d.revoked_at is not null then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
    if d.expires_at<=clock_timestamp() then return jsonb_build_object('failure','SESSION_EXPIRED'); end if;
    if d.last_renewed_at > clock_timestamp()-interval '1 second' then return jsonb_build_object('failure','RATE_LIMITED'); end if;
    update private.identity_writing_delegations set last_renewed_at=clock_timestamp() where delegation_hash=d.delegation_hash;
    -- Bounded per-family cleanup; proofs are kept for anti-replay.
    delete from private.identity_writing_grants where delegation_hash=d.delegation_hash and expires_at<=clock_timestamp();
    insert into private.identity_writing_grants(grant_hash,proof_id,session_id,target_site_id,expires_at,delegation_hash)
      values(p_args->>'grant_hash',d.proof_id,s.id,target.id,least(clock_timestamp()+interval '15 minutes',s.expires_at,d.expires_at),d.delegation_hash) returning * into g;
  elsif p_action='issue' then
    insert into private.identity_writing_proofs(session_id,target_site_id,code_challenge,return_path,expires_at,protocol,attempt_id)
      values(s.id,target.id,p_args->>'code_challenge',p_args->>'return_path',least(clock_timestamp()+interval '60 seconds',s.expires_at),coalesce((p_args->>'protocol')::integer,1),p_args->>'attempt_id') returning * into p;
    return to_jsonb(p) || jsonb_build_object('member_id',m.id,'session_version',s.session_version);
  end if;
  if p_action='redeem' then
    select * into p from private.identity_writing_proofs where id=p.id for update;
    if p.session_id is distinct from (p_args->>'session_id')::uuid or p.target_site_id<>target.id then return jsonb_build_object('failure','TARGET_MISMATCH'); end if;
    if p.consumed_at is not null then return jsonb_build_object('failure','PROOF_USED'); end if;
    if p.expires_at<=clock_timestamp() then return jsonb_build_object('failure','SESSION_EXPIRED'); end if;
    if p.protocol<>coalesce((p_args->>'protocol')::integer,1) or (p.protocol=2 and p.attempt_id is distinct from p_args->>'attempt_id') then return jsonb_build_object('failure','FORBIDDEN'); end if;
    if p.code_challenge is distinct from p_args->>'code_challenge' then return jsonb_build_object('failure','FORBIDDEN'); end if;
    if p.protocol=2 then
      insert into private.identity_writing_delegations(delegation_hash,proof_id,session_id,target_site_id,expires_at)
        values(p_args->>'delegation_hash',p.id,s.id,target.id,s.expires_at) returning * into d;
    end if;
    expiry := least(clock_timestamp()+interval '15 minutes',s.expires_at);
    insert into private.identity_writing_grants(grant_hash,proof_id,session_id,target_site_id,expires_at,delegation_hash)
      values(p_args->>'grant_hash',p.id,s.id,target.id,expiry,d.delegation_hash) returning * into g;
    update private.identity_writing_proofs set consumed_at=clock_timestamp() where id=p.id;
  elsif p_action='check' then
    select * into g from private.identity_writing_grants where grant_hash=p_args->>'grant_hash';
    if g.target_site_id<>target.id then return jsonb_build_object('failure','TARGET_MISMATCH'); end if;
    if g.delegation_hash is not null and not exists(select 1 from private.identity_writing_delegations wd where wd.delegation_hash=g.delegation_hash and wd.revoked_at is null and wd.expires_at>clock_timestamp()) then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
    if g.revoked_at is not null then return jsonb_build_object('failure','SESSION_REVOKED'); end if;
    if g.expires_at<=clock_timestamp() then return jsonb_build_object('failure','SESSION_EXPIRED'); end if;
  end if;
  return jsonb_build_object('active',true,'proof_id',g.proof_id,'central_session_id',s.id,'site_id',target.id,'expires_at',g.expires_at,
    'member',jsonb_build_object('id',m.id,'display_name',left(m.display_name,20),'homepage_url',home.homepage_url),
    'home_origin',home.origin,'home_base_path',home.base_path) || case when d.delegation_hash is not null then jsonb_build_object('delegation_expires_at',d.expires_at) else '{}'::jsonb end;
end;
$$;

alter table private.identity_login_attempts add column writing_challenge text, add column visit_attempt_id text;
create function private.identity_create_login_attempt_writing(p_member uuid,p_site uuid,p_return_site uuid,p_return_path text,p_challenge text,p_writing_challenge text,p_visit_attempt text)
returns jsonb language plpgsql security invoker set search_path='' as $$
declare a jsonb;
begin
 if p_writing_challenge is null or p_writing_challenge !~ '^[A-Za-z0-9_-]{43}$' or p_visit_attempt is null or length(p_visit_attempt) not between 1 and 128 then return null; end if;
 a := private.identity_create_login_attempt(p_member,p_site,p_return_site,p_return_path,p_challenge);
 if a is null then return null; end if;
 update private.identity_login_attempts set writing_challenge=p_writing_challenge,visit_attempt_id=p_visit_attempt where id=(a->>'id')::uuid;
 return a;
end;
$$;
revoke all on function private.identity_create_login_attempt_writing(uuid,uuid,uuid,text,text,text,text) from public,anon,authenticated;
grant execute on function private.identity_create_login_attempt_writing(uuid,uuid,uuid,text,text,text,text) to service_role;
commit;
