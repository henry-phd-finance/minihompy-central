-- Request-local read authorization. No content or reusable read permit is stored.
begin;
create function private.identity_read_context(p_args jsonb) returns jsonb
language plpgsql security definer set search_path='' set lock_timeout='3s' set statement_timeout='3s' as $$
declare
 k text; site uuid; actor uuid; owner_id uuid; home_id uuid; g jsonb; fresh jsonb;
 rel private.identity_relationships; stamp timestamptz; expiry timestamptz; sid uuid;
begin
 if jsonb_typeof(p_args) is distinct from 'object' or octet_length(p_args::text)>8192
  or not(p_args ?& array['site_id','grant_hash','request_id','request_hash']) then raise exception 'BAD_REQUEST'; end if;
 for k in select jsonb_object_keys(p_args) loop
  if k<>all(array['site_id','grant_hash','request_id','request_hash']) or jsonb_typeof(p_args->k) is distinct from 'string' then raise exception 'BAD_REQUEST'; end if;
 end loop;
 if (p_args->>'site_id')!~*'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  or (p_args->>'request_id')!~*'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  or (p_args->>'request_hash')!~'^[0-9a-f]{64}$' or (p_args->>'grant_hash')!~'^[A-Za-z0-9_-]{43}$' then raise exception 'BAD_REQUEST'; end if;
 site:=(p_args->>'site_id')::uuid;
 -- Existing check locks the central session, also used by logout/grant revocation.
 g:=private.identity_writing_action('check',jsonb_build_object('site_id',site,'grant_hash',p_args->>'grant_hash'));
 if g?'failure' then return g; end if;
 actor:=(g->'member'->>'id')::uuid; sid:=(g->>'central_session_id')::uuid;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('relationship-actor:'||actor,0));
 select s.site_id into home_id from private.identity_sessions s where s.id=sid;
 -- Freeze both verified site bindings before choosing the target owner/pair.
 perform 1 from private.identity_sites s where s.id in (site,home_id) order by s.id for share;
 select s.member_id into owner_id from private.identity_sites s where s.id=site;
 perform 1 from private.identity_members m where m.id in (actor,owner_id) order by m.id for share;
 perform 1 from private.identity_bindings b where b.site_id in (site,home_id) order by b.site_id,b.member_id for share;
 if actor<>owner_id then
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('relationship-pair:'||least(actor,owner_id)||':'||greatest(actor,owner_id),0));
 end if;
 -- READ COMMITTED fresh statements after waits observe committed deactivation/revocation.
 fresh:=private.identity_writing_action('check',jsonb_build_object('site_id',site,'grant_hash',p_args->>'grant_hash'));
 if fresh?'failure' then raise exception '%',fresh->>'failure'; end if;
 if (fresh->'member'->>'id')::uuid<>actor or (fresh->>'central_session_id')::uuid<>sid then raise exception 'TARGET_MISMATCH'; end if;
 if owner_id is null then raise exception 'TARGET_MISMATCH'; end if;
 if actor<>owner_id then
  select * into rel from private.identity_relationships where member_low=least(actor,owner_id) and member_high=greatest(actor,owner_id);
 end if;
 perform private.relationship_rate('read-context:'||actor||':'||site,60,240);
 stamp:=clock_timestamp();
 select least(stamp+interval '5 seconds',(fresh->>'expires_at')::timestamptz,s.expires_at) into expiry from private.identity_sessions s where s.id=sid;
 if expiry<=stamp then raise exception 'SESSION_EXPIRED'; end if;
 return jsonb_build_object('protocol',1,'request_id',(p_args->>'request_id')::uuid,'request_hash',p_args->>'request_hash',
  'actor_member_id',actor,'site_id',site,'owner_member_id',owner_id,'central_session_id',sid,
  'relationship',case when actor=owner_id then 'self' else coalesce(rel.state,'none') end,
  'relationship_revision',coalesce(rel.revision,0),'can_read_friends',actor<>owner_id and coalesce(rel.state='accepted',false),
  'authorized_at',stamp,'expires_at',expiry);
exception
 when invalid_text_representation then return jsonb_build_object('failure','BAD_REQUEST');
 when raise_exception then
  if sqlerrm=any(array['BAD_REQUEST','AUTH_REQUIRED','SESSION_EXPIRED','SESSION_REVOKED','FORBIDDEN','TARGET_MISMATCH','RATE_LIMITED']) then
   return jsonb_build_object('failure',sqlerrm)||case when sqlerrm='RATE_LIMITED' then jsonb_build_object('retry_after',greatest(1,60-mod(floor(extract(epoch from clock_timestamp()))::bigint,60))) else '{}'::jsonb end;
  end if;
  raise;
end $$;
create function private.identity_read_context_ready() returns integer
language plpgsql security definer set search_path='' set lock_timeout='3s' set statement_timeout='3s' as $$
begin
 perform 1 from private.identity_relationships limit 1;
 perform 1 from private.identity_relationship_limits limit 1;
 if private.identity_read_context('{}')->>'failure' is distinct from 'BAD_REQUEST' then return 0; end if;
 return 1;
end $$;
revoke all on function private.identity_read_context(jsonb),private.identity_read_context_ready() from public,anon,authenticated;
grant execute on function private.identity_read_context(jsonb),private.identity_read_context_ready() to service_role;
commit;
