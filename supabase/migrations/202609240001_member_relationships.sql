-- Central relationship source of truth. No public table access or production HTTP routes yet.
begin;
create table private.identity_relationships (
 member_low uuid not null references private.identity_members(id),
 member_high uuid not null references private.identity_members(id),
 state text not null check(state in ('none','pending','accepted')),
 revision bigint not null check(revision between 1 and 9007199254740991),
 request_id uuid not null unique,
 sender_id uuid not null, receiver_id uuid not null,
 requested_at timestamptz not null, accepted_at timestamptz, updated_at timestamptz not null,
 primary key(member_low,member_high),
 check(member_low<member_high),
 check((sender_id=member_low and receiver_id=member_high) or (sender_id=member_high and receiver_id=member_low)),
 check(state<>'accepted' or accepted_at is not null)
);
create index identity_relationship_receiver on private.identity_relationships(receiver_id,sender_id) where state='pending';
create index identity_relationship_sender on private.identity_relationships(sender_id,receiver_id) where state='pending';
create index identity_relationship_high on private.identity_relationships(member_high,member_low) where state='accepted';
create table private.identity_relationship_operations (
 actor_id uuid not null references private.identity_members(id), site_id uuid not null references private.identity_sites(id),
 operation_id uuid not null, target_id uuid not null references private.identity_members(id),
 fingerprint jsonb not null, result jsonb not null, created_at timestamptz not null default clock_timestamp(),
 primary key(actor_id,site_id,operation_id)
);
create table private.identity_review_permits (
 permit_id uuid not null unique default gen_random_uuid(),
 actor_member_id uuid not null references private.identity_members(id), site_id uuid not null references private.identity_sites(id),
 owner_member_id uuid not null references private.identity_members(id), central_session_id uuid not null references private.identity_sessions(id),
 operation_id uuid not null, body_sha256 text not null check(body_sha256 ~ '^[0-9a-f]{64}$'),
 relationship_revision bigint not null, authorized_at timestamptz not null, expires_at timestamptz not null,
 primary key(actor_member_id,site_id,operation_id), check(expires_at>authorized_at),check(actor_member_id<>owner_member_id)
);
create table private.identity_relationship_limits (
 bucket text not null, window_start bigint not null, hits integer not null check(hits>0),
 primary key(bucket,window_start)
);
-- Persistent directional cooldown survives cancellation, rejection and a reversed request.
create table private.identity_relationship_cooldowns (
 sender_id uuid not null references private.identity_members(id), receiver_id uuid not null references private.identity_members(id),
 requested_at timestamptz not null, primary key(sender_id,receiver_id), check(sender_id<>receiver_id)
);
alter table private.identity_relationships enable row level security;
alter table private.identity_relationship_operations enable row level security;
alter table private.identity_review_permits enable row level security;
alter table private.identity_relationship_limits enable row level security;
alter table private.identity_relationship_cooldowns enable row level security;
revoke all on private.identity_relationships,private.identity_relationship_operations,private.identity_review_permits,
 private.identity_relationship_limits,private.identity_relationship_cooldowns from public,anon,authenticated,service_role;

create function private.relationship_profile(p_member uuid) returns jsonb language sql stable security invoker set search_path='' as $$
 select jsonb_build_object('member_id',m.id,'handle',m.handle,'display_name',m.display_name,'destination',
  (select jsonb_build_object('site_id',v->>'site_id','homepage_url',v->>'homepage_url')
   from jsonb_array_elements(private.identity_navigation('members',null,array[m.id])) v
   where exists(select 1 from private.identity_bindings b where b.member_id=m.id and b.site_id=(v->>'site_id')::uuid and b.status='active') limit 1))
 from private.identity_members m where m.id=p_member and m.status='active'
$$;
create function private.relationship_view(p_actor uuid,p_target uuid) returns jsonb language sql stable security invoker set search_path='' as $$
 select jsonb_build_object('state',case when p_actor=p_target then 'self' when r.state='pending' then
  case when r.sender_id=p_actor then 'outgoing' else 'incoming' end else coalesce(r.state,'none') end,
  'revision',coalesce(r.revision,0),'request_id',case when r.state in ('pending','accepted') then r.request_id else null end,
  'target',coalesce(private.relationship_profile(p_target),jsonb_build_object('member_id',p_target,'unavailable',true)))
 from (select 1) dummy left join private.identity_relationships r on r.member_low=least(p_actor,p_target) and r.member_high=greatest(p_actor,p_target)
$$;
create function private.relationship_rate(p_bucket text,p_seconds integer,p_max integer) returns void
 language plpgsql security invoker set search_path='' as $$
declare w bigint; n integer;
begin
 w:=floor(extract(epoch from clock_timestamp())/p_seconds)::bigint;
 insert into private.identity_relationship_limits(bucket,window_start,hits) values(p_bucket,w,1)
 on conflict(bucket,window_start) do update set hits=private.identity_relationship_limits.hits+1 returning hits into n;
 if n>p_max then raise exception 'RATE_LIMITED' using errcode='P0001'; end if;
 -- Only counters expire, never operation/permit tombstones or cooldowns. Bounded per bucket.
 delete from private.identity_relationship_limits where bucket=p_bucket and window_start<w-1;
end $$;

create function private.identity_relationship_action(p_action text,p_args jsonb) returns jsonb
 language plpgsql security definer set search_path='' as $$
declare
 allowed text[]; k text; site uuid; actor uuid; target uuid; op uuid; rid uuid; rev bigint;
 g jsonb; fresh jsonb; r private.identity_relationships; previous private.identity_relationship_operations;
 permit private.identity_review_permits; fp jsonb; result jsonb; stamp timestamptz; expires timestamptz;
 low_id uuid; high_id uuid; n integer:=20; after_id uuid; cursor_kind text; cur jsonb; row_item record;
 items jsonb:='[]'; last_id uuid; next_cursor jsonb:=null; count_items integer:=0; verb text; profile jsonb;
begin
 if p_action is null or p_action not in ('friends','state','requests','actions','operations','review-permits')
  or jsonb_typeof(p_args) is distinct from 'object' or octet_length(p_args::text)>8192 then
  return jsonb_build_object('failure','BAD_REQUEST'); end if;
 allowed:=case p_action
  when 'friends' then array['member_id','limit','cursor','ip_hash']
  when 'state' then array['site_id','grant_hash','target_member_id']
  when 'requests' then array['site_id','grant_hash','direction','limit','cursor']
  when 'actions' then array['site_id','grant_hash','action','target_member_id','operation_id','expected_revision','request_id']
  when 'operations' then array['site_id','grant_hash','operation_id']
  else array['site_id','grant_hash','operation_id','body_sha256'] end;
 for k in select jsonb_object_keys(p_args) loop
  if not(k=any(allowed)) or jsonb_typeof(p_args->k)='null' then raise exception 'BAD_REQUEST'; end if;
  if k in ('grant_hash','action','direction','body_sha256','ip_hash') and jsonb_typeof(p_args->k)<>'string' then raise exception 'BAD_REQUEST'; end if;
  if k in ('member_id','site_id','target_member_id','operation_id','request_id') and
   (jsonb_typeof(p_args->k)<>'string' or (p_args->>k)!~*'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') then raise exception 'BAD_REQUEST'; end if;
 end loop;
 if p_action='friends' then
  target:=(p_args->>'member_id')::uuid;
  if target is null or coalesce(p_args->>'ip_hash','')!~'^[0-9a-f]{64}$' then raise exception 'BAD_REQUEST'; end if;
  if not exists(select 1 from private.identity_members where id=target and status='active') then raise exception 'NOT_FOUND'; end if;
  perform private.relationship_rate('public:'||(p_args->>'ip_hash'),60,120);
 else
  site:=(p_args->>'site_id')::uuid;
  if site is null or coalesce(p_args->>'grant_hash','')!~'^[A-Za-z0-9_-]{43}$' then raise exception 'BAD_REQUEST'; end if;
  g:=private.identity_writing_action('check',jsonb_build_object('site_id',site,'grant_hash',p_args->>'grant_hash'));
  if g?'failure' then return g; end if;
  actor:=(g->'member'->>'id')::uuid;
  -- Across independent central sessions for one actor: quota and operation IDs serialize too.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('relationship-actor:'||actor::text,0));
  fresh:=private.identity_writing_action('check',jsonb_build_object('site_id',site,'grant_hash',p_args->>'grant_hash'));
  if fresh?'failure' then raise exception '%',fresh->>'failure'; end if;
  target:=(p_args->>'target_member_id')::uuid;
 end if;
 if p_action in ('friends','requests') then
  if p_args?'limit' then
   if jsonb_typeof(p_args->'limit')<>'number' or (p_args->>'limit')!~'^[0-9]+$' then raise exception 'BAD_REQUEST'; end if;
   n:=(p_args->>'limit')::integer;
  end if;
  if n not between 1 and 50 then raise exception 'BAD_REQUEST'; end if;
  cursor_kind:=case when p_action='friends' then 'friends' else p_args->>'direction' end;
  if cursor_kind is null or cursor_kind not in ('friends','incoming','outgoing') or (p_action='requests' and cursor_kind='friends') then raise exception 'BAD_REQUEST'; end if;
  if p_action='requests' then target:=actor; end if;
  if p_args?'cursor' then
   cur:=p_args->'cursor';
   if jsonb_typeof(cur)<>'object' or octet_length(cur::text)>512 or cur->'v' is distinct from '1'::jsonb
     or cur->>'kind' is distinct from cursor_kind or cur->>'member_id' is distinct from target::text
     or coalesce(cur->>'after','')!~*'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     or (cur-array['v','kind','member_id','after'])<>'{}'::jsonb then raise exception 'BAD_REQUEST'; end if;
   after_id:=(cur->>'after')::uuid;
  end if;
  if p_action='requests' then perform private.relationship_rate('read:'||actor||':'||site,60,120); end if;
  for row_item in
   select t.*,private.relationship_profile(t.peer) as profile from (
    select x.*,case when x.member_low=target then x.member_high else x.member_low end peer
    from private.identity_relationships x where
     (p_action='friends' and x.state='accepted' and target in (x.member_low,x.member_high)) or
     (p_action='requests' and x.state='pending' and ((cursor_kind='incoming' and x.receiver_id=actor) or (cursor_kind='outgoing' and x.sender_id=actor)))
   ) t where (after_id is null or t.peer>after_id)
    and (p_action<>'friends' or exists(select 1 from private.identity_members m where m.id=t.peer and m.status='active'))
   order by t.peer limit n+1
  loop
   count_items:=count_items+1;
   if count_items>n then next_cursor:=jsonb_build_object('v',1,'kind',cursor_kind,'member_id',target,'after',last_id); exit; end if;
   last_id:=row_item.peer;
   profile:=coalesce(row_item.profile,jsonb_build_object('member_id',row_item.peer,'unavailable',true));
   items:=items||jsonb_build_array(case when p_action='friends' then profile else
    jsonb_build_object('target',profile,'request_id',row_item.request_id,'revision',row_item.revision,'state',cursor_kind) end);
  end loop;
  return jsonb_build_object('items',items,'next_cursor',next_cursor);
 end if;
 if p_action in ('state','actions') and (target is null or not exists(select 1 from private.identity_members where id=target)) then raise exception 'NOT_FOUND'; end if;
 if p_action='state' then
  perform private.relationship_rate('read:'||actor||':'||site,60,120);
  return private.relationship_view(actor,target);
 end if;
 op:=(p_args->>'operation_id')::uuid;
 if op is null then raise exception 'BAD_REQUEST'; end if;
 if p_action='operations' then
  perform private.relationship_rate('read:'||actor||':'||site,60,120);
  select * into previous from private.identity_relationship_operations where actor_id=actor and site_id=site and operation_id=op;
  if not found then raise exception 'NOT_FOUND'; end if;
  return jsonb_build_object('operation_result',previous.result,'relationship',private.relationship_view(actor,previous.target_id));
 end if;
 if p_action='review-permits' then
  if coalesce(p_args->>'body_sha256','')!~'^[0-9a-f]{64}$' then raise exception 'BAD_REQUEST'; end if;
  select member_id into target from private.identity_sites where id=site;
 else
  verb:=p_args->>'action';
  if verb is null or verb not in ('request','accept','reject','cancel','disconnect')
   or jsonb_typeof(p_args->'expected_revision') is distinct from 'number'
   or (p_args->>'expected_revision')!~'^[0-9]+$' then raise exception 'BAD_REQUEST'; end if;
  rev:=(p_args->>'expected_revision')::bigint;
  if rev>9007199254740991 then raise exception 'BAD_REQUEST'; end if;
  rid:=(p_args->>'request_id')::uuid;
  if (verb='request' and p_args?'request_id') or (verb<>'request' and rid is null) then raise exception 'BAD_REQUEST'; end if;
 end if;
 if actor=target then raise exception 'FORBIDDEN'; end if;
 low_id:=least(actor,target);high_id:=greatest(actor,target);
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('relationship-pair:'||low_id||':'||high_id,0));
 -- The initial authentication may have waited for actor/pair locks. Expiry must be checked again.
 fresh:=private.identity_writing_action('check',jsonb_build_object('site_id',site,'grant_hash',p_args->>'grant_hash'));
 if fresh?'failure' then raise exception '%',fresh->>'failure'; end if;
 select * into r from private.identity_relationships where member_low=low_id and member_high=high_id for update;
 stamp:=clock_timestamp();
 if p_action='review-permits' then
  perform private.relationship_rate('read:'||actor||':'||site,60,120);
  select * into permit from private.identity_review_permits where actor_member_id=actor and site_id=site and operation_id=op;
  if found then
   if permit.body_sha256<>p_args->>'body_sha256' then raise exception 'REQUEST_CONFLICT'; end if;
   if permit.central_session_id<>(g->>'central_session_id')::uuid or permit.owner_member_id<>target then raise exception 'FORBIDDEN'; end if;
   if permit.expires_at<=stamp then raise exception 'PERMIT_EXPIRED'; end if;
   return to_jsonb(permit);
  end if;
  if r.state is distinct from 'accepted' then raise exception 'NOT_FRIENDS'; end if;
  perform private.relationship_rate('permit-minute:'||actor||':'||site,60,5);
  perform private.relationship_rate('permit-day:'||actor||':'||site,86400,100);
  select least(stamp+interval '30 seconds',(fresh->>'expires_at')::timestamptz,s.expires_at) into expires
    from private.identity_sessions s where s.id=(g->>'central_session_id')::uuid;
  if expires<=stamp then raise exception 'SESSION_EXPIRED'; end if;
  insert into private.identity_review_permits(actor_member_id,site_id,owner_member_id,central_session_id,operation_id,body_sha256,relationship_revision,authorized_at,expires_at)
   values(actor,site,target,(g->>'central_session_id')::uuid,op,p_args->>'body_sha256',r.revision,stamp,expires) returning * into permit;
  return to_jsonb(permit);
 end if;
 fp:=jsonb_build_object('action',verb,'target_member_id',target,'expected_revision',rev)
  ||case when rid is null then '{}'::jsonb else jsonb_build_object('request_id',rid) end;
 select * into previous from private.identity_relationship_operations where actor_id=actor and site_id=site and operation_id=op;
 if found then
  if previous.fingerprint<>fp then raise exception 'REQUEST_CONFLICT'; end if;
  perform private.relationship_rate('read:'||actor||':'||site,60,120);
  return jsonb_build_object('operation_result',previous.result,'relationship',private.relationship_view(actor,target));
 end if;
 if coalesce(r.revision,0)<>rev or (verb<>'request' and r.request_id is distinct from rid) then raise exception 'REVISION_CONFLICT'; end if;
 if verb='request' then
  if coalesce(r.state,'none')<>'none' then raise exception 'REVISION_CONFLICT'; end if;
 elsif verb in ('accept','reject','cancel') then
  if r.state is distinct from 'pending' then raise exception 'REVISION_CONFLICT'; end if;
  if (verb in ('accept','reject') and actor<>r.receiver_id) or (verb='cancel' and actor<>r.sender_id) then raise exception 'FORBIDDEN'; end if;
 elsif r.state is distinct from 'accepted' then raise exception 'REVISION_CONFLICT'; end if;
 if verb in ('request','accept') and (coalesce(private.relationship_profile(target)->'destination','null'::jsonb)='null'::jsonb or coalesce(private.relationship_profile(actor)->'destination','null'::jsonb)='null'::jsonb) then raise exception 'FORBIDDEN'; end if;
 perform private.relationship_rate('change:'||actor,60,20);
 if verb='request' then
  if exists(select 1 from private.identity_relationship_cooldowns where sender_id=actor and receiver_id=target and requested_at>stamp-interval '60 seconds') then raise exception 'RATE_LIMITED'; end if;
  perform private.relationship_rate('request-day:'||actor,86400,100);
  insert into private.identity_relationship_cooldowns values(actor,target,stamp) on conflict(sender_id,receiver_id) do update set requested_at=excluded.requested_at;
  insert into private.identity_relationships(member_low,member_high,state,revision,request_id,sender_id,receiver_id,requested_at,updated_at)
   values(low_id,high_id,'pending',rev+1,gen_random_uuid(),actor,target,stamp,stamp)
   on conflict(member_low,member_high) do update set state='pending',revision=excluded.revision,request_id=excluded.request_id,
    sender_id=actor,receiver_id=target,requested_at=stamp,accepted_at=null,updated_at=stamp;
 else
  update private.identity_relationships set state=case when verb='accept' then 'accepted' else 'none' end,revision=revision+1,
   accepted_at=case when verb='accept' then stamp else null end,updated_at=stamp where member_low=low_id and member_high=high_id;
 end if;
 result:=jsonb_build_object('action',verb,'operation_id',op,'relationship',private.relationship_view(actor,target));
 insert into private.identity_relationship_operations values(actor,site,op,target,fp,result,stamp);
 return jsonb_build_object('operation_result',result,'relationship',private.relationship_view(actor,target));
exception
 when invalid_text_representation or numeric_value_out_of_range then return jsonb_build_object('failure','BAD_REQUEST');
 when raise_exception then
  if sqlerrm=any(array['BAD_REQUEST','AUTH_REQUIRED','SESSION_EXPIRED','SESSION_REVOKED','FORBIDDEN','TARGET_MISMATCH','NOT_FOUND','NOT_FRIENDS','REVISION_CONFLICT','REQUEST_CONFLICT','PERMIT_EXPIRED','RATE_LIMITED']) then
   return jsonb_build_object('failure',sqlerrm)||case when sqlerrm='RATE_LIMITED' then jsonb_build_object('retry_after',60) else '{}'::jsonb end;
  end if;
  raise;
end $$;
revoke all on function private.relationship_profile(uuid),private.relationship_view(uuid,uuid),private.relationship_rate(text,integer,integer),private.identity_relationship_action(text,jsonb) from public,anon,authenticated,service_role;
grant execute on function private.identity_relationship_action(text,jsonb) to service_role;
commit;
