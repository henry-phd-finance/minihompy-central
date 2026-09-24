import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createIdentityDb} from './helpers/identity-db.mjs';
import {id,member,site,session,seedRelationships,grantFor,rpc,command} from './helpers/relationship-fixture.mjs';
const {pg}=await createIdentityDb();let groups=0;
const check=async(name,fn)=>{await fn();console.log(`PASS ${++groups}: ${name}`);};
const admin=async(sql,args)=>{await pg.exec('reset role');try{return await pg.query(sql,args);}finally{await pg.exec('set role service_role');}};
const ok=r=>{assert.ok(!r.failure,JSON.stringify(r));return r;};
const bad=(r,f)=>assert.equal(r.failure,f,JSON.stringify(r));
let grants={},baseRequest,requestId;
const call=(n,action,args={})=>rpc(pg,action,{...grants[n],...args});
const action=(n,target,verb,rev,rid,extra)=>call(n,'actions',command(target,verb,rev,rid,extra));
const publicList=(n,args={})=>rpc(pg,'friends',{member_id:member(n),ip_hash:'f'.repeat(64),...args});
async function resetRates(){await admin('delete from private.identity_relationship_limits');await admin('delete from private.identity_relationship_cooldowns');}
try{
 await pg.exec('reset role');await seedRelationships(pg,8);for(let n=1;n<=8;n++)grants[n]=await grantFor(pg,n);await pg.exec('set role service_role');
 await check('service RPC only: no anon/authenticated RPC or table access; no direct service DML',async()=>{
  for(const role of ['anon','authenticated','service_role']){
   await pg.exec('set role '+role);
   for(const table of ['identity_relationships','identity_relationship_operations','identity_review_permits','identity_relationship_limits','identity_relationship_cooldowns']){
    await assert.rejects(pg.query('select * from private.'+table),e=>e.code==='42501');
    await assert.rejects(pg.query('delete from private.'+table),e=>e.code==='42501');
   }
   await assert.rejects(pg.query('select private.relationship_rate($1,60,120)',['bypass']),e=>e.code==='42501');
   if(role!=='service_role')await assert.rejects(rpc(pg,'state',{...grants[1],target_member_id:member(2)}),e=>e.code==='42501');
  }
  assert.equal(ok(await call(1,'state',{target_member_id:member(1)})).state,'self');
 });
 await check('unknown fields, types, revisions, invalid grants and wrong site are rejected',async()=>{
  for(const extra of [{actor:member(2)},{member_id:member(2)},{expected_revision:-1},{expected_revision:'0'},{expected_revision:9007199254740992},{request_id:id(90)},{action:null},{operation_id:'not-uuid'}])bad(await action(1,2,'request',0,null,extra),'BAD_REQUEST');
  bad(await rpc(pg,'state',{...grants[1],site_id:site(1),target_member_id:member(2)}),'TARGET_MISMATCH');
  bad(await rpc(pg,'state',{...grants[1],grant_hash:'x'.repeat(43),target_member_id:member(2)}),'SESSION_REVOKED');
  bad(await action(1,1,'request',0),'FORBIDDEN');bad(await action(1,999,'request',0),'NOT_FOUND');
 });
 await check('request is one central pair, symmetric pending views and private inboxes',async()=>{
  baseRequest=command(2,'request',0);const result=ok(await call(1,'actions',baseRequest));requestId=result.relationship.request_id;
  assert.equal(result.relationship.state,'outgoing');assert.equal(ok(await call(2,'state',{target_member_id:member(1)})).state,'incoming');
  assert.equal(ok(await call(2,'requests',{direction:'incoming'})).items.length,1);
  assert.equal(ok(await call(3,'requests',{direction:'incoming'})).items.length,0);
  bad(await call(3,'requests',{direction:'incoming',member_id:member(2)}),'BAD_REQUEST');
  assert.deepEqual(ok(await publicList(1)).items,[]);
 });
 await check('duplicate/opposite requests do not accept, third party and sender cannot accept',async()=>{
  bad(await action(1,2,'request',1),'REVISION_CONFLICT');bad(await action(2,1,'request',1),'REVISION_CONFLICT');
  bad(await action(1,2,'accept',1,requestId),'FORBIDDEN');bad(await action(3,1,'accept',1,requestId),'REVISION_CONFLICT');
  bad(await action(2,1,'cancel',1,requestId),'FORBIDDEN');
 });
 await check('accept updates both perspectives; retry returns old operation plus current state',async()=>{
  ok(await action(2,1,'accept',1,requestId));assert.equal(ok(await call(1,'state',{target_member_id:member(2)})).state,'accepted');
  const retry=ok(await call(1,'actions',baseRequest));assert.equal(retry.operation_result.relationship.state,'outgoing');assert.equal(retry.relationship.state,'accepted');
  bad(await call(1,'actions',{...baseRequest,target_member_id:member(3)}),'REQUEST_CONFLICT');
  bad(await call(3,'operations',{operation_id:baseRequest.operation_id}),'NOT_FOUND');
  assert.equal(ok(await call(1,'operations',{operation_id:baseRequest.operation_id})).relationship.state,'accepted');
 });
 await check('public profiles contain neither pending/request metadata nor auth data',async()=>{
  const list=ok(await publicList(1));assert.equal(list.items.length,1);assert.equal(list.items[0].member_id,member(2));
  assert.deepEqual(Object.keys(list.items[0]).sort(),['destination','display_name','handle','member_id']);
  assert.ok(!JSON.stringify(list).includes(requestId));
 });
 let permitArgs,permit;
 await check('permit owner derives from site and binds body/actor/session/operation with <=30s expiry',async()=>{
  permitArgs={operation_id:randomUUID(),body_sha256:'a'.repeat(64)};permit=ok(await call(1,'review-permits',permitArgs));
  assert.equal(permit.owner_member_id,member(2));assert.equal(permit.actor_member_id,member(1));assert.equal(permit.central_session_id,session(1));
  assert.ok(Date.parse(permit.expires_at)-Date.parse(permit.authorized_at)<=30000);
  bad(await call(1,'review-permits',{...permitArgs,owner_member_id:member(3)}),'BAD_REQUEST');
  bad(await call(2,'review-permits',{operation_id:randomUUID(),body_sha256:'a'.repeat(64)}),'FORBIDDEN');
  bad(await call(3,'review-permits',{operation_id:randomUUID(),body_sha256:'a'.repeat(64)}),'NOT_FRIENDS');
 });
 await check('disconnect denies new permits but exact old permit survives with fixed deadline',async()=>{
  ok(await action(2,1,'disconnect',2,requestId));
  assert.deepEqual(ok(await call(1,'review-permits',permitArgs)),permit);
  bad(await call(1,'review-permits',{...permitArgs,body_sha256:'b'.repeat(64)}),'REQUEST_CONFLICT');
  bad(await call(1,'review-permits',{operation_id:randomUUID(),body_sha256:'a'.repeat(64)}),'NOT_FRIENDS');
  await admin("update private.identity_review_permits set authorized_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute'");
  bad(await call(1,'review-permits',permitArgs),'PERMIT_EXPIRED');
 });
 await check('directional cooldown survives disconnect; fresh request ID prevents stale accept/cancel',async()=>{
  bad(await action(1,2,'request',3),'RATE_LIMITED');await resetRates();
  const next=ok(await action(1,2,'request',3)).relationship;assert.notEqual(next.request_id,requestId);
  bad(await action(2,1,'accept',4,requestId),'REVISION_CONFLICT');bad(await action(1,2,'cancel',4,requestId),'REVISION_CONFLICT');
  ok(await action(2,1,'reject',4,next.request_id));
  const reverse=ok(await action(2,1,'request',5)).relationship;ok(await action(2,1,'cancel',6,reverse.request_id));
 });
 await check('failed mutations roll back counters/pairs/receipts together',async()=>{
  const before=(await admin('select (select count(*) from private.identity_relationship_operations)::int ops,(select sum(hits) from private.identity_relationship_limits)::int hits')).rows[0];
  bad(await action(1,3,'accept',0,id(900)),'REVISION_CONFLICT');
  assert.deepEqual((await admin('select (select count(*) from private.identity_relationship_operations)::int ops,(select sum(hits) from private.identity_relationship_limits)::int hits')).rows[0],before);
 });
 await check('inactive peers are masked in pending lists; rejection and cancellation remain available',async()=>{
  await resetRates();const r=ok(await action(3,4,'request',0)).relationship;
  await admin("update private.identity_members set status='suspended' where id=$1",[member(3)]);
  const inbox=ok(await call(4,'requests',{direction:'incoming'}));assert.deepEqual(inbox.items[0].target,{member_id:member(3),unavailable:true});
  bad(await action(4,3,'accept',1,r.request_id),'FORBIDDEN');ok(await action(4,3,'reject',1,r.request_id));
  await admin("update private.identity_members set status='active' where id=$1",[member(3)]);
 });
 await check('inactive or unverified homes cannot receive new requests; unsafe destinations stay null',async()=>{
  await admin("update private.identity_sites set verification_status='needs_reverification' where id=$1",[site(5)]);
  bad(await action(1,5,'request',0),'FORBIDDEN');
  await admin("update private.identity_sites set verification_status='verified',homepage_url='https://evil.test/' where id=$1",[site(5)]);
  bad(await action(1,5,'request',0),'FORBIDDEN');
  await admin("update private.identity_sites set homepage_url='https://m5.test/home/' where id=$1",[site(5)]);
  await admin("update private.identity_bindings set status='revoked' where site_id=$1",[site(5)]);
  bad(await action(1,5,'request',0),'FORBIDDEN');
  await admin("update private.identity_bindings set status='active' where site_id=$1",[site(5)]);
  await admin("update private.identity_sites set homepage_url='https://evil.test/' where id=$1",[site(1)]);
  bad(await action(1,5,'request',0),'FORBIDDEN');
  await admin("update private.identity_sites set homepage_url='https://m1.test/home/' where id=$1",[site(1)]);
 });
 await check('public keyset pages are stable, hide inactive peers and bind cursor scope',async()=>{
  await resetRates();
  for(const n of [3,4,5,6]){const r=ok(await action(1,n,'request',0)).relationship;ok(await action(n,1,'accept',r.revision,r.request_id));}
  const first=ok(await publicList(1,{limit:2}));assert.deepEqual(first.items.map(x=>x.member_id),[member(3),member(4)]);
  const second=ok(await publicList(1,{limit:2,cursor:first.next_cursor}));assert.deepEqual(second.items.map(x=>x.member_id),[member(5),member(6)]);assert.equal(second.next_cursor,null);
  bad(await publicList(2,{cursor:first.next_cursor}),'BAD_REQUEST');bad(await publicList(1,{limit:51}),'BAD_REQUEST');
  bad(await publicList(1,{cursor:{...first.next_cursor,extra:true}}),'BAD_REQUEST');
  await admin("update private.identity_members set status='deleted' where id=$1",[member(3)]);
  await admin("update private.identity_sites set verification_status='needs_reverification' where id=$1",[site(4)]);
  const visible=ok(await publicList(1));assert.ok(!visible.items.some(x=>x.member_id===member(3)));assert.equal(visible.items.find(x=>x.member_id===member(4)).destination,null);
  await admin("update private.identity_members set status='active' where id=$1",[member(3)]);
  await admin("update private.identity_sites set verification_status='verified' where id=$1",[site(4)]);
 });
 await check('pending cursor cannot cross member/direction and public requests reveal no pending data',async()=>{
  for(const n of [7,8])ok(await action(n,1,'request',0));
  const first=ok(await call(1,'requests',{direction:'incoming',limit:1}));assert.equal(first.items.length,1);assert.ok(first.next_cursor);
  const second=ok(await call(1,'requests',{direction:'incoming',limit:1,cursor:first.next_cursor}));assert.equal(second.items.length,1);assert.notEqual(second.items[0].target.member_id,first.items[0].target.member_id);
  bad(await call(1,'requests',{direction:'outgoing',cursor:first.next_cursor}),'BAD_REQUEST');
  bad(await call(2,'requests',{direction:'incoming',cursor:first.next_cursor}),'BAD_REQUEST');
 });
 await check('rate limits are server-side, retries do not consume mutation quota',async()=>{
  await resetRates();
  const r=ok(await action(1,2,'request',7));
  for(let i=0;i<5;i++)ok(await call(1,'actions',{...baseRequest,operation_id:r.operation_result.operation_id,expected_revision:7}));
  assert.equal((await admin("select hits from private.identity_relationship_limits where bucket=$1",['change:'+member(1)])).rows[0].hits,1);
  const window=Math.floor(Date.now()/60000);
  await admin('insert into private.identity_relationship_limits values($1,$2,20) on conflict(bucket,window_start) do update set hits=20',['change:'+member(2),window]);
  bad(await action(2,1,'accept',8,r.relationship.request_id),'RATE_LIMITED');
  await resetRates();ok(await action(2,1,'accept',8,r.relationship.request_id));
  for(let i=0;i<5;i++)ok(await call(1,'review-permits',{operation_id:randomUUID(),body_sha256:'c'.repeat(64)}));
  bad(await call(1,'review-permits',{operation_id:randomUUID(),body_sha256:'c'.repeat(64)}),'RATE_LIMITED');
  await resetRates();
  await admin('insert into private.identity_relationship_limits values($1,$2,120)',['public:'+'f'.repeat(64),window]);
  bad(await publicList(1),'RATE_LIMITED');
 });
 await check('daily quotas, authenticated read quotas and unknown cursor/body types are enforced',async()=>{
  await resetRates();
  const day=Math.floor(Date.now()/86400000),minute=Math.floor(Date.now()/60000);
  await admin('insert into private.identity_relationship_limits values($1,$2,100)',['request-day:'+member(7),day]);
  bad(await action(7,8,'request',0),'RATE_LIMITED');
  await admin('insert into private.identity_relationship_limits values($1,$2,100)',['permit-day:'+member(1)+':'+site(2),day]);
  bad(await call(1,'review-permits',{operation_id:randomUUID(),body_sha256:'d'.repeat(64)}),'RATE_LIMITED');
  await admin('insert into private.identity_relationship_limits values($1,$2,120)',['read:'+member(1)+':'+site(2),minute]);
  bad(await call(1,'requests',{direction:'incoming'}),'RATE_LIMITED');
  for(const args of [{limit:null},{limit:'1'},{limit:1.5},{cursor:[]},{cursor:'bad'}])bad(await publicList(1,args),'BAD_REQUEST');
  bad(await call(1,'review-permits',{operation_id:randomUUID(),body_sha256:'x'.repeat(64)}),'BAD_REQUEST');
 });
 await check('pending cancellation with inactive peer and disconnect with suspended peer stay available',async()=>{
  await resetRates();const r=ok(await action(7,8,'request',0)).relationship;
  await admin("update private.identity_members set status='suspended' where id=$1",[member(8)]);
  ok(await action(7,8,'cancel',1,r.request_id));
  await admin("update private.identity_members set status='suspended' where id=$1",[member(3)]);
  const state=ok(await call(1,'state',{target_member_id:member(3)}));
  ok(await action(1,3,'disconnect',state.revision,state.request_id));
  bad(await publicList(3),'NOT_FOUND');
  await admin("update private.identity_members set status='active' where id in ($1,$2)",[member(8),member(3)]);
  bad(await action(7,8,'request',2),'RATE_LIMITED');
 });
 await check('renewed grant on same central session can retrieve permit, new session cannot rebind it',async()=>{
  await resetRates();const args={operation_id:randomUUID(),body_sha256:'e'.repeat(64)};
  const first=ok(await call(1,'review-permits',args));
  await pg.exec('reset role');const fresh=await grantFor(pg,1);await pg.exec('set role service_role');
  assert.deepEqual(ok(await rpc(pg,'review-permits',{...fresh,...args})),first);
  await admin("insert into private.identity_sessions(id,member_id,site_id,session_version,owner_user_id,expires_at) values($1,$2,$3,1,$4,clock_timestamp()+interval '1 day')",[id(999),member(1),site(1),id(301)]);
  await pg.exec('reset role');const other=await grantFor(pg,1,2,id(999));await pg.exec('set role service_role');
  bad(await rpc(pg,'review-permits',{...other,...args}),'FORBIDDEN');
  await admin("update private.identity_writing_grants set expires_at=clock_timestamp()+interval '10 seconds' where grant_hash=$1",[fresh.grant_hash]);
  const limited=ok(await rpc(pg,'review-permits',{...fresh,operation_id:randomUUID(),body_sha256:'e'.repeat(64)}));
  assert.ok(Date.parse(limited.expires_at)-Date.parse(limited.authorized_at)<=10000);
 });
 await check('grant revocation, delegation revocation, expiry and central logout block old operations',async()=>{
  await resetRates();
  for(const [sql,undo,args,expected] of [
   ["update private.identity_writing_grants set expires_at=clock_timestamp()-interval '1 second' where grant_hash=$1","update private.identity_writing_grants set expires_at=clock_timestamp()+interval '10 minutes' where grant_hash=$1",[grants[1].grant_hash],'SESSION_EXPIRED'],
   ['update private.identity_writing_grants set revoked_at=clock_timestamp() where grant_hash=$1','update private.identity_writing_grants set revoked_at=null where grant_hash=$1',[grants[1].grant_hash],'SESSION_REVOKED'],
   ['update private.identity_writing_delegations set revoked_at=clock_timestamp()','update private.identity_writing_delegations set revoked_at=null',[],'SESSION_REVOKED'],
   ['update private.identity_sessions set revoked_at=clock_timestamp() where id=$1','update private.identity_sessions set revoked_at=null where id=$1',[session(1)],'SESSION_REVOKED']
  ]){await admin(sql,args);bad(await call(1,'operations',{operation_id:baseRequest.operation_id}),expected);await admin(undo,args);}
 });
 console.log(`All ${groups} relationship SQL groups passed (PGlite, actual migration/RPC).`);
}finally{await pg.close();}
