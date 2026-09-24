// Real independent PostgreSQL connections, observed lock waits, disposable loopback-only container.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {member,site,session,id,seedRelationships,grantFor,rpc,command} from './helpers/relationship-fixture.mjs';
const container=execFileSync('docker',['run','--rm','-d','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','postgres:16-alpine'],{encoding:'utf8'}).trim();
const sleep=ms=>new Promise(r=>setTimeout(r,ms));let pool,a,b,grants={},alternate,groups=0;
const ok=r=>{assert.ok(!r.failure,JSON.stringify(r));return r;};
const bad=(r,f)=>assert.equal(r.failure,f,JSON.stringify(r));
const call=(client,n,act,args={})=>rpc(client,act,{...grants[n],...args});
const act=(client,n,target,verb,rev,rid)=>call(client,n,'actions',command(target,verb,rev,rid));
async function waitLock(client){for(let i=0;i<300;i++){if((await pool.query('select wait_event_type from pg_stat_activity where pid=$1',[client.processID])).rows[0]?.wait_event_type==='Lock')return;await sleep(10);}throw Error('Expected observed PostgreSQL lock wait');}
async function reset(){
 await pool.query('truncate private.identity_relationship_operations,private.identity_review_permits,private.identity_relationships,private.identity_relationship_limits,private.identity_relationship_cooldowns');
 await pool.query("update private.identity_sessions set revoked_at=null;update private.identity_writing_grants set revoked_at=null,expires_at=clock_timestamp()+interval '10 minutes';update private.identity_writing_delegations set revoked_at=null");
}
async function pending(){return ok(await act(a,1,2,'request',0)).relationship;}
async function accepted(){const r=await pending();return ok(await act(b,2,1,'accept',1,r.request_id)).relationship;}
async function check(name,fn){await reset();await fn();console.log(`PASS ${++groups}: ${name}`);}
const permit=()=>({operation_id:randomUUID(),body_sha256:'a'.repeat(64)});
const logout=(c,n)=>c.query("select private.identity_writing_action('logout',$1) result",[{session_id:session(n),member_id:member(n),session_version:1}]);
try{
 const port=Number(execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').at(-1));
 pool=new pg.Pool({host:'127.0.0.1',port,user:'postgres',database:'postgres',max:5});
 for(let n=0;;n++){try{await pool.query('select 1');break;}catch(e){if(n>=100)throw e;await sleep(100);}}
 await pool.query('create role anon;create role authenticated;create role service_role bypassrls');
 for(const f of ['202609180001_identity.sql','202609190001_fix_private_schema_permissions.sql','202609230001_verified_identity.sql','202609230002_member_writing.sql','202609230003_member_navigation.sql','202609230004_member_sessions.sql'])await pool.query(await readFile(new URL('../supabase/migrations/'+f,import.meta.url),'utf8'));
 await seedRelationships(pool,6);for(let n=1;n<=6;n++)grants[n]=await grantFor(pool,n);
 const baseline=(await pool.query('select * from private.identity_writing_grants order by grant_hash')).rows;
 await pool.query(await readFile(new URL('../supabase/migrations/202609240001_member_relationships.sql',import.meta.url),'utf8'));
 assert.deepEqual((await pool.query('select * from private.identity_writing_grants order by grant_hash')).rows,baseline);
 console.log('PASS: additive migration preserves existing grants');
 await pool.query("insert into private.identity_sessions(id,member_id,site_id,session_version,owner_user_id,expires_at) values($1,$2,$3,1,$4,clock_timestamp()+interval '1 day')",[id(999),member(1),site(1),id(301)]);
 alternate=await grantFor(pool,1,2,id(999));
 a=await pool.connect();b=await pool.connect();
 for(const c of [a,b])await c.query("set statement_timeout='8s';set lock_timeout='6s';set role service_role");
 await check('opposing requests serialize on absent pair: exactly one pending, never automatic accept',async()=>{
  await a.query('begin');const one=ok(await act(a,1,2,'request',0));const two=act(b,2,1,'request',0);await waitLock(b);await a.query('commit');bad(await two,'REVISION_CONFLICT');
  assert.equal((await pool.query('select count(*)::int n from private.identity_relationships')).rows[0].n,1);assert.equal(one.relationship.state,'outgoing');
 });
 await check('accept first, cancel waits then conflicts',async()=>{
  const r=await pending();await a.query('begin');ok(await act(a,2,1,'accept',1,r.request_id));const wait=act(b,1,2,'cancel',1,r.request_id);await waitLock(b);await a.query('commit');bad(await wait,'REVISION_CONFLICT');
  assert.equal(ok(await call(a,1,'state',{target_member_id:member(2)})).state,'accepted');
 });
 await check('cancel first, accept cannot revive cancelled request',async()=>{
  const r=await pending();await a.query('begin');ok(await act(a,1,2,'cancel',1,r.request_id));const wait=act(b,2,1,'accept',1,r.request_id);await waitLock(b);await a.query('commit');bad(await wait,'REVISION_CONFLICT');
 });
 await check('reject first, concurrent accept cannot overwrite rejection',async()=>{
  const r=await pending();await a.query('begin');ok(await act(a,2,1,'reject',1,r.request_id));const wait=act(b,2,1,'accept',1,r.request_id);await waitLock(b);await a.query('commit');bad(await wait,'REVISION_CONFLICT');
 });
 await check('new request generation survives old delayed cancel/accept',async()=>{
  const old=await pending();ok(await act(a,1,2,'cancel',1,old.request_id));
  await a.query('begin');const next=ok(await act(a,2,1,'request',2)).relationship;
  const wait=act(b,1,2,'cancel',3,old.request_id);await waitLock(b);await a.query('commit');bad(await wait,'REVISION_CONFLICT');
  bad(await act(a,2,1,'accept',3,old.request_id),'REVISION_CONFLICT');assert.notEqual(next.request_id,old.request_id);
 });
 await check('same operation across separate logins is one mutation and one receipt',async()=>{
  const args=command(2,'request',0);await a.query('begin');const first=ok(await call(a,1,'actions',args));
  const wait=rpc(b,'actions',{...alternate,...args});await waitLock(b);await a.query('commit');assert.deepEqual(ok(await wait),first);
  assert.equal((await pool.query('select count(*)::int n from private.identity_relationship_operations')).rows[0].n,1);
 });
 await check('same operation with different target conflicts even across separate logins',async()=>{
  const args=command(2,'request',0);await a.query('begin');ok(await call(a,1,'actions',args));
  const wait=rpc(b,'actions',{...alternate,...args,target_member_id:member(3)});await waitLock(b);await a.query('commit');bad(await wait,'REQUEST_CONFLICT');
  assert.equal((await pool.query('select count(*)::int n from private.identity_relationships')).rows[0].n,1);
 });
 await check('permit first, disconnect waits; original permit remains bounded and replayable',async()=>{
  const r=await accepted(),args=permit();await a.query('begin');const first=ok(await call(a,1,'review-permits',args));
  const wait=act(b,2,1,'disconnect',2,r.request_id);await waitLock(b);await a.query('commit');ok(await wait);
  assert.deepEqual(ok(await call(a,1,'review-permits',args)),first);bad(await call(a,1,'review-permits',permit()),'NOT_FRIENDS');
 });
 await check('disconnect first, pending permit never gets authorization',async()=>{
  const r=await accepted();await a.query('begin');ok(await act(a,2,1,'disconnect',2,r.request_id));
  const wait=call(b,1,'review-permits',permit());await waitLock(b);await a.query('commit');bad(await wait,'NOT_FRIENDS');
  assert.equal((await pool.query('select count(*)::int n from private.identity_review_permits')).rows[0].n,0);
 });
 await check('concurrent permit retries issue one authorization and preserve deadline',async()=>{
  await accepted();const args=permit();await a.query('begin');const first=ok(await call(a,1,'review-permits',args));
  const wait=call(b,1,'review-permits',args);await waitLock(b);await a.query('commit');assert.deepEqual(ok(await wait),first);
  bad(await rpc(b,'review-permits',{...alternate,...args}),'FORBIDDEN');
 });
 await check('central logout first: waiting relationship mutation fails auth',async()=>{
  await a.query('begin');await logout(a,1);const wait=act(b,1,2,'request',0);await waitLock(b);await a.query('commit');bad(await wait,'SESSION_REVOKED');
  assert.equal((await pool.query('select count(*)::int n from private.identity_relationships')).rows[0].n,0);
 });
 await check('mutation first: logout waits and blocks subsequent result lookup',async()=>{
  const args=command(2,'request',0);await a.query('begin');ok(await call(a,1,'actions',args));
  const wait=logout(b,1);await waitLock(b);await a.query('commit');await wait;
  bad(await call(a,1,'operations',{operation_id:args.operation_id}),'SESSION_REVOKED');
 });
 await check('grant expiry while waiting for pair lock is rechecked before commit',async()=>{
  const r=await accepted();await a.query('begin');ok(await act(a,2,1,'disconnect',2,r.request_id));
  const wait=call(b,1,'review-permits',permit());await waitLock(b);
  await pool.query("update private.identity_writing_grants set expires_at=clock_timestamp()-interval '1 second' where grant_hash=$1",[grants[1].grant_hash]);
  await a.query('commit');bad(await wait,'SESSION_EXPIRED');
 });
 await check('actor quota across separate login sessions is atomic',async()=>{
  await pool.query("insert into private.identity_relationship_limits values($1,floor(extract(epoch from clock_timestamp())/60)::bigint,19)",['change:'+member(1)]);
  await a.query('begin');ok(await act(a,1,2,'request',0));const wait=rpc(b,'actions',{...alternate,...command(3,'request',0)});
  await waitLock(b);await a.query('commit');bad(await wait,'RATE_LIMITED');
  assert.equal((await pool.query('select count(*)::int n from private.identity_relationships')).rows[0].n,1);
 });
 await check('rolled-back transaction leaves no partial pair/operation/quota; waiter can succeed',async()=>{
  await a.query('begin');ok(await act(a,1,2,'request',0));const wait=act(b,2,1,'request',0);await waitLock(b);await a.query('rollback');ok(await wait);
  const rows=(await pool.query('select sender_id from private.identity_relationships')).rows;assert.deepEqual(rows,[{sender_id:member(2)}]);
  assert.equal((await pool.query('select count(*)::int n from private.identity_relationship_operations')).rows[0].n,1);
 });
 await check('public quota serializes across connections and rejects the 121st query',async()=>{
  const ip='a'.repeat(64);await pool.query("insert into private.identity_relationship_limits values($1,floor(extract(epoch from clock_timestamp())/60)::bigint,119)",['public:'+ip]);
  await a.query('begin');ok(await rpc(a,'friends',{member_id:member(1),ip_hash:ip}));const wait=rpc(b,'friends',{member_id:member(2),ip_hash:ip});await waitLock(b);await a.query('commit');bad(await wait,'RATE_LIMITED');
 });
 console.log(`All ${groups} independent PostgreSQL concurrency groups passed; container cleanup follows.`);
}finally{
 for(const c of [a,b].filter(Boolean)){await c.query('rollback').catch(()=>{});c.release();}
 if(pool)await pool.end();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});
}
