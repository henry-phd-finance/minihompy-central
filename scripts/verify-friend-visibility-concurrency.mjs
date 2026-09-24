// Real PostgreSQL connections and PostgREST, disposable loopback-only containers.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:net';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {member,site,session,id,seedRelationships,grantFor,rpc,command} from './helpers/relationship-fixture.mjs';
const container=execFileSync('docker',['run','--rm','-d','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','postgres:16-alpine'],{encoding:'utf8'}).trim();
const sleep=ms=>new Promise(r=>setTimeout(r,ms));let pool,a,b,restContainer,grants={},alternate,relation,groups=0;
const ok=r=>{assert.ok(!r.failure,JSON.stringify(r));return r;};
const args=(n=1)=>({...grants[n],request_id:randomUUID(),request_hash:'a'.repeat(64)});
const read=async(c,p=args())=>(await c.query('select private.identity_read_context($1) result',[p])).rows[0].result;
const action=(c,n,verb,rev,rid)=>rpc(c,'actions',{...grants[n],...command(n===1?2:1,verb,rev,rid)});
const disconnect=c=>action(c,2,'disconnect',relation.revision,relation.request_id);
const logout=c=>c.query("select private.identity_writing_action('logout',$1)",[{session_id:session(1),member_id:member(1),session_version:1}]);
async function waitLock(c){for(let i=0;i<200;i++){if((await pool.query('select wait_event_type from pg_stat_activity where pid=$1',[c.processID])).rows[0]?.wait_event_type==='Lock')return;await sleep(10);}throw Error('No observed lock wait');}
async function reset(){
 await pool.query("truncate private.identity_relationships,private.identity_relationship_operations,private.identity_review_permits,private.identity_relationship_limits,private.identity_relationship_cooldowns;update private.identity_members set status='active';update private.identity_sites set status='active';update private.identity_bindings set status='active';update private.identity_sessions set revoked_at=null,expires_at=clock_timestamp()+interval '1 day';update private.identity_writing_grants set revoked_at=null,expires_at=clock_timestamp()+interval '15 minutes';update private.identity_writing_delegations set revoked_at=null");
 const pending=ok(await action(a,1,'request',0)).relationship;relation=ok(await action(b,2,'accept',1,pending.request_id)).relationship;
}
async function check(name,fn){await reset();await fn();console.log(`PASS ${++groups}: ${name}`);}
try {
 const port=Number(execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').at(-1));
 pool=new pg.Pool({host:'127.0.0.1',port,user:'postgres',database:'postgres',max:6});
 for(let i=0;;i++){try{await pool.query('select 1');break;}catch(e){if(i>=100)throw e;await sleep(100);}}
 await pool.query('create role anon;create role authenticated;create role service_role bypassrls');
 for(const f of ['202609180001_identity.sql','202609190001_fix_private_schema_permissions.sql','202609230001_verified_identity.sql','202609230002_member_writing.sql','202609230003_member_navigation.sql','202609230004_member_sessions.sql','202609240001_member_relationships.sql'])await pool.query(await readFile(new URL('../supabase/migrations/'+f,import.meta.url),'utf8'));
 await seedRelationships(pool,3);for(const n of [1,2,3])grants[n]=await grantFor(pool,n);
 const before=(await pool.query('select * from private.identity_writing_grants order by grant_hash')).rows;
 await pool.query(await readFile(new URL('../supabase/migrations/202609240002_friend_visibility.sql',import.meta.url),'utf8'));
 assert.deepEqual((await pool.query('select * from private.identity_writing_grants order by grant_hash')).rows,before);
 await pool.query("insert into private.identity_sessions(id,member_id,site_id,session_version,owner_user_id,expires_at) values($1,$2,$3,1,$4,clock_timestamp()+interval '1 day')",[id(999),member(1),site(1),id(301)]);alternate=await grantFor(pool,1,2,id(999));
 a=await pool.connect();b=await pool.connect();for(const c of [a,b])await c.query("set role service_role;set statement_timeout='6s'");
 await check('disconnect first: blocked reader sees committed none, including same request ID retry',async()=>{
  const p=args();await a.query('begin');ok(await disconnect(a));const wait=read(b,p);await waitLock(b);await a.query('commit');assert.equal(ok(await wait).can_read_friends,false);assert.equal(ok(await read(b,p)).relationship,'none');
 });
 await check('read first: disconnect waits, already authorized context has at most five seconds',async()=>{
  await a.query('begin');const d=ok(await read(a));const wait=disconnect(b);await waitLock(b);await a.query('commit');ok(await wait);assert.equal(d.can_read_friends,true);assert.ok(Date.parse(d.expires_at)-Date.parse(d.authorized_at)<=5000);assert.equal(ok(await read(a)).can_read_friends,false);
 });
 await check('logout first: reader waits and denies; read first makes logout wait then denies next read',async()=>{
  await a.query('begin');await logout(a);const wait=read(b);await waitLock(b);await a.query('commit');assert.equal((await wait).failure,'SESSION_REVOKED');
  await reset();await a.query('begin');ok(await read(a));const out=logout(b);await waitLock(b);await a.query('commit');await out;assert.equal((await read(a)).failure,'SESSION_REVOKED');
 });
 await check('owner/actor/site/binding deactivation before read commits is rechecked after row lock waits',async()=>{
  for(const [table,key,target,code] of [['identity_members','id',member(2),'TARGET_MISMATCH'],['identity_members','id',member(1),'SESSION_REVOKED'],['identity_sites','id',site(2),'TARGET_MISMATCH'],['identity_bindings','site_id',site(1),'SESSION_REVOKED']]){
   const c=await pool.connect();try{
    await c.query('begin');await c.query(`update private.${table} set status=$1 where ${key}=$2`,[table==='identity_bindings'?'revoked':'suspended',target]);
    const wait=read(b);await waitLock(b);await c.query('commit');assert.equal((await wait).failure,code);
    await c.query(`update private.${table} set status='active' where ${key}=$1`,[target]);
   }finally{await c.query('rollback');c.release();}
  }
 });
 await check('read first: account deactivation waits, subsequent read denies',async()=>{
  const c=await pool.connect();try{await a.query('begin');ok(await read(a));const wait=c.query("update private.identity_members set status='suspended' where id=$1",[member(2)]);await waitLock(c);await a.query('commit');await wait;assert.equal((await read(a)).failure,'TARGET_MISMATCH');}finally{c.release();}
 });
 await check('grant expiry during pair lock wait is checked again',async()=>{
  await a.query('begin');ok(await disconnect(a));const wait=read(b);await waitLock(b);await pool.query("update private.identity_writing_grants set expires_at=clock_timestamp()-interval '1 second' where grant_hash=$1",[grants[1].grant_hash]);await a.query('commit');assert.equal((await wait).failure,'SESSION_EXPIRED');
 });
 await check('quota is atomic across independent logins, separate from relationship limits',async()=>{
  await pool.query("insert into private.identity_relationship_limits select $1,floor(extract(epoch from clock_timestamp())/60)::bigint+x,239 from generate_series(0,1) x",['read-context:'+member(1)+':'+site(2)]);
  await a.query('begin');ok(await read(a));const wait=read(b,{...args(),...alternate});await waitLock(b);await a.query('commit');assert.equal((await wait).failure,'RATE_LIMITED');
  assert.ok(!(await rpc(a,'state',{...grants[1],target_member_id:member(2)})).failure);
 });
 // PostgREST hoists function statement_timeout before executing the outer query.
 await pool.query("create role authenticator login;grant service_role to authenticator;alter role authenticator set statement_timeout='8s';alter role authenticator set lock_timeout='8s'");
 const server=createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const restPort=server.address().port;await new Promise(r=>server.close(r));
 restContainer=execFileSync('docker',['run','--rm','-d','--network','host','-e',`PGRST_DB_URI=postgres://authenticator@127.0.0.1:${port}/postgres`,'-e','PGRST_DB_SCHEMAS=private','-e','PGRST_SERVER_HOST=127.0.0.1','-e','PGRST_DB_ANON_ROLE=service_role','-e',`PGRST_SERVER_PORT=${restPort}`,'public.ecr.aws/supabase/postgrest:v14.5'],{encoding:'utf8'}).trim();
 const base=`http://127.0.0.1:${restPort}`;for(let i=0;;i++){try{if((await fetch(base)).ok)break;}catch{}if(i>100)throw Error('PostgREST startup');await sleep(100);}
 const http=async()=>{const r=await fetch(base+'/rpc/identity_read_context',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({p_args:args()}),signal:AbortSignal.timeout(10000)});return {status:r.status,data:await r.json()};};
 await check('PostgREST executes actual service-only read RPC',async()=>{const r=await http();assert.equal(r.status,200);assert.equal(r.data.can_read_friends,true);});
 await check('PostgREST lock timeout applies at three seconds, not authenticator eight seconds',async()=>{
  await a.query('begin');ok(await read(a));const start=Date.now(),r=await http(),elapsed=Date.now()-start;assert.ok(['57014','55P03'].includes(r.data.code),JSON.stringify(r));assert.ok(elapsed>=2700&&elapsed<5000,'elapsed '+elapsed);await a.query('rollback');console.log('HTTP lock bound ms: '+elapsed);
 });
 await check('PostgREST statement timeout cancels slow counter and rolls back quota',async()=>{
  await pool.query("create function private.slow_read_fixture() returns trigger language plpgsql as $$begin perform pg_sleep(5);return new;end;$$;create trigger slow_read_fixture after insert or update on private.identity_relationship_limits for each row execute function private.slow_read_fixture()");
  const start=Date.now(),r=await http(),elapsed=Date.now()-start;assert.equal(r.data.code,'57014',JSON.stringify(r));assert.ok(elapsed>=2700&&elapsed<4500,'elapsed '+elapsed);await sleep(100);assert.equal((await pool.query("select count(*)::int n from private.identity_relationship_limits where bucket like 'read-context:%'")).rows[0].n,0);await pool.query('drop trigger slow_read_fixture on private.identity_relationship_limits;drop function private.slow_read_fixture()');console.log('HTTP statement bound ms: '+elapsed);
 });
 console.log(`All ${groups} independent PostgreSQL/PostgREST groups passed; no hosted writes.`);
}finally{
 if(restContainer)execFileSync('docker',['rm','-f',restContainer],{stdio:'ignore'});
 for(const c of [a,b].filter(Boolean)){await c.query('rollback').catch(()=>{});c.release();}await pool?.end();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});
}
