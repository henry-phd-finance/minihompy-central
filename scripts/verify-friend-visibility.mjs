import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createIdentityDb} from './helpers/identity-db.mjs';
import {member,site,session,seedRelationships,grantFor,rpc,command,hash} from './helpers/relationship-fixture.mjs';
import {handleIdentityApiRequest} from '../supabase/functions/identity-api/handler.js';
const {pg,db}=await createIdentityDb();let groups=0;const grants={},tokens={};
const body=()=>({site_id:site(2),request_id:randomUUID(),request_hash:'a'.repeat(64)});
const options={supabaseClient:db,allowedOrigins:new Set(['https://m1.test']),transportPeerIp:'127.0.0.1'};
const admin=async(sql,args)=>{await pg.exec('reset role');try{return await pg.query(sql,args);}finally{await pg.exec('set role service_role');}};
const check=async(name,fn)=>{await fn();console.log(`PASS ${++groups}: ${name}`);};
async function http(n=1,b=body(),status=200,extra={},opts=options){
 const r=await handleIdentityApiRequest(new Request('https://central.test/functions/v1/identity-api/relationships/read-context',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+tokens[n],...extra},body:JSON.stringify(b)}),opts);
 const data=await r.json();assert.equal(r.status,status,JSON.stringify(data));assert.equal(r.headers.get('Cache-Control'),'private, no-store');return {data,r};
}
const sql=(args)=>db.rpc('identity_read_context',{p_args:args});
const action=(n,verb,revision,rid)=>rpc(pg,'actions',{...grants[n],...command(n===1?2:1,verb,revision,rid)});
try {
 await pg.exec('reset role');await seedRelationships(pg,3);
 for(const n of [1,2,3]){grants[n]=await grantFor(pg,n);tokens[n]=String(n).repeat(43);await pg.query('update private.identity_writing_grants set grant_hash=$1 where grant_hash=$2',[hash(tokens[n]),grants[n].grant_hash]);grants[n].grant_hash=hash(tokens[n]);}
 await pg.exec('set role service_role');
 await check('service-only RPC and no reusable permit table; strict SQL input',async()=>{
  for(const role of ['anon','authenticated']){await pg.exec('set role '+role);assert.equal((await sql({...body(),...grants[1]})).error?.code,'42501');await assert.rejects(pg.query('select private.identity_read_context_ready()'),e=>e.code==='42501');}
  await pg.exec('set role service_role');
  for(const input of [{},{...body(),...grants[1],owner_member_id:member(1)},{...body(),...grants[1],request_hash:7},{...body(),...grants[1],request_id:null}])assert.equal((await sql(input)).data.failure,'BAD_REQUEST');
 });
 await check('HTTP rejects spoofed fields, browser Origin, malformed credentials and cross-site grants',async()=>{
  for(const patch of [{actor_member_id:member(2)},{can_read_friends:true},{owner_member_id:member(1)},{request_hash:'x'},{request_id:4},{body:'content'}])await http(1,{...body(),...patch},400);
  await http(1,body(),403,{Origin:'https://m1.test'});await http(1,body(),401,{Authorization:'Bearer '+member(1)});
  await http(1,{...body(),site_id:site(1)},403);await http(1,body(),401,{Authorization:'Bearer '+'z'.repeat(43)});
 });
 await check('none/pending/accepted/self/C permissions, exact response and short binding',async()=>{
  assert.equal((await http()).data.relationship,'none');assert.equal((await http(2)).data.relationship,'self');
  const pending=await action(1,'request',0);assert.ok(!pending.failure,JSON.stringify(pending));const rid=pending.relationship.request_id;
  assert.equal((await http()).data.relationship,'pending');assert.equal((await http()).data.can_read_friends,false);
  assert.ok(!(await action(2,'accept',1,rid)).failure);
  const b=body(),d=(await http(1,b)).data;
  assert.equal(d.can_read_friends,true);assert.equal(d.actor_member_id,member(1));assert.equal(d.owner_member_id,member(2));assert.equal(d.central_session_id,session(1));assert.equal(d.request_id,b.request_id);assert.equal(d.request_hash,b.request_hash);
  assert.ok(Date.parse(d.expires_at)-Date.parse(d.authorized_at)<=5000);
  assert.deepEqual(Object.keys(d).sort(),['protocol','request_id','request_hash','actor_member_id','site_id','owner_member_id','central_session_id','relationship','relationship_revision','can_read_friends','authorized_at','expires_at'].sort());
  assert.equal((await http(3)).data.can_read_friends,false);
  assert.ok(!(await action(2,'disconnect',2,rid)).failure);
  assert.equal((await http(1,b)).data.can_read_friends,false); // repeated ID is not a cached permit
 });
 await check('inactive actor/owner/site/binding and revoked/expired session or grant fail closed',async()=>{
  const cases=[
   ['identity_members','status',"'suspended'",'id',member(1),401,"'active'"],
   ['identity_members','status',"'suspended'",'id',member(2),403,"'active'"],
   ['identity_sites','status',"'suspended'",'id',site(2),403,"'active'"],
   ['identity_sites','verification_status',"'needs_reverification'",'id',site(2),403,"'verified'"],
   ['identity_bindings','status',"'revoked'",'site_id',site(1),401,"'active'"],
   ['identity_bindings','status',"'revoked'",'site_id',site(2),403,"'active'"],
   ['identity_sessions','expires_at',"clock_timestamp()-interval '1 second'",'id',session(1),401,"clock_timestamp()+interval '1 day'"],
   ['identity_sessions','revoked_at','clock_timestamp()','id',session(1),401,'null'],
   ['identity_writing_grants','revoked_at','clock_timestamp()','grant_hash',grants[1].grant_hash,401,'null'],
   ['identity_writing_grants','expires_at',"clock_timestamp()-interval '1 second'",'grant_hash',grants[1].grant_hash,401,"clock_timestamp()+interval '15 minutes'"]
  ];
  for(const [table,col,value,key,id,status,restore] of cases){await admin(`update private.${table} set ${col}=${value} where ${key}=$1`,[id]);await http(1,body(),status);await admin(`update private.${table} set ${col}=${restore} where ${key}=$1`,[id]);}
 });
 await check('independent 240/min actor+site quota and bounded Retry-After',async()=>{
  const bucket='read-context:'+member(1)+':'+site(2);
  // Cover both minute windows so crossing a minute boundary cannot make this flaky.
  await admin("insert into private.identity_relationship_limits(bucket,window_start,hits) select $1,floor(extract(epoch from clock_timestamp())/60)::bigint+x,240 from generate_series(0,1) x on conflict(bucket,window_start) do update set hits=240",[bucket]);
  const {r}=await http(1,body(),429);assert.ok(Number(r.headers.get('Retry-After'))>=1&&Number(r.headers.get('Retry-After'))<=60);
  await http(3);assert.ok(!(await rpc(pg,'state',{...grants[1],target_member_id:member(2)})).failure);
  await admin('delete from private.identity_relationship_limits where bucket=$1',[bucket]);
 });
 await check('capability follows actual SQL readiness; malformed DB context and unavailable DB fail closed',async()=>{
  const health=async(opts)=>(await (await handleIdentityApiRequest(new Request('https://central.test/health'),opts)).json()).friend_visibility_protocol;
  assert.equal(await health(options),1);const absent={...options,supabaseClient:{rpc:async()=>({error:{code:'missing'}})}};assert.equal(await health(absent),0);await http(1,body(),503,{},absent);
  const b=body(),good=(await http(1,b)).data;
  for(const patch of [{site_id:site(1)},{request_id:randomUUID()},{can_read_friends:true},{protocol:2},{expires_at:new Date(Date.now()+60000).toISOString()}])await http(1,b,503,{}, {...options,supabaseClient:{rpc:async()=>({data:{...good,...patch}})}});
 });
 await check('HTTP method, bounded body and five-second abort fail closed',async()=>{
  const url='https://central.test/functions/v1/identity-api/relationships/read-context';
  const invoke=async(init,status)=>{const r=await handleIdentityApiRequest(new Request(url,init),options);assert.equal(r.status,status);};
  await invoke({method:'GET'},405);
  await invoke({method:'POST',headers:{'Content-Type':'application/json'},body:'{'},400);
  await invoke({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...body(),request_hash:'a'.repeat(9000)})},400);
  let signal;const start=Date.now();
  await http(1,body(),503,{}, {...options,supabaseClient:{rpc:()=>({abortSignal(s){signal=s;return new Promise(()=>{});}})}});
  assert.equal(signal.aborted,true);assert.ok(Date.now()-start>=4900&&Date.now()-start<6500);
 });
 await check('missing read RPC removes capability; revoked delegation is rejected',async()=>{
  await admin('alter function private.identity_read_context(jsonb) rename to unavailable_read_context');
  const r=await handleIdentityApiRequest(new Request('https://central.test/health'),options);assert.equal((await r.json()).friend_visibility_protocol,0);
  await admin('alter function private.unavailable_read_context(jsonb) rename to identity_read_context');
  await admin("update private.identity_writing_delegations set revoked_at=clock_timestamp() where session_id=$1",[session(1)]);await http(1,body(),401);
 });
 console.log(`All ${groups} friend visibility SQL/HTTP groups passed.`);
} finally {await pg.close();}
