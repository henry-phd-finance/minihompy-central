import assert from 'node:assert/strict';
import {createIdentityDb} from './helpers/identity-db.mjs';
import {handleIdentityApiRequest} from '../supabase/functions/identity-api/handler.js';
import {signToken,verifyToken} from '../supabase/functions/_shared/tokens.js';
import {randomSecret,sha256} from '../supabase/functions/_shared/auth-proof.js';
const {pg,db}=await createIdentityDb();
const secret='test-only-writing-proof-key-at-least-32-bytes';
const id=n=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const member=id(1), siteA=id(2), siteB=id(3), memberB=id(4), owner=id(5);
const options={supabaseClient:db,centralSecret:secret,allowedOrigins:new Set(['https://central.github.io'])};
const verifier=randomSecret(), challenge=await sha256(verifier);
let count=0;
async function group(name,fn){await fn();console.log(`PASS ${++count}: ${name}`);}
async function call(path,body={},expected=200,credential,overrides={}){
 const response=await handleIdentityApiRequest(new Request('https://central.test'+path,{method:'POST',headers:{'Content-Type':'application/json',...(credential?{Authorization:`Bearer ${credential}`}:{})},body:JSON.stringify(body)}),{...options,...overrides});
 const data=await response.json();assert.equal(response.status,expected,`${path}: ${JSON.stringify(data)}`);assert.equal(response.headers.get('Cache-Control'),'no-store');return data;
}
async function login(){
 const {data:a,error}=await db.rpc('identity_create_login_attempt',{p_member:member,p_site:siteA,p_return_site:siteB,p_return_path:'/home/',p_challenge:challenge});assert.equal(error,null);
 const {data:b}=await db.rpc('identity_activate_login_attempt',{p_id:a.id,p_member:member,p_site:siteA,p_owner:owner});
 const now=Math.floor(Date.now()/1000),ticket=await signToken({kind:'activation_ticket',jti:b.activation_id,sub:member,site_id:siteA,iat:now,exp:now+60},secret);
 return (await call('/sessions/complete',{activation_ticket:ticket,code_verifier:verifier})).central_session;
}
const issue=(session,extra={},expected=200)=>call('/writing-proofs/issue',{central_session:session,target_site_id:siteB,code_challenge:challenge,return_path:'/home/#/guestbook',...extra},expected);
const redeem=(proof,extra={},expected=200)=>call('/writing-proofs/redeem',{writing_proof:proof,site_id:siteB,code_verifier:verifier,...extra},expected);
try{
 await pg.query("insert into private.identity_members(id,handle,display_name) values($1,'alice','Alice'),($2,'bob','Bob')",[member,memberB]);
 for(const [sid,mid,name,local] of [[siteA,member,'alice',owner],[siteB,memberB,'bob',id(6)]]){
  await pg.query("insert into private.identity_sites(id,member_id,origin,base_path,homepage_url,login_url,supabase_project_ref,verification_status) values($1,$2,$3,'/home/',$4,$5,$6,'verified')",[sid,mid,`https://${name}.github.io`,`https://${name}.github.io/home/`,`https://${name}.github.io/home/login/`,name.repeat(4)]);
  await pg.query('insert into private.identity_bindings(site_id,member_id,local_user_id) values($1,$2,$3)',[sid,mid,local]);
 }
 let session=await login(), proof, granted;
 await group('real login completion persists separate SID; issue and redeem verified profile',async()=>{
  const c=await verifyToken(session,'central_session',secret);assert.ok(c.central_session_id);
  assert.equal((await pg.query('select count(*)::int as n from private.identity_sessions')).rows[0].n,1);
  proof=(await issue(session)).writing_proof;granted=await redeem(proof);
  assert.deepEqual(granted.member,{id:member,display_name:'Alice',homepage_url:'https://alice.github.io/home/'});
  assert.equal(granted.site_id,siteB);assert.ok(Date.parse(granted.expires_at)<=Date.now()+900000);
  assert.match(granted.grant,/^[A-Za-z0-9_-]{43}$/);
  assert.equal((await call('/writing-grants/check',{site_id:siteB},200,granted.grant)).active,true);
 });
 await group('proof consumed once; target, PKCE and kind cannot be substituted',async()=>{
  await redeem(proof,{},409);
  const p=(await issue(session)).writing_proof;
  await redeem(p,{site_id:siteA},403);await redeem(p,{code_verifier:randomSecret()},403);
  await redeem(p+'x',{},401);await redeem(session,{},401);
  const statuses=await Promise.all([0,1].map(()=>handleIdentityApiRequest(new Request('https://central.test/writing-proofs/redeem',{method:'POST',body:JSON.stringify({writing_proof:p,site_id:siteB,code_verifier:verifier})}),options).then(r=>r.status)));
  assert.deepEqual(statuses.sort(),[200,409]);
 });
 await group('expired signed proof and database deadline fail independently',async()=>{
  const p=(await issue(session)).writing_proof,c=await verifyToken(p,'writing_proof',secret),now=Math.floor(Date.now()/1000);
  await redeem(await signToken({...c,iat:now-61,exp:now-1},secret),{},401);
  await pg.query("update private.identity_writing_proofs set expires_at=now()-interval '1 second' where id=$1",[c.jti]);await redeem(p,{},401);
  await issue(session,{return_path:'https://evil.example/'},400);await issue(session,{code_challenge:'bad'},400);
 });
 await group('legacy sessions still identify visitors but cannot authorize writing',async()=>{
  const c=await verifyToken(session,'central_session',secret);delete c.central_session_id;const legacy=await signToken(c,secret);
  await issue(legacy,{},401);
  assert.equal((await call('/visits/issue',{central_session:legacy,target_site_id:siteB})).status,'identified');
 });
 await group('member, site, verification and binding revocation invalidate outstanding proofs/grants',async()=>{
  for(const [sql,undo,args] of [
   ["update private.identity_members set status='suspended' where id=$1","update private.identity_members set status='active' where id=$1",[member]],
   ["update private.identity_sites set verification_status='needs_reverification' where id=$1","update private.identity_sites set verification_status='verified' where id=$1",[siteA]],
   ["update private.identity_bindings set status='revoked' where site_id=$1","update private.identity_bindings set status='active' where site_id=$1",[siteA]],
  ]){const p=(await issue(session)).writing_proof;await pg.query(sql,args);await redeem(p,{},401);await call('/writing-grants/check',{site_id:siteB},401,granted.grant);await pg.query(undo,args);}
  await pg.query("update private.identity_members set status='suspended' where id=$1",[memberB]);await call('/writing-grants/check',{site_id:siteB},403,granted.grant);await pg.query("update private.identity_members set status='active' where id=$1",[memberB]);
  await call('/writing-grants/check',{site_id:siteA},403,granted.grant);
  await pg.query('update private.identity_bindings set local_user_id=$1 where site_id=$2',[id(99),siteA]);
  await issue(session,{},401);
  await pg.query('update private.identity_bindings set local_user_id=$1 where site_id=$2',[owner,siteA]);
 });
 await group('grant revoke is idempotent and expiry enforced',async()=>{
  const g=await redeem((await issue(session)).writing_proof);
  await call('/writing-grants/revoke',{},200,g.grant);await call('/writing-grants/revoke',{},200,g.grant);
  await call('/writing-grants/check',{site_id:siteB},401,g.grant);
  const next=await redeem((await issue(session)).writing_proof);
  await pg.query("update private.identity_writing_grants set expires_at=now()-interval '1 second' where grant_hash=$1",[await sha256(next.grant)]);
  await call('/writing-grants/check',{site_id:siteB},401,next.grant);
 });
 await group('logout invalidates grants, unconsumed proofs and visits, but not another login',async()=>{
  const second=await login(),pending=(await issue(session)).writing_proof;
  const visit=await call('/visits/issue',{central_session:session,target_site_id:siteB});
  await call('/sessions/logout',{central_session:session});await call('/sessions/logout',{central_session:session});
  await redeem(pending,{},401);await issue(session,{},401);await call('/writing-grants/check',{site_id:siteB},401,granted.grant);
  assert.equal((await call('/visits/issue',{central_session:session,target_site_id:siteB})).status,'anonymous');
  assert.equal((await call('/visits/resolve',{visit_ticket:visit.visit_ticket,site_id:siteB})).status,'anonymous');
  await issue(second);session=second;
 });
 await group('session version changes and server session expiry invalidate writing',async()=>{
  const c=await verifyToken(session,'central_session',secret);
  await pg.query('update private.identity_members set session_version=session_version+1 where id=$1',[member]);await issue(session,{},401);
  await pg.query('update private.identity_members set session_version=session_version-1 where id=$1',[member]);
  await pg.query("update private.identity_sessions set expires_at=now()-interval '1 second' where id=$1",[c.central_session_id]);await issue(session,{},401);session=await login();
 });
 await group('browser roles cannot read private grants or invoke service RPC',async()=>{
  for(const role of ['anon','authenticated']){
   await pg.exec('reset role; set role '+role);
   try{for(const table of ['identity_sessions','identity_writing_proofs','identity_writing_grants'])await assert.rejects(pg.query('select * from private.'+table));await assert.rejects(pg.query("select private.identity_writing_action('session','{}')"));}
   finally{await pg.exec('reset role; set role service_role');}
  }
 });
 await group('profile comes from verified directory, bounded writer label, and invalid home URL fails closed',async()=>{
  await pg.query("update private.identity_members set display_name=$1 where id=$2",['가'.repeat(30),member]);
  await pg.query("update private.identity_sites set homepage_url='https://alice.github.io/home/index.html' where id=$1",[siteA]);
  const g=await redeem((await issue(session,{member_id:memberB,display_name:'spoof'})).writing_proof);
  assert.equal(g.member.id,member);assert.equal(g.member.display_name,'가'.repeat(20));
  assert.equal(g.member.homepage_url,'https://alice.github.io/home/index.html');
  await pg.query("update private.identity_sites set homepage_url='https://evil.example/home/' where id=$1",[siteA]);
  await call('/writing-grants/check',{site_id:siteB},503,g.grant);
  await pg.query("update private.identity_sites set homepage_url='https://alice.github.io/home/' where id=$1",[siteA]);
 });
 await group('secrets are not persisted and database failures fail closed',async()=>{
  const g=await redeem((await issue(session)).writing_proof);
  const dump=JSON.stringify((await pg.query('select * from private.identity_writing_grants')).rows)+JSON.stringify((await pg.query('select * from private.identity_writing_proofs')).rows);
  assert.ok(!dump.includes(g.grant));assert.ok(!dump.includes(verifier));assert.ok(!dump.includes(session));
  const data=await call('/writing-grants/check',{site_id:siteB},503,g.grant,{supabaseClient:{rpc:async()=>({error:{message:'sensitive detail'}})}});assert.ok(!JSON.stringify(data).includes('sensitive'));
 });
 console.log(`All ${count} member writing groups passed (PGlite SQL + actual API handler).`);
}finally{await pg.close();}
