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
 const session=await login(), attempt='visit-attempt-v2';
 const issue2=async()=>{
  const v=await call('/visits/issue',{central_session:session,target_site_id:siteB,return_path:'/home/#/guestbook',attempt_id:attempt,writing_protocol:2,code_challenge:challenge});
  const fragment=new URLSearchParams(new URL(v.return_url).hash.slice(1));
  assert.equal(fragment.get('vt'),v.visit_ticket);return fragment.get('wp');
 };
 const redeem2=(p,extra={},status=200)=>redeem(p,{protocol:2,attempt_id:attempt,...extra},status);
 const renew=(d,site=siteB,status=200)=>call('/writing-delegations/renew',{site_id:site},status,d);
 let family;
 await group('combined visit signs v2 proof bound to member, site, PKCE and attempt',async()=>{
  const p=await issue2(),c=await verifyToken(p,'writing_proof',secret);
  assert.equal(c.protocol,2);assert.equal(c.attempt_id,attempt);assert.equal(c.aud,siteB);
  await redeem2(p,{attempt_id:'other'},403);await redeem2(p,{code_verifier:randomSecret()},403);
  await redeem(p,{},403);family=await redeem2(p);assert.match(family.delegation,/^[A-Za-z0-9_-]{43}$/);
  assert.ok(Date.parse(family.delegation_expires_at)>Date.parse(family.expires_at));await redeem2(p,{},409);
 });
 await group('anonymous and v1 visits never issue v2 writing credentials',async()=>{
  for(const b of [{writing_protocol:2,code_challenge:challenge,attempt_id:attempt},{central_session:session}]){
   const v=await call('/visits/issue',{target_site_id:siteB,...b});assert.equal(new URLSearchParams(new URL(v.return_url).hash.slice(1)).has('wp'),false);
  }
  await call('/visits/issue',{target_site_id:siteB,writing_protocol:2,code_challenge:'bad',attempt_id:attempt},400);
  const old=await redeem((await issue(session)).writing_proof);assert.equal(old.delegation,undefined);
 });
 await group('expired initial grant renews with site-scoped delegation, not grant bearer',async()=>{
  await pg.query("update private.identity_writing_grants set expires_at=now()-interval '1 second' where grant_hash=$1",[await sha256(family.grant)]);
  await call('/writing-grants/check',{site_id:siteB},401,family.grant);
  const fresh=await renew(family.delegation);assert.equal(fresh.member.id,member);assert.equal(fresh.proof_id,family.proof_id);
  assert.ok(Date.parse(fresh.expires_at)<=Date.now()+900000);
  await call('/writing-grants/check',{site_id:siteB},200,fresh.grant);
  await renew(family.grant,siteB,401);await call('/writing-grants/check',{site_id:siteB},401,family.delegation);
  await renew(family.delegation,siteA,403);
  assert.equal((await pg.query('select count(*)::int n from private.identity_writing_grants where delegation_hash=$1',[await sha256(family.delegation)])).rows[0].n,1);
 });
 await group('concurrent renewal is bounded and rate-limited with Retry-After',async()=>{
  await pg.query('update private.identity_writing_delegations set last_renewed_at=null');
  const requests=await Promise.all([0,1].map(()=>handleIdentityApiRequest(new Request('https://central.test/writing-delegations/renew',{method:'POST',headers:{Authorization:'Bearer '+family.delegation},body:JSON.stringify({site_id:siteB})}),options)));
  assert.deepEqual(requests.map(r=>r.status).sort(),[200,429]);assert.equal(requests.find(r=>r.status===429).headers.get('Retry-After'),'1');
 });
 await group('delegation revoke is idempotent and invalidates all family grants',async()=>{
  await call('/writing-delegations/revoke',{},200,family.delegation);await call('/writing-delegations/revoke',{},200,family.delegation);
  await renew(family.delegation,siteB,401);
  const rows=(await pg.query('select revoked_at from private.identity_writing_grants where delegation_hash=$1',[await sha256(family.delegation)])).rows;assert.ok(rows.length);assert.ok(rows.every(r=>r.revoked_at));
 });
 await group('member/version/home/target/binding changes block delegation renewal',async()=>{
  family=await redeem2(await issue2());
  for(const [sql,undo,args,status] of [
   ["update private.identity_members set status='suspended' where id=$1","update private.identity_members set status='active' where id=$1",[member],401],
   ['update private.identity_members set session_version=2 where id=$1','update private.identity_members set session_version=1 where id=$1',[member],401],
   ["update private.identity_sites set verification_status='needs_reverification' where id=$1","update private.identity_sites set verification_status='verified' where id=$1",[siteA],401],
   ["update private.identity_sites set verification_status='needs_reverification' where id=$1","update private.identity_sites set verification_status='verified' where id=$1",[siteB],403],
   ["update private.identity_bindings set status='revoked' where site_id=$1","update private.identity_bindings set status='active' where site_id=$1",[siteA],401],
   ["update private.identity_bindings set status='revoked' where site_id=$1","update private.identity_bindings set status='active' where site_id=$1",[siteB],403],
  ]){await pg.query(sql,args);await renew(family.delegation,siteB,status);await pg.query(undo,args);}
  await pg.query('update private.identity_bindings set local_user_id=$1 where site_id=$2',[id(99),siteA]);await renew(family.delegation,siteB,401);await pg.query('update private.identity_bindings set local_user_id=$1 where site_id=$2',[owner,siteA]);
 });
 await group('login-intent stores writing challenge; completion returns DB-bound values',async()=>{
  const intent=await call('/login-intents',{handle:'alice',return_site_id:siteB,return_path:'/home/',code_challenge:challenge,writing_protocol:2,writing_challenge:challenge,visit_attempt_id:attempt});
  const row=(await pg.query('select * from private.identity_login_attempts where id=$1',[intent.attempt_id])).rows[0];assert.equal(row.writing_challenge,challenge);assert.equal(row.visit_attempt_id,attempt);
  const {data:a}=await db.rpc('identity_activate_login_attempt',{p_id:row.id,p_member:member,p_site:siteA,p_owner:owner});
  const now=Math.floor(Date.now()/1000),ticket=await signToken({kind:'activation_ticket',jti:a.activation_id,sub:member,site_id:siteA,iat:now,exp:now+60},secret);
  const completed=await call('/sessions/complete',{activation_ticket:ticket,code_verifier:verifier,writing_challenge:'spoof',visit_attempt_id:'spoof'});
  assert.equal(completed.writing_challenge,challenge);assert.equal(completed.visit_attempt_id,attempt);assert.equal(completed.writing_protocol,2);
 });
 await group('central logout blocks renewal and grants but preserves another login',async()=>{
  const second=await login();await call('/sessions/logout',{central_session:session});await renew(family.delegation,siteB,401);
  await call('/writing-grants/check',{site_id:siteB},401,family.grant);
  const p=await call('/writing-proofs/issue',{central_session:second,target_site_id:siteB,return_path:'/home/',code_challenge:challenge,protocol:2,attempt_id:attempt});
  family=await redeem2(p.writing_proof);
 });
 await group('renewal respects central absolute expiry and delegation expiry',async()=>{
  await pg.query("update private.identity_writing_delegations set expires_at=now()-interval '1 second' where delegation_hash=$1",[await sha256(family.delegation)]);await renew(family.delegation,siteB,401);
  await pg.query("update private.identity_writing_delegations set expires_at=now()+interval '1 day' where delegation_hash=$1",[await sha256(family.delegation)]);
  await pg.query("update private.identity_sessions set expires_at=now()+interval '30 seconds' where id=$1",[family.central_session_id]);
  const g=await renew(family.delegation);assert.ok(Date.parse(g.expires_at)<=Date.now()+31000);
  await pg.query("update private.identity_sessions set expires_at=now()-interval '1 second' where id=$1",[family.central_session_id]);await renew(family.delegation,siteB,401);
 });
 await group('private delegation/RPC roles and hash-only persistence',async()=>{
  const rows=(await pg.query('select * from private.identity_writing_delegations')).rows;
  assert.ok(!JSON.stringify(rows).includes(family.delegation));assert.ok(!JSON.stringify(rows).includes(session));
  for(const role of ['anon','authenticated']){await pg.exec('reset role; set role '+role);try{
   await assert.rejects(pg.query('select * from private.identity_writing_delegations'));
   await assert.rejects(pg.query("select private.identity_writing_action('renew','{}')"));
   await assert.rejects(pg.query("select private.identity_create_login_attempt_writing(null,null,null,null,null,null,null)"));
  }finally{await pg.exec('reset role; set role service_role');}}
 });
 await group('input limits, caller identity injection and wrong protocol are rejected',async()=>{
  await call('/writing-delegations/renew',{site_id:siteB,member_id:member},400,family.delegation);
  await call('/writing-delegations/renew',{site_id:siteB},401,'bad');
  await call('/writing-delegations/renew',{site_id:siteB,padding:'x'.repeat(33000)},400,family.delegation);
  await call('/visits/issue',{target_site_id:siteB,writing_protocol:2,attempt_id:attempt,code_challenge:challenge,padding:'x'.repeat(33000)},400);
  const second=await login();const p=await issue(second,{protocol:2,attempt_id:attempt});
  const c=await verifyToken(p.writing_proof,'writing_proof',secret);
  // Even signed test claims cannot bypass the DB-bound original attempt/protocol.
  await redeem2(await signToken({...c,attempt_id:'different'},secret),{attempt_id:'different'},403);
  await redeem2(await signToken({...c,protocol:1},secret),{},403);
 });
 await group('database failure is 503 and never exposes internals',async()=>{
  const failure={rpc:async()=>({error:{message:'secret detail'}})};
  const d=await call('/writing-delegations/renew',{site_id:siteB},503,family.delegation,{supabaseClient:failure});assert.ok(!JSON.stringify(d).includes('secret detail'));
  const proxy={...db,rpc:failure.rpc};const second=await login();
  await call('/visits/issue',{central_session:second,target_site_id:siteB,attempt_id:attempt,code_challenge:challenge,writing_protocol:2},503,undefined,{supabaseClient:proxy});
 });
 console.log(`All ${count} v2 session groups passed (actual API + PGlite SQL; concurrent requests serialized by PGlite).`);
}finally{await pg.close();}
