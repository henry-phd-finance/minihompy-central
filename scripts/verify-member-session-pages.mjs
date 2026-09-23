import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const sources=Object.fromEntries(await Promise.all(['login','complete','visit-flow'].map(async k=>[k,await readFile(new URL('../public/'+k+'.js',import.meta.url),'utf8')])));
const challenge='c'.repeat(43),attempt='visit-id';
const flush=()=>new Promise(setImmediate);
function fixture(action='visit'){
 const calls=[],values=new Map(),els=new Map();let pending=null;
 const el=k=>{if(!els.has(k))els.set(k,{hidden:false,value:'alice',addEventListener(e,fn){this[e]=fn;}});return els.get(k);};
 const flow={pendingKey:'pending',sessionKey:'central',random:()=> 'v'.repeat(43),challenge:async()=> 'k'.repeat(43),storage:()=>({}),read:()=>pending,save:(s,k,v)=>{if(k==='pending')pending=v;},remove:(s,k)=>{if(k==='pending')pending=null;},page:(base,path,args)=>new URL(base+'/'+path+'?'+new URLSearchParams(args)),post:async(base,path,body)=>{
  calls.push({path,body});
  if(path==='login-intents')return {attempt_id:'login-id',redirect_url:'https://owner.test/login',return_url:'https://b.test/home/'};
  if(path==='sessions/complete')return {central_session:'central-only',return_site_id:'B',return_path:'/home/',writing_protocol:2,writing_challenge:challenge,visit_attempt_id:attempt};
  return {return_url:'https://b.test/home/#vt=fixture&wp=proof'};
 }};
 const ctx={window:{MinihompyLoginFlow:flow,MINIHOMPY_CENTRAL_CONFIG:{apiBaseUrl:'https://api.test',pageBaseUrl:'https://central.test'}},URLSearchParams,
  location:{pathname:'/complete.html',hash:'#ticket=activation&attempt_id=login-id',search:'?site_id=B&return_path=%2Fhome%2F&attempt_id='+attempt+'&writing_protocol=2&code_challenge='+challenge,assign(url){this.destination=url;},replace(url){this.destination=url;}},history:{length:1,replaceState(){}},Date,
  localStorage:{getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)},document:{body:{dataset:{action}},querySelector:el}};
 return {ctx,flow,calls,el,values,setPending:p=>{pending=p;},getPending:()=>pending};
}
{
 const f=fixture();vm.runInNewContext(sources.login,f.ctx);await f.el('#login-form').submit({preventDefault(){}});
 const b=f.calls[0].body;assert.equal(b.writing_protocol,2);assert.equal(b.writing_challenge,challenge);assert.equal(b.visit_attempt_id,attempt);assert.notEqual(b.code_challenge,challenge);
 assert.equal(f.getPending().writingChallenge,challenge);
 console.log('PASS: login forwards separate login/writing PKCE and visit attempt');
}
{
 const f=fixture();f.setPending({verifier:'fixture',siteId:'B',attemptId:'login-id',visitAttemptId:'spoof',deadline:Date.now()+10000});
 await vm.runInNewContext(sources.complete,f.ctx);
 const url=new URL(f.ctx.location.destination);assert.equal(url.searchParams.get('code_challenge'),challenge);assert.equal(url.searchParams.get('attempt_id'),attempt);assert.equal(url.searchParams.get('writing_protocol'),'2');assert.ok(!url.href.includes('central-only'));
 console.log('PASS: completion forwards DB-bound challenge/attempt without central token');
}
for(const action of ['visit','logout']){
 const f=fixture(action);f.values.set('central','central-only');vm.runInNewContext(sources['visit-flow'],f.ctx);await flush();
 const b=f.calls.find(c=>c.path==='visits/issue').body;
 if(action==='visit'){assert.equal(b.writing_protocol,2);assert.equal(b.code_challenge,challenge);}
 else{assert.equal(b.writing_protocol,undefined);assert.equal(b.central_session,null);}
 console.log('PASS: '+action+' forwards or suppresses writing request correctly');
}
