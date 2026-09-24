import {sha256} from '../_shared/auth-proof.js';
import {UUID,json,fail,errorReply} from '../_shared/relationship-protocol.js';

// Supabase builders support abortSignal; the race also bounds injected transports.
async function rpc(db,name,args) {
 const controller=new AbortController();let timer;
 try {
  let query=db?.rpc(name,args);
  if(query?.abortSignal)query=query.abortSignal(controller.signal);
  return await Promise.race([query,new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error('Read context timeout'));},5000);})]);
 } finally {clearTimeout(timer);}
}
export async function readContextReady(db) {
 try {const r=await rpc(db,'identity_read_context_ready',{});return !r?.error&&r?.data===1;} catch {return false;}
}
function output(d,args) {
 if(!d||d.protocol!==1)fail('IDENTITY_UNAVAILABLE');
 const result={protocol:1};
 for(const key of ['request_id','actor_member_id','site_id','owner_member_id','central_session_id']) {
  if(typeof d[key]!=='string'||!UUID.test(d[key]))fail('IDENTITY_UNAVAILABLE');result[key]=d[key];
 }
 if(d.request_id!==args.request_id||d.site_id!==args.site_id||d.request_hash!==args.request_hash)fail('IDENTITY_UNAVAILABLE');
 if(!['none','pending','accepted','self'].includes(d.relationship)||!Number.isSafeInteger(d.relationship_revision)||d.relationship_revision<0
  ||typeof d.can_read_friends!=='boolean'||d.can_read_friends!==(d.relationship==='accepted')
  ||(d.relationship==='self')!==(d.actor_member_id===d.owner_member_id))fail('IDENTITY_UNAVAILABLE');
 for(const key of ['authorized_at','expires_at']) {
  if(typeof d[key]!=='string'||!Number.isFinite(Date.parse(d[key])))fail('IDENTITY_UNAVAILABLE');result[key]=d[key];
 }
 const duration=Date.parse(d.expires_at)-Date.parse(d.authorized_at);
 if(duration<=0||duration>5000||Date.parse(d.expires_at)<=Date.now()||Date.parse(d.authorized_at)>Date.now()+1000)fail('IDENTITY_UNAVAILABLE');
 return {...result,request_hash:d.request_hash,relationship:d.relationship,relationship_revision:d.relationship_revision,can_read_friends:d.can_read_friends};
}
export async function handleReadContext(req,{db}={}) {
 const headers={'Cache-Control':'private, no-store','Vary':'Origin, Authorization, X-Minihompy-Auth-Mode'};
 try {
  // This is a server grant exchange, never a browser credential endpoint.
  if(req.headers.has('Origin'))fail('FORBIDDEN');
  if(req.method!=='POST')fail('METHOD_NOT_ALLOWED');
  if(new URL(req.url).search||req.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()!=='application/json')fail('BAD_REQUEST');
  const body=await json(req);
  if(Object.keys(body).sort().join()!=='request_hash,request_id,site_id')fail('BAD_REQUEST');
  for(const key of ['site_id','request_id']){if(typeof body[key]!=='string'||!UUID.test(body[key]))fail('BAD_REQUEST');body[key]=body[key].toLowerCase();}
  if(typeof body.request_hash!=='string'||!/^[0-9a-f]{64}$/.test(body.request_hash))fail('BAD_REQUEST');
  const bearer=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.get('Authorization')||'');if(!bearer)fail('AUTH_REQUIRED');
  const args={...body,grant_hash:await sha256(bearer[1])};
  const r=await rpc(db,'identity_read_context',{p_args:args});if(r?.error||!r?.data)fail('IDENTITY_UNAVAILABLE');
  if(r.data.failure){try{fail(r.data.failure);}catch(e){e.retryAfter=r.data.retry_after;throw e;}}
  return {status:200,body:output(r.data,args),headers};
 } catch(e) {const r=errorReply(e);return {...r,headers:{...headers,...r.headers}};}
}
