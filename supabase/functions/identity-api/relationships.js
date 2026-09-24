import {sha256} from '../_shared/auth-proof.js';
import {input,output,json,decodeCursor,fail,errorReply} from '../_shared/relationship-protocol.js';
export async function relationshipReady(db){try{const r=await db?.rpc('identity_relationship_action',{p_action:'state',p_args:{}});return !r?.error&&r?.data?.failure==='BAD_REQUEST';}catch{return false;}}
export async function handleRelationships(req,path,{db,transportPeerIp}={}){
 try{
  const action=path.slice('/relationships/'.length),url=new URL(req.url);let args;
  if(!['friends','state','requests','actions','operations','review-permits'].includes(action))fail('NOT_FOUND');
  if(req.method!==(action==='friends'?'GET':'POST'))fail('METHOD_NOT_ALLOWED');
  if(action==='friends'){
   const q={};for(const [k,v] of url.searchParams){if(k in q)fail('BAD_REQUEST');q[k]=v;}
   if('limit' in q){if(!/^[0-9]+$/.test(q.limit))fail('BAD_REQUEST');q.limit=Number(q.limit);}args=input(action,q,true);
   // Only the server entrypoint supplies this socket address. Never trust forwarded request headers.
   if(typeof transportPeerIp!=='string'||!transportPeerIp||transportPeerIp.length>128)fail('NOT_CONFIGURED');
   const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(transportPeerIp));args.ip_hash=[...new Uint8Array(bytes)].map(v=>v.toString(16).padStart(2,'0')).join('');
  }else{
   if(url.search||req.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()!=='application/json')fail('BAD_REQUEST');
   args=input(action,await json(req),true);const bearer=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.get('Authorization')||'');if(!bearer)fail('AUTH_REQUIRED');args.grant_hash=await sha256(bearer[1]);
  }
  if(args.cursor)args.cursor=decodeCursor(args.cursor);
  const r=await db?.rpc('identity_relationship_action',{p_action:action,p_args:args});if(r?.error||!r?.data)fail('IDENTITY_UNAVAILABLE');
  if(r.data.failure){try{fail(r.data.failure);}catch(e){e.retryAfter=r.data.retry_after;throw e;}}
  return {status:200,body:{...output(action,r.data),...(action==='review-permits'?{server_time:new Date().toISOString()}:{})},headers:{}};
 }catch(e){return errorReply(e);}
}
