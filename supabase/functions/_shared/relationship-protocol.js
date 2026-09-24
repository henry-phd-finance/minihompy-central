// Shared wire contract; byte-identical copy lives in personal member-writing/relationship-protocol.js.
export const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const STATUS={BAD_REQUEST:400,AUTH_REQUIRED:401,SESSION_EXPIRED:401,SESSION_REVOKED:401,FORBIDDEN:403,TARGET_MISMATCH:403,NOT_FRIENDS:403,NOT_FOUND:404,REVISION_CONFLICT:409,REQUEST_CONFLICT:409,PERMIT_EXPIRED:409,RATE_LIMITED:429,IDENTITY_UNAVAILABLE:503,NOT_CONFIGURED:503,METHOD_NOT_ALLOWED:405};
export const fail=code=>{throw Object.assign(Error('관계 정보를 확인하지 못했습니다.'),{code,status:STATUS[code]||503});};
export function errorReply(e){const code=Object.hasOwn(STATUS,e?.code)?e.code:'IDENTITY_UNAVAILABLE';return {status:STATUS[code],body:{error:{code,message:'관계 정보를 확인하지 못했습니다. 다시 시도해 주세요.'}},headers:code==='RATE_LIMITED'?{'Retry-After':String(Math.max(1,Math.min(60,Math.floor(e.retryAfter)||1)))}:{}};}
export async function json(input,max=8192,error='BAD_REQUEST'){
 try{const reader=input.body?.getReader();if(!reader)fail(error);const parts=[];let n=0;
  try{for(;;){const r=await reader.read();if(r.done)break;n+=r.value.length;if(n>max)fail(error);parts.push(r.value);}}finally{await reader.cancel().catch(()=>{});}
  const bytes=new Uint8Array(n);let at=0;for(const p of parts){bytes.set(p,at);at+=p.length;}
  const d=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));if(!d||Array.isArray(d)||typeof d!=='object')fail(error);return d;
 }catch{fail(error);}
}
const keys={state:['target_member_id'],requests:['direction','limit','cursor'],actions:['action','target_member_id','operation_id','expected_revision','request_id'],operations:['operation_id'],'review-permits':['operation_id','body_sha256'],friends:['member_id','limit','cursor']};
export function input(action,body,central=false){
 const allowed=keys[action];if(!allowed||!body||Array.isArray(body)||typeof body!=='object')fail('BAD_REQUEST');
 for(const [k,v] of Object.entries(body))if(!allowed.includes(k)&&!(central&&action!=='friends'&&k==='site_id')||v===null)fail('BAD_REQUEST');
 const result={...body};
 for(const k of ['member_id','target_member_id','operation_id','request_id','site_id'])if(k in result){if(typeof result[k]!=='string'||!UUID.test(result[k]))fail('BAD_REQUEST');result[k]=result[k].toLowerCase();}
 for(const k of action==='friends'?['member_id']:action==='state'?['target_member_id']:action==='actions'?['action','target_member_id','operation_id','expected_revision']:action==='requests'?['direction']:['operation_id'])if(!(k in result))fail('BAD_REQUEST');
 if(central&&action!=='friends'&&!result.site_id)fail('BAD_REQUEST');
 if('limit' in result&&(!Number.isInteger(result.limit)||result.limit<1||result.limit>50))fail('BAD_REQUEST');
 if(action==='requests'&&!['incoming','outgoing'].includes(result.direction))fail('BAD_REQUEST');
 if(action==='actions'){
  if(!['request','accept','reject','cancel','disconnect'].includes(result.action)||!Number.isSafeInteger(result.expected_revision)||result.expected_revision<0)fail('BAD_REQUEST');
  if(result.action==='request'?'request_id' in result:!result.request_id)fail('BAD_REQUEST');
 }
 if(action==='review-permits'&&(typeof result.body_sha256!=='string'||!/^[0-9a-f]{64}$/.test(result.body_sha256)))fail('BAD_REQUEST');
 if('cursor' in result&&(typeof result.cursor!=='string'||result.cursor.length>512||!result.cursor.length))fail('BAD_REQUEST');
 return result;
}
export function decodeCursor(value){try{if(!/^[A-Za-z0-9_-]+$/.test(value))fail('BAD_REQUEST');const b=atob(value.replace(/-/g,'+').replace(/_/g,'/'));const c=JSON.parse(b);cursor(c);if(encodeCursor(c)!==value)fail('BAD_REQUEST');return c;}catch{fail('BAD_REQUEST');}}
export function encodeCursor(c){cursor(c);return btoa(JSON.stringify(c)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function cursor(c){if(!c||Array.isArray(c)||c.v!==1||!['friends','incoming','outgoing'].includes(c.kind)||!UUID.test(c.member_id||'')||!UUID.test(c.after||'')||Object.keys(c).sort().join()!=='after,kind,member_id,v')fail('IDENTITY_UNAVAILABLE');}
function profile(p){
 if(!p||!UUID.test(p.member_id||''))fail('IDENTITY_UNAVAILABLE');
 if(p.unavailable===true)return {member_id:p.member_id,unavailable:true};
 if(typeof p.handle!=='string'||!/^[a-z0-9._-]{2,30}$/.test(p.handle)||typeof p.display_name!=='string'||!p.display_name.trim()||[...p.display_name].length>50||/[\u0000-\u001f\u007f]/.test(p.display_name))fail('IDENTITY_UNAVAILABLE');
 let destination=null;if(p.destination!==null){try{const d=p.destination,u=new URL(d.homepage_url);if(!UUID.test(d.site_id)||u.protocol!=='https:'||u.username||u.password||u.hash||d.homepage_url.length>2048)throw Error();destination={site_id:d.site_id,homepage_url:u.href};}catch{fail('IDENTITY_UNAVAILABLE');}}
 return {member_id:p.member_id,handle:p.handle,display_name:p.display_name,destination};
}
function state(s){if(!s||!['self','none','outgoing','incoming','accepted'].includes(s.state)||!Number.isSafeInteger(s.revision)||s.revision<0||(s.request_id!==null&&!UUID.test(s.request_id||'')))fail('IDENTITY_UNAVAILABLE');return {state:s.state,revision:s.revision,request_id:s.request_id,target:profile(s.target)};}
export function output(action,d,{wireCursor=false}={}){
 if(action==='state')return state(d);
 if(['friends','requests'].includes(action)){
  if(!Array.isArray(d?.items)||d.items.length>50||!('next_cursor' in d))fail('IDENTITY_UNAVAILABLE');
  const items=d.items.map(p=>{if(action==='friends'){const v=profile(p);if(v.unavailable)fail('IDENTITY_UNAVAILABLE');return v;}if(!['incoming','outgoing'].includes(p.state)||!UUID.test(p.request_id||'')||!Number.isSafeInteger(p.revision)||p.revision<1)fail('IDENTITY_UNAVAILABLE');return {state:p.state,revision:p.revision,request_id:p.request_id,target:profile(p.target)};});
  let next_cursor=null;if(d.next_cursor!==null){if(wireCursor){if(typeof d.next_cursor!=='string'||d.next_cursor.length>512)fail('IDENTITY_UNAVAILABLE');try{decodeCursor(d.next_cursor);}catch{fail('IDENTITY_UNAVAILABLE');}next_cursor=d.next_cursor;}else next_cursor=encodeCursor(d.next_cursor);}
  return {items,next_cursor};
 }
 if(['actions','operations'].includes(action)){
  const o=d?.operation_result;if(!o||!UUID.test(o.operation_id||'')||!['request','accept','reject','cancel','disconnect'].includes(o.action))fail('IDENTITY_UNAVAILABLE');
  return {operation_result:{action:o.action,operation_id:o.operation_id,relationship:state(o.relationship)},relationship:state(d.relationship)};
 }
 if(action==='review-permits'){
  const r={};for(const k of ['permit_id','actor_member_id','site_id','owner_member_id','central_session_id','operation_id']){if(!UUID.test(d?.[k]||''))fail('IDENTITY_UNAVAILABLE');r[k]=d[k];}
  if(!/^[0-9a-f]{64}$/.test(d.body_sha256||'')||!Number.isSafeInteger(d.relationship_revision)||d.relationship_revision<1)fail('IDENTITY_UNAVAILABLE');
  for(const k of ['authorized_at','expires_at']){if(typeof d[k]!=='string'||!Number.isFinite(Date.parse(d[k])))fail('IDENTITY_UNAVAILABLE');r[k]=d[k];}
  const duration=Date.parse(r.expires_at)-Date.parse(r.authorized_at);if(duration<=0||duration>30000)fail('IDENTITY_UNAVAILABLE');
  return {...r,body_sha256:d.body_sha256,relationship_revision:d.relationship_revision};
 }
 fail('IDENTITY_UNAVAILABLE');
}
