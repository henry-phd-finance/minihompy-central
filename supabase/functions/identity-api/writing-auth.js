import { ApiError, UUID, CHALLENGE, sha256, randomSecret, readBody } from '../_shared/auth-proof.js';
import { signToken, verifyToken } from '../_shared/tokens.js';
import { validateRelativePath } from '../_shared/validation.js';
export const WRITING_PATHS = new Set(['/writing-proofs/issue','/writing-proofs/redeem','/writing-grants/check','/writing-grants/revoke','/sessions/logout','/writing-delegations/renew','/writing-delegations/revoke']);
const statuses = { AUTH_REQUIRED:401, SESSION_EXPIRED:401, SESSION_REVOKED:401, FORBIDDEN:403, TARGET_MISMATCH:403, PROOF_USED:409, BAD_REQUEST:400, RATE_LIMITED:429 };
function fail(code) { const error = new ApiError(statuses[code] || 503, '회원 작성 인증을 확인하지 못했습니다.'); error.code=code; throw error; }
export async function writingAction(db, action, args) {
  if (!db) fail('IDENTITY_UNAVAILABLE');
  let result;
  try { result=await db.rpc('identity_writing_action',{p_action:action,p_args:args}); } catch { fail('IDENTITY_UNAVAILABLE'); }
  if(result.error || !result.data) fail('IDENTITY_UNAVAILABLE');
  if(result.data.failure) fail(result.data.failure);
  return result.data;
}
export async function writingSessionActive(db, claims, strict=false) {
  if (!claims.central_session_id) return true; // Legacy visitor-only sessions.
  if (!UUID.test(claims.central_session_id)) return false;
  try { return (await writingAction(db,'session',{session_id:claims.central_session_id,member_id:claims.sub,session_version:claims.session_version})).active===true; }
  catch (e) { if(strict && e.status===503) throw e; return false; }
}
async function claims(value, kind, secret) {
  let c;
  try { c=await verifyToken(value,kind,secret); } catch { fail('AUTH_REQUIRED'); }
  const now=Math.floor(Date.now()/1000);
  if(!Number.isInteger(c.exp)||!Number.isInteger(c.iat)||c.exp<=now||c.iat>now||c.exp<=c.iat) fail('SESSION_EXPIRED');
  if(!UUID.test(c.sub||'')||!UUID.test(c.central_session_id||'')||!Number.isInteger(c.session_version)||c.session_version<1) fail('AUTH_REQUIRED');
  return c;
}
function grant(req) {
  const match=/^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.get('Authorization')||'');
  if(!match) fail('AUTH_REQUIRED'); return match[1];
}
function cleanProfile(result) {
  try {
    const u=new URL(result.member.homepage_url);
    if(u.protocol!=='https:'||u.username||u.password||u.origin!==result.home_origin||u.hash) throw Error();
    validateRelativePath(u.pathname+u.search,result.home_base_path);
  } catch { fail('IDENTITY_UNAVAILABLE'); }
  const {home_origin,home_base_path,...safe}=result; return safe;
}
export async function handleWritingAuth(req,path,{db,secret}) {
  if(req.method!=='POST') return {status:405,body:{error:{code:'METHOD_NOT_ALLOWED',message:'POST 요청이 필요합니다.'}}};
  const body=await readBody(req);
  if(!body || typeof body!=='object'||Array.isArray(body)) fail('BAD_REQUEST');
  if(path.startsWith('/writing-delegations/')) {
    if(Object.keys(body).some(k=>k!=='site_id') || (path.endsWith('/renew')&&!UUID.test(body.site_id||''))) fail('BAD_REQUEST');
    const delegation_hash=await sha256(grant(req));
    if(path.endsWith('/revoke')) return {status:200,body:await writingAction(db,'revoke_delegation',{delegation_hash})};
    const rawGrant=randomSecret();
    const result=await writingAction(db,'renew',{delegation_hash,site_id:body.site_id,grant_hash:await sha256(rawGrant)});
    return {status:200,body:{...cleanProfile(result),grant:rawGrant}};
  }
  if(path==='/writing-grants/revoke') {
    return {status:200,body:await writingAction(db,'revoke',{grant_hash:await sha256(grant(req))})};
  }
  if(path==='/writing-grants/check') {
    if(!UUID.test(body.site_id||'')) fail('BAD_REQUEST');
    return {status:200,body:cleanProfile(await writingAction(db,'check',{grant_hash:await sha256(grant(req)),site_id:body.site_id}))};
  }
  if(path==='/sessions/logout') {
    const c=await claims(body.central_session,'central_session',secret);
    return {status:200,body:await writingAction(db,'logout',{session_id:c.central_session_id,member_id:c.sub,session_version:c.session_version})};
  }
  if(path==='/writing-proofs/issue') {
    const c=await claims(body.central_session,'central_session',secret);
    const protocol=body.protocol===undefined?1:body.protocol;
    if(![1,2].includes(protocol) || (protocol===2 && (typeof body.attempt_id!=='string'||!body.attempt_id||body.attempt_id.length>128||/[\u0000-\u001f\u007f]/.test(body.attempt_id)))) fail('BAD_REQUEST');
    if(!UUID.test(body.target_site_id||'')||!CHALLENGE.test(body.code_challenge||'')) fail('BAD_REQUEST');
    const {data:site,error}=await db.from('identity_sites').select('base_path,origin').eq('id',body.target_site_id).maybeSingle();
    if(error) fail('IDENTITY_UNAVAILABLE'); if(!site) fail('TARGET_MISMATCH');
    let returnPath;
    try { returnPath=validateRelativePath(body.return_path||'',site.base_path); } catch { fail('BAD_REQUEST'); }
    const p=await writingAction(db,'issue',{session_id:c.central_session_id,member_id:c.sub,session_version:c.session_version,site_id:body.target_site_id,code_challenge:body.code_challenge,return_path:returnPath,protocol,...(protocol===2?{attempt_id:body.attempt_id}:{})});
    const now=Math.floor(Date.now()/1000), exp=Math.floor(Date.parse(p.expires_at)/1000);
    const proof=await signToken({kind:'writing_proof',jti:p.id,sub:c.sub,central_session_id:c.central_session_id,session_version:c.session_version,aud:body.target_site_id,code_challenge:body.code_challenge,iat:now,exp,...(protocol===2?{protocol:2,attempt_id:body.attempt_id}:{})},secret);
    return {status:200,body:{writing_proof:proof,expires_at:new Date(exp*1000).toISOString(),return_path:returnPath,return_url:new URL(returnPath,site.origin).href}};
  }
  const c=await claims(body.writing_proof,'writing_proof',secret);
  if(!UUID.test(c.jti||'')||!UUID.test(body.site_id||'')||typeof body.code_verifier!=='string'||!/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier)||c.exp-c.iat>60) fail('BAD_REQUEST');
  if(c.aud!==body.site_id) fail('TARGET_MISMATCH');
  const challenge=await sha256(body.code_verifier);
  if(challenge!==c.code_challenge) fail('FORBIDDEN');
  const protocol=c.protocol===undefined?1:c.protocol;
  if(![1,2].includes(protocol) || (protocol===2 && (body.protocol!==2||!c.attempt_id||body.attempt_id!==c.attempt_id)) || (protocol===1&&body.protocol===2)) fail('FORBIDDEN');
  const rawGrant=randomSecret(), delegation=protocol===2?randomSecret():null;
  const result=await writingAction(db,'redeem',{proof_id:c.jti,session_id:c.central_session_id,member_id:c.sub,session_version:c.session_version,site_id:body.site_id,code_challenge:challenge,grant_hash:await sha256(rawGrant),protocol,...(protocol===2?{attempt_id:c.attempt_id,delegation_hash:await sha256(delegation)}:{})});
  return {status:200,body:{...cleanProfile(result),grant:rawGrant,...(delegation?{delegation}:{})}};
}
