import { signToken, verifyToken } from '../_shared/tokens.js';
import { validateHandle, validateRelativePath } from '../_shared/validation.js';
import { ApiError, UUID, CHALLENGE, bearer, sha256, randomSecret, siteProposal, verifyOwner, verifyPagesChallenge, challengeUrl, readBody } from '../_shared/auth-proof.js';

export const SECURE_PATHS = new Set(['/login-intents', '/login-context', '/activation-tickets', '/sessions/complete', '/sites', '/sites/verify', '/sites/reverify']);
async function one(db, table, filters) {
  let query = db.from(table).select('*');
  for (const [key, value] of Object.entries(filters)) query = query.eq(key, value);
  const { data, error } = await query.maybeSingle();
  if (error) throw new ApiError(503, '등록 정보를 조회하지 못했습니다.');
  return data;
}
async function rpc(db, name, args) {
  const { data, error } = await db.rpc(name, args);
  if (error) throw new ApiError(error.code === '23505' ? 409 : 503, '인증 상태를 저장하지 못했습니다.');
  if (!data) throw new ApiError(409, '만료·사용 완료 또는 변경된 인증 요청입니다. 다시 시작해 주세요.');
  return data;
}
async function token(value, kind, secret) {
  try { return await verifyToken(value, kind, secret); }
  catch { throw new ApiError(400, '유효하지 않거나 만료된 인증 요청입니다.'); }
}
function activeSite(db, filters) { return one(db, 'identity_sites', { ...filters, status: 'active', verification_status: 'verified' }); }
function requireChallenge(value) {
  if (!CHALLENGE.test(value || '')) throw new ApiError(400, 'S256 code_challenge가 필요합니다.');
}

export async function handleSecureAuth(req, path, { db, secret, fetcher = fetch }) {
  if (!db) throw new ApiError(503, 'Database not available');
  const body = await readBody(req);
  const now = Math.floor(Date.now() / 1000);

  if (path === '/sites' || path === '/sites/reverify') {
    const accessToken = bearer(req);
    let proposal, existingSite = null;
    if (path === '/sites/reverify') {
      if (!UUID.test(body.site_id || '')) throw new ApiError(400, 'site_id가 필요합니다.');
      existingSite = await one(db, 'identity_sites', { id: body.site_id, status: 'active' });
      if (!existingSite) throw new ApiError(404, '사이트를 찾을 수 없습니다.');
      const member = await one(db, 'identity_members', { id: existingSite.member_id, status: 'active' });
      if (!member) throw new ApiError(403, '활성 사용자가 아닙니다.');
      proposal = siteProposal({ ...existingSite, handle: member.handle, display_name: member.display_name, supabase_publishable_key: body.supabase_publishable_key });
    } else { proposal = siteProposal(body); }
    const ownerId = await verifyOwner(proposal, accessToken, fetcher);
    if (existingSite) {
      const binding = await one(db, 'identity_bindings', { site_id: existingSite.id });
      if (binding && (binding.local_user_id !== ownerId || binding.status !== 'active')) throw new ApiError(403, '기존 소유자 연결과 일치하지 않습니다.');
    }
    const id = crypto.randomUUID(), challenge = randomSecret();
    const expiresAt = new Date((now + 86400) * 1000).toISOString();
    // Pending claims do not reserve a handle or modify an existing active site.
    const { error } = await db.from('identity_registrations').insert({
      id, existing_site_id: existingSite?.id || null, proposal, owner_user_id: ownerId,
      challenge_hash: await sha256(challenge), expires_at: expiresAt,
    });
    if (error) throw new ApiError(503, '등록 요청을 저장하지 못했습니다.');
    return { status: 202, body: {
      status: 'pending', registration_id: id, expires_at: expiresAt,
      verification_url: challengeUrl(proposal, id), verification_file: { registration_id: id, challenge },
    } };
  }

  if (path === '/sites/verify') {
    const accessToken = bearer(req);
    if (!UUID.test(body.registration_id || '')) throw new ApiError(400, 'registration_id가 필요합니다.');
    const registration = await one(db, 'identity_registrations', { id: body.registration_id });
    if (!registration || registration.consumed_at || Date.parse(registration.expires_at) <= Date.now()) throw new ApiError(409, '만료되었거나 사용 완료된 등록 요청입니다.');
    const ownerId = await verifyOwner(registration.proposal, accessToken, fetcher);
    if (ownerId !== registration.owner_user_id) throw new ApiError(403, '등록 요청의 소유자와 다릅니다.');
    await verifyPagesChallenge(registration, fetcher);
    return { status: 200, body: await rpc(db, 'identity_verify_registration', { p_registration_id: registration.id, p_owner: ownerId }) };
  }

  if (path === '/login-intents') {
    requireChallenge(body.code_challenge);
    if (!UUID.test(body.return_site_id || '') || (body.member_id && !UUID.test(body.member_id)) || (body.site_id && !UUID.test(body.site_id))) {
      throw new ApiError(400, '유효한 사이트/사용자 ID가 필요합니다.');
    }
    let member;
    if (body.member_id) member = await one(db, 'identity_members', { id: body.member_id, status: 'active' });
    else if (body.site_id) {
      const site = await activeSite(db, { id: body.site_id });
      if (site) member = await one(db, 'identity_members', { id: site.member_id, status: 'active' });
    } else {
      let handle;
      try { handle = validateHandle(body.handle); } catch { throw new ApiError(400, '유효한 ID가 필요합니다.'); }
      member = await one(db, 'identity_members', { handle, status: 'active' });
    }
    if (!member) throw new ApiError(404, '활성 사용자를 찾을 수 없습니다.');
    const site = await activeSite(db, { member_id: member.id });
    const returnSite = await activeSite(db, { id: body.return_site_id });
    if (!site || !returnSite) throw new ApiError(400, '소유권 확인이 완료된 활성 사이트가 필요합니다.');
    let returnPath;
    try { returnPath = validateRelativePath(body.return_path || '', returnSite.base_path); }
    catch { throw new ApiError(400, '복귀 경로가 올바르지 않습니다.'); }
    const attempt = await rpc(db, 'identity_create_login_attempt', {
      p_member: member.id, p_site: site.id, p_return_site: returnSite.id,
      p_return_path: returnPath, p_challenge: body.code_challenge,
    });
    const intent = await signToken({ kind: 'login_intent', jti: attempt.id, sub: member.id, site_id: site.id,
      return_site_id: returnSite.id, return_path: returnPath, iat: now, exp: Math.floor(Date.parse(attempt.intent_expires_at) / 1000) }, secret);
    const redirect = new URL(site.login_url); redirect.searchParams.set('login_intent', intent);
    return { status: 200, body: { login_intent: intent, login_url: site.login_url, redirect_url: redirect.href,
      attempt_id: attempt.id, expires_at: attempt.intent_expires_at, handle: member.handle,
      return_url: new URL(returnPath, returnSite.origin).href } };
  }

  if (path === '/login-context') {
    const intent = await token(body.login_intent, 'login_intent', secret);
    if (!UUID.test(intent.jti || '') || body.site_id !== intent.site_id) throw new ApiError(403, '로그인 대상 사이트가 일치하지 않습니다.');
    const attempt = await one(db, 'identity_login_attempts', { id: intent.jti, member_id: intent.sub, site_id: intent.site_id });
    if (!attempt || attempt.activated_at || Date.parse(attempt.intent_expires_at) <= Date.now()) throw new ApiError(409, '만료되었거나 이미 사용한 로그인 요청입니다. 다시 시작해 주세요.');
    const member = await one(db, 'identity_members', { id: intent.sub, status: 'active' });
    const site = await activeSite(db, { id: intent.site_id, member_id: intent.sub });
    const returnSite = await activeSite(db, { id: attempt.return_site_id });
    const binding = await one(db, 'identity_bindings', { site_id: intent.site_id, member_id: intent.sub, status: 'active' });
    if (!member || !site || !returnSite || !binding || binding.local_user_id !== attempt.owner_user_id || member.session_version !== attempt.session_version) throw new ApiError(403, '로그인 요청의 계정 상태가 변경되었습니다.');
    return { status: 200, body: { attempt_id: attempt.id, handle: member.handle, site_id: site.id,
      expires_at: attempt.intent_expires_at, return_site_id: returnSite.id, return_path: attempt.return_path } };
  }

  if (path === '/activation-tickets') {
    const accessToken = bearer(req);
    const intent = await token(body.login_intent, 'login_intent', secret);
    if (!UUID.test(intent.jti || '') || body.site_id !== intent.site_id) throw new ApiError(403, '로그인 대상 사이트가 일치하지 않습니다.');
    const site = await activeSite(db, { id: intent.site_id, member_id: intent.sub });
    if (!site) throw new ApiError(403, '검증된 사이트가 아닙니다.');
    const ownerId = await verifyOwner(site, accessToken, fetcher);
    const binding = await one(db, 'identity_bindings', { site_id: site.id, member_id: intent.sub, status: 'active' });
    if (!binding || binding.local_user_id !== ownerId || (body.local_user_id && body.local_user_id !== ownerId)) throw new ApiError(403, '등록된 소유자 계정과 일치하지 않습니다.');
    const attempt = await rpc(db, 'identity_activate_login_attempt', { p_id: intent.jti, p_member: intent.sub, p_site: site.id, p_owner: ownerId });
    const ticket = await signToken({ kind: 'activation_ticket', jti: attempt.activation_id, sub: intent.sub, site_id: site.id,
      iat: now, exp: Math.floor(Date.parse(attempt.activation_expires_at) / 1000) }, secret);
    return { status: 200, body: { activation_ticket: ticket, attempt_id: attempt.id } };
  }

  if (path === '/sessions/complete') {
    const ticket = await token(body.activation_ticket || body.ticket, 'activation_ticket', secret);
    if (!UUID.test(ticket.jti || '') || typeof body.code_verifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(body.code_verifier)) throw new ApiError(400, '로그인을 시작한 브라우저의 code_verifier가 필요합니다.');
    const attempt = await rpc(db, 'identity_complete_login_attempt', {
      p_activation_id: ticket.jti, p_member: ticket.sub, p_site: ticket.site_id, p_challenge: await sha256(body.code_verifier),
    });
    const centralSession = await signToken({ kind: 'central_session', sub: attempt.member_id, session_version: attempt.session_version,
      central_session_id: attempt.central_session_id,
      iat: now, exp: Math.floor(Date.parse(attempt.session_expires_at) / 1000) }, secret);
    return { status: 200, body: {
      central_session: centralSession, session_key: 'minihompy.identity.session.v1',
      user: { id: attempt.member_id, handle: attempt.handle, display_name: attempt.display_name },
      return_site_id: attempt.return_site_id, return_path: attempt.return_path,
      return_url: new URL(attempt.return_path, attempt.return_origin).href,
    } };
  }
  throw new ApiError(404, 'Not Found');
}
