import { base64UrlEncode } from './tokens.js';
import { validateHandle, validateDisplayName, validateOrigin, validateRelativePath } from './validation.js';

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
export async function sha256(value) {
  return base64UrlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}
export function randomSecret() { return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32))); }
export function bearer(req) {
  const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(req.headers.get('Authorization') || '');
  if (!match || match[1].length > 16384) throw new ApiError(401, '개인 Supabase access token이 필요합니다.');
  return match[1];
}
export function projectOrigin(ref) {
  if (typeof ref !== 'string' || !/^[a-z]{20}$/.test(ref)) throw new ApiError(400, '유효한 Supabase project ref가 필요합니다.');
  return `https://${ref}.supabase.co`;
}
export function publicKey(key, ref) {
  if (typeof key !== 'string' || key.length > 4096) throw new ApiError(400, '공개 Supabase API 키가 필요합니다.');
  if (/^sb_publishable_[A-Za-z0-9_-]{10,}$/.test(key)) return key;
  try {
    const parts = key.split('.');
    const claims = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (parts.length === 3 && claims.role === 'anon' && claims.ref === ref) return key;
  } catch { /* Never echo credentials. */ }
  throw new ApiError(400, 'publishable 또는 해당 프로젝트의 anon 키만 허용됩니다.');
}

// Fixed public hosting boundary. Custom domains require a separate SSRF-safe verifier.
export function siteProposal(body) {
  try {
    const origin = validateOrigin(body.origin);
    const host = new URL(origin).hostname;
    if (!/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\.github\.io$/.test(host) || new URL(origin).port) {
      throw new Error('현재 등록은 개인 GitHub Pages 도메인만 지원합니다.');
    }
    const base = body.base_path;
    if (typeof base !== 'string' || !/^\/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*\/)*$/.test(base)) throw new Error('base_path 형식이 잘못되었습니다.');
    const urls = {};
    for (const field of ['homepage_url', 'login_url']) {
      const url = new URL(body[field]);
      if (url.origin !== origin || url.username || url.password || url.hash || url.href.length > 2048) throw new Error('사이트 URL의 origin이 일치해야 합니다.');
      validateRelativePath(url.pathname + url.search, base);
      urls[field] = url.href;
    }
    projectOrigin(body.supabase_project_ref);
    return {
      handle: validateHandle(body.handle), display_name: validateDisplayName(body.display_name),
      origin, base_path: base, ...urls, supabase_project_ref: body.supabase_project_ref,
      supabase_publishable_key: publicKey(body.supabase_publishable_key, body.supabase_project_ref),
    };
  } catch (error) { throw new ApiError(400, error.message); }
}

async function limitedJson(response, limit = 65536) {
  if (!response.body) throw new Error('empty');
  const reader = response.body.getReader();
  let length = 0; const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > limit) throw new Error('oversize');
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder().decode(bytes));
  } finally { await reader.cancel().catch(() => {}); }
}
export async function readBody(req) {
  try { const value = await limitedJson(req, 32768); if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(); return value; }
  catch { throw new ApiError(400, '유효한 JSON 객체가 필요합니다.'); }
}
async function fetchJson(url, init, fetcher, failureStatus, message) {
  try {
    const response = await fetcher(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error();
    return await limitedJson(response);
  } catch { throw new ApiError(failureStatus, message); }
}

// GET /auth/v1/user is the Auth server validation used by supabase.auth.getUser(jwt).
// The target comes from the registered project, never from the token's untrusted issuer.
export async function verifyOwner(site, token, fetcher = fetch) {
  const origin = projectOrigin(site.supabase_project_ref);
  const headers = { apikey: publicKey(site.supabase_publishable_key, site.supabase_project_ref), Authorization: `Bearer ${token}` };
  const user = await fetchJson(`${origin}/auth/v1/user`, { headers }, fetcher, 401, '개인 Supabase 인증을 확인하지 못했습니다.');
  if (!UUID.test(user?.id || '') || user.is_anonymous !== false || user.role !== 'authenticated') {
    throw new ApiError(403, '영구 사용자 계정으로 로그인해야 합니다.');
  }
  const admin = await fetchJson(`${origin}/rest/v1/rpc/is_minihompy_admin`, {
    method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: '{}',
  }, fetcher, 403, '개인 미니홈피 소유자 권한을 확인하지 못했습니다.');
  if (admin !== true) throw new ApiError(403, '개인 미니홈피 소유자 계정이 아닙니다.');
  return user.id;
}
export function challengeUrl(proposal, registrationId) {
  return `${proposal.origin}${proposal.base_path}minihompy-identity/${registrationId}.json`;
}
export async function verifyPagesChallenge(registration, fetcher = fetch) {
  // Revalidate persisted metadata before any outbound request.
  const proposal = siteProposal(registration.proposal);
  const proof = await fetchJson(challengeUrl(proposal, registration.id), { cache: 'no-store' }, fetcher, 403, 'GitHub Pages 소유권 파일을 확인하지 못했습니다.');
  if (proof?.registration_id !== registration.id || !CHALLENGE.test(proof?.challenge || '') ||
      await sha256(proof.challenge) !== registration.challenge_hash) throw new ApiError(403, '사이트 소유권 증명이 일치하지 않습니다.');
}
