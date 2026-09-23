import { ApiError, UUID } from '../_shared/auth-proof.js';

export const NAVIGATION_PATHS = new Set(['/navigation/site', '/navigation/members', '/navigation/random']);
// Use the verified registered root, never a historical content URL or login URL.
export function safeNavigationSite(site) {
  try {
    const u = new URL(site.homepage_url);
    return u.protocol === 'https:' && !u.username && !u.password && !u.search && !u.hash
      && (!u.port || (Number(u.port) >= 1 && Number(u.port) <= 65535))
      && /^https:\/\/[a-zA-Z0-9.-]+(:[0-9]+)?$/.test(site.origin)
      && (site.homepage_url === site.origin + site.base_path || site.homepage_url === site.origin + site.base_path.replace(/\/$/, ''));
  } catch { return false; }
}
export function isNavigationRequest(path, params) {
  return NAVIGATION_PATHS.has(path) || (path === '/directory'
    && (params.has('limit') || params.has('after') || (!params.has('handle') && !params.has('q') && !params.has('query'))));
}
const invalid = () => { throw new ApiError(400, '잘못된 이동 조회 조건입니다.'); };
const uuid = value => { if (!UUID.test(value || '')) invalid(); return value.toLowerCase(); };
export async function handleNavigation(req, path, db) {
  if (req.method !== 'GET') return { status: 405, body: { error: 'GET 요청만 지원합니다.' } };
  const params = new URL(req.url).searchParams;
  const allowed = path === '/directory' ? ['q','query','limit','after']
    : path === '/navigation/members' ? ['member_ids'] : ['site_id'];
  for (const key of params.keys()) if (!allowed.includes(key) || params.getAll(key).length !== 1) invalid();
  const args = { p_mode: 'list', p_site: null, p_members: null, p_query: null, p_after: null, p_limit: 20 };
  if (path === '/directory') {
    if (params.has('q') && params.has('query')) invalid();
    const query = params.get('q') ?? params.get('query');
    if (query !== null) {
      const trimmed = query.trim();
      if (query.length > 100 || trimmed.length < 2 || trimmed.length > 30 || /[\u0000-\u001f\u007f]/u.test(query)) invalid();
      args.p_query = trimmed.toLowerCase();
    }
    if (params.has('limit')) {
      if (!/^(?:[1-9]|[1-4][0-9]|50)$/.test(params.get('limit'))) invalid();
      args.p_limit = Number(params.get('limit'));
    }
    if (params.has('after')) args.p_after = uuid(params.get('after'));
  } else if (path === '/navigation/members') {
    const raw = params.get('member_ids') || '';
    if (raw.length > 1849) invalid();
    const ids = raw.split(',');
    if (ids.length > 50) invalid();
    args.p_mode = 'members'; args.p_members = [...new Set(ids.map(uuid))];
  } else {
    args.p_mode = path === '/navigation/site' ? 'site' : 'random';
    args.p_site = uuid(params.get('site_id'));
  }
  if (!db) throw new ApiError(503, '이동 정보를 조회할 수 없습니다.');
  const { data, error } = await db.rpc('identity_navigation', args);
  if (error || !Array.isArray(data)) throw new ApiError(503, '이동 정보를 조회할 수 없습니다.');
  // Explicit allowlist: SQL additions must never accidentally publish private fields.
  const items = data.map(row => ({ id: row.id, site_id: row.site_id, handle: row.handle,
    display_name: row.display_name, homepage_url: row.homepage_url }));
  if (args.p_mode === 'site') return { status: items.length ? 200 : 404, body: items.length ? { item: items[0] } : { error: '방문 가능한 사이트가 없습니다.' } };
  if (args.p_mode === 'random') return { status: 200, body: { item: items[0] || null } };
  if (args.p_mode === 'members') return { status: 200, body: { items } };
  const more = items.length > args.p_limit;
  const page = items.slice(0, args.p_limit);
  return { status: 200, body: { items: page, next_cursor: more ? page.at(-1).id : null } };
}
