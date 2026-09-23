// Legacy Edge page URLs forward to the single static Pages UI.
const DEFAULT_PAGES = 'https://henry-phd-finance.github.io/minihompy-central';
function env(name) { return globalThis.Deno?.env?.get(name) ?? globalThis.process?.env?.[name]; }
export function normalizePagePath(pathname) {
  let path = pathname.replace(/^\/(?:functions\/v1\/)?identity-page(?=\/|$)/, '');
  if (!path.startsWith('/')) path = '/' + path;
  return path.length > 1 ? path.replace(/\/$/, '') : path;
}
export async function handleIdentityPageRequest(req, options = {}) {
  const url = new URL(req.url), path = normalizePagePath(url.pathname);
  if (req.method !== 'GET' || !['/login', '/complete', '/visit', '/logout'].includes(path)) return new Response('Not Found', { status: 404 });
  try {
    const base = new URL(options.centralPageUrl || env('CENTRAL_PAGE_URL') || DEFAULT_PAGES);
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) throw Error();
    const destination = base.href.replace(/\/$/, '') + path + '.html' + url.search;
    // Browsers inherit the original fragment when Location does not replace it.
    return new Response(null, { status: 302, headers: { Location: destination, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' } });
  } catch { return new Response('Central Pages URL is not configured correctly', { status: 503 }); }
}
