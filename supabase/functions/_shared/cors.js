/**
 * Central Identity Dynamic CORS Module (ESM)
 */

export function getCorsHeaders(requestOrigin, allowedOrigins) {
  const allowedSet = allowedOrigins instanceof Set ? allowedOrigins : new Set(allowedOrigins);
  const headers = {
    'Vary': 'Origin',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-client-info, apikey',
    'Access-Control-Max-Age': '86400',
  };

  if (requestOrigin && allowedSet.has(requestOrigin)) {
    headers['Access-Control-Allow-Origin'] = requestOrigin;
  }

  return headers;
}

export function handleCorsPreflight(request, allowedOrigins) {
  if (request.method !== 'OPTIONS') {
    return null;
  }

  const origin = request.headers.get('Origin');
  const allowedSet = allowedOrigins instanceof Set ? allowedOrigins : new Set(allowedOrigins);

  if (origin && allowedSet.has(origin)) {
    return new Response(null, {
      status: 204,
      headers: getCorsHeaders(origin, allowedSet),
    });
  }

  return new Response('CORS origin not allowed', { status: 403 });
}
