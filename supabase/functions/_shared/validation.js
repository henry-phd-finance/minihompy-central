/**
 * Central Identity Validation and Normalization Module (ESM)
 */

export function validateHandle(raw) {
  if (typeof raw !== 'string') {
    throw new Error('handle은 문자열이어야 합니다.');
  }
  const normalized = raw.trim().toLowerCase();
  if (!/^[a-z0-9._-]{2,30}$/.test(normalized)) {
    throw new Error('handle은 2~30자의 영문 소문자, 숫자, 마침표(.), 밑줄(_), 하이픈(-)만 사용할 수 있습니다.');
  }
  return normalized;
}

export function validateDisplayName(raw) {
  if (typeof raw !== 'string') {
    throw new Error('이름은 문자열이어야 합니다.');
  }
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 50 || /[\u0000-\u001f\u007f]/u.test(trimmed)) {
    throw new Error('표시 이름은 제어 문자 없이 1~50자로 입력해 주세요.');
  }
  return trimmed;
}

export function validateOrigin(raw, allowLocalHttp = false) {
  if (typeof raw !== 'string') {
    throw new Error('origin은 문자열이어야 합니다.');
  }
  const trimmed = raw.trim();

  let url;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error('올바른 URL 형식이 아닙니다.');
  }

  if (url.username || url.password) {
    throw new Error('origin에 사용자 인증 정보를 포함할 수 없습니다.');
  }

  if (url.pathname !== '/' || url.search || url.hash) {
    throw new Error('origin에는 경로, 쿼리, 해시를 포함할 수 없습니다.');
  }

  const isLocalHost = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';

  if (url.protocol === 'http:') {
    if (!allowLocalHttp || !isLocalHost) {
      throw new Error('HTTPS 프로토콜만 허용됩니다.');
    }
  } else if (url.protocol !== 'https:') {
    throw new Error('지원되지 않는 프로토콜입니다.');
  }

  return url.origin;
}

export function validateRelativePath(raw, basePath = '/') {
  if (typeof raw !== 'string') {
    throw new Error('복귀 경로는 문자열이어야 합니다.');
  }

  const path = raw.trim();
  if (!path) return basePath;

  if (path.length > 2048) {
    throw new Error('복귀 경로가 최대 길이(2048자)를 초과했습니다.');
  }

  if (/[\u0000-\u001f\u007f\\]/u.test(path)) {
    throw new Error('복귀 경로에 허용되지 않는 제어 문자 또는 역슬래시가 포함되어 있습니다.');
  }

  if (path.startsWith('//') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(path)) {
    throw new Error('외부 스킴이나 프로토콜 상대 경로는 허용되지 않습니다.');
  }

  let normalizedBase = basePath.trim();
  if (!normalizedBase.startsWith('/')) normalizedBase = '/' + normalizedBase;
  if (!normalizedBase.endsWith('/')) normalizedBase = normalizedBase + '/';

  let resolved;
  try {
    resolved = new URL(path, 'https://dummy.local' + normalizedBase);
  } catch {
    throw new Error('복귀 경로 파싱에 실패했습니다.');
  }

  if (resolved.origin !== 'https://dummy.local') {
    throw new Error('복귀 경로가 유효하지 않습니다.');
  }

  if (!resolved.pathname.startsWith(normalizedBase) && resolved.pathname !== normalizedBase.slice(0, -1)) {
    throw new Error('복귀 경로가 등록된 기본 경로(base_path)를 벗어날 수 없습니다.');
  }

  return resolved.pathname + resolved.search + resolved.hash;
}
