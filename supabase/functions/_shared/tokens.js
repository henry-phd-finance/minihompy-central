/**
 * Central Identity HMAC-SHA-256 Token Module (ESM)
 * Compatible with Deno and Node.js 18+ (Web Crypto API).
 */

export const MAX_TOKEN_BYTES = 4096;
export const CLOCK_TOLERANCE_SECONDS = 30;

export function base64UrlEncode(buffer) {
  let binary = '';
  const len = buffer.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function stringToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToString(bytes) {
  return new TextDecoder().decode(bytes);
}

export function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function getHmacKey(secret) {
  const secretBytes = stringToBytes(secret);
  return await globalThis.crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function signToken(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerPart = base64UrlEncode(stringToBytes(JSON.stringify(header)));
  const payloadPart = base64UrlEncode(stringToBytes(JSON.stringify(payload)));
  const signingInput = `${headerPart}.${payloadPart}`;

  const key = await getHmacKey(secret);
  const signatureBuffer = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    stringToBytes(signingInput)
  );
  const signaturePart = base64UrlEncode(new Uint8Array(signatureBuffer));

  const token = `${signingInput}.${signaturePart}`;
  if (stringToBytes(token).byteLength > MAX_TOKEN_BYTES) {
    throw new Error('토큰 크기가 최대 허용치(4KiB)를 초과했습니다.');
  }
  return token;
}

export async function verifyToken(
  token,
  expectedKind,
  secret,
  nowSeconds = Math.floor(Date.now() / 1000)
) {
  if (typeof token !== 'string') {
    throw new Error('토큰 형식이 올바르지 않습니다.');
  }

  const tokenBytes = stringToBytes(token);
  if (tokenBytes.byteLength > MAX_TOKEN_BYTES) {
    throw new Error('토큰 크기가 허용 범위(4KiB)를 초과했습니다.');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('토큰 형식이 올바르지 않습니다.');
  }

  const [headerPart, payloadPart, signaturePart] = parts;
  if (!headerPart || !payloadPart || !signaturePart) {
    throw new Error('토큰 구성 요소가 비어 있습니다.');
  }

  let header;
  try {
    header = JSON.parse(bytesToString(base64UrlDecode(headerPart)));
  } catch {
    throw new Error('토큰 헤더 파싱에 실패했습니다.');
  }

  if (header.alg !== 'HS256') {
    throw new Error(`지원하지 않는 서명 알고리즘입니다: ${header.alg}`);
  }

  const key = await getHmacKey(secret);
  const signingInput = `${headerPart}.${payloadPart}`;
  const expectedSignatureBuffer = await globalThis.crypto.subtle.sign(
    'HMAC',
    key,
    stringToBytes(signingInput)
  );
  const expectedSignatureBytes = new Uint8Array(expectedSignatureBuffer);

  let actualSignatureBytes;
  try {
    actualSignatureBytes = base64UrlDecode(signaturePart);
  } catch {
    throw new Error('토큰 서명 디코딩에 실패했습니다.');
  }

  if (!timingSafeEqual(expectedSignatureBytes, actualSignatureBytes)) {
    throw new Error('토큰 서명이 일치하지 않거나 변조되었습니다.');
  }

  let payload;
  try {
    payload = JSON.parse(bytesToString(base64UrlDecode(payloadPart)));
  } catch {
    throw new Error('토큰 페이로드 파싱에 실패했습니다.');
  }

  if (!payload || typeof payload !== 'object') {
    throw new Error('토큰 페이로드가 유효한 객체가 아닙니다.');
  }

  if (payload.kind !== expectedKind) {
    throw new Error(`예상하지 않은 토큰 종류입니다 (기대: ${expectedKind}, 실제: ${payload.kind})`);
  }

  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') {
    throw new Error('토큰 발행 시각 또는 만료 시각이 누락되었습니다.');
  }

  if (nowSeconds > payload.exp + CLOCK_TOLERANCE_SECONDS) {
    throw new Error('토큰 유효 시간이 만료되었습니다.');
  }
  if (nowSeconds < payload.iat - CLOCK_TOLERANCE_SECONDS) {
    throw new Error('토큰 발행 시각이 현재 시각보다 미래입니다.');
  }

  return payload;
}
