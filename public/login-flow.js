(() => {
  'use strict';
  const encode = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  function page(base, name, params = {}) {
    const url = new URL(base.replace(/\/$/, '') + '/' + name);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) throw Error('로그인 주소 설정을 확인해 주세요.');
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    return url;
  }
  async function post(base, path, body, bearer) {
    let response;
    try {
      response = await fetch(page(base, path), {
        method: 'POST', headers: { 'Content-Type': 'application/json', ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}) },
        body: JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(15000), credentials: 'omit',
      });
    } catch { throw Error('서버에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요.'); }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = Error(typeof data.error === 'string' ? data.error : '요청을 완료하지 못했습니다. 다시 시도해 주세요.');
      error.status = response.status; throw error;
    }
    return data;
  }
  function storage(kind) { try { return window[kind]; } catch { return null; } }
  function save(storage, key, value) {
    const data = JSON.stringify(value);
    try { storage.setItem(key, data); if (storage.getItem(key) !== data) throw Error(); }
    catch { throw Error('로그인을 위해 브라우저 저장소 사용을 허용해 주세요.'); }
  }
  function read(storage, key) { try { return JSON.parse(storage.getItem(key)); } catch { return null; } }
  function remove(storage, key) { try { storage.removeItem(key); } catch { /* No credentials in errors. */ } }
  window.MinihompyLoginFlow = Object.freeze({ page, post, save, read, remove, storage,
    random: () => encode(crypto.getRandomValues(new Uint8Array(32))),
    challenge: async value => encode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))),
    pendingKey: 'minihompy.identity.login.v2', sessionKey: 'minihompy.identity.session.v1',
  });
})();
