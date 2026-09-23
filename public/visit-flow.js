(() => {
  'use strict';
  const flow = window.MinihompyLoginFlow, config = window.MINIHOMPY_CENTRAL_CONFIG;
  const params = new URLSearchParams(location.search);
  const siteId = params.get('site_id') || params.get('target_site_id');
  const message = document.querySelector('#message'), retry = document.querySelector('#retry'), back = document.querySelector('#back');
  let busy = false;
  async function run() {
    if (busy) return;
    busy = true; retry.hidden = back.hidden = true;
    message.textContent = '방문자 정보를 확인하고 있습니다.';
    try {
      let session;
      try {
        session = localStorage.getItem(flow.sessionKey);
      } catch { throw Error('브라우저 저장소에 접근하지 못했습니다. 저장소 사용을 허용한 뒤 다시 시도해 주세요.'); }
      if (document.body.dataset.action === 'logout') {
        if (session) {
          try { await flow.post(config.apiBaseUrl, 'sessions/logout', { central_session: session }); }
          catch (error) {
            // Expired/invalid and legacy visitor-only credentials cannot authorize
            // writing grants. Network/server failures must remain retryable.
            if (error.status !== 401) throw error;
          }
        }
        try {
          localStorage.removeItem(flow.sessionKey);
          if (localStorage.getItem(flow.sessionKey) !== null) throw Error();
        } catch { throw Error('브라우저 저장소에 접근하지 못했습니다. 저장소 사용을 허용한 뒤 다시 시도해 주세요.'); }
        session = null;
      }
      if (!siteId) {
        if (document.body.dataset.action !== 'logout') throw Error('미니홈피에서 다시 시작해 주세요.');
        message.textContent = '로그아웃이 완료되었습니다.'; return;
      }
      const data = await flow.post(config.apiBaseUrl, 'visits/issue', {
        central_session: session, target_site_id: siteId,
        return_path: params.get('return_path') || '/', attempt_id: params.get('attempt_id') || '',
      });
      if (data.session_invalid) {
        try { localStorage.removeItem(flow.sessionKey); if (localStorage.getItem(flow.sessionKey) !== null) throw Error(); }
        catch { throw Error('만료된 로그인 정보를 지우지 못했습니다. 저장소 설정을 확인해 주세요.'); }
      }
      if (!data.return_url) throw Error('복귀 주소를 확인하지 못했습니다. 다시 시도해 주세요.');
      location.replace(data.return_url);
    } catch (error) {
      message.textContent = error.message;
      retry.hidden = false; back.hidden = history.length < 2;
    } finally { busy = false; }
  }
  retry.addEventListener('click', run);
  back.addEventListener('click', () => history.back());
  void run();
})();
