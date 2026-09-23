(async () => {
  'use strict';
  const flow = window.MinihompyLoginFlow, config = window.MINIHOMPY_CENTRAL_CONFIG;
  const fragment = new URLSearchParams(location.hash.slice(1));
  const ticket = fragment.get('ticket'), attemptId = fragment.get('attempt_id');
  history.replaceState(null, '', location.pathname);
  const pending = flow.read(flow.storage('sessionStorage'), flow.pendingKey);
  const message = document.querySelector('#message'), restart = document.querySelector('#restart'), back = document.querySelector('#return');
  if (pending?.siteId) {
    restart.href = flow.page(config.pageBaseUrl, 'login.html', { site_id: pending.siteId, return_path: pending.returnPath, attempt_id: pending.visitAttemptId || '' }).href;
    if (pending.returnUrl) { back.href = pending.returnUrl; back.hidden = false; }
  }
  try {
    if (!ticket || !pending?.verifier || pending.attemptId !== attemptId || pending.deadline < Date.now()) {
      throw Error('로그인 요청이 만료되었거나 이 탭에서 시작하지 않은 요청입니다. 다시 로그인해 주세요.');
    }
    // Check persistent storage before consuming the one-use activation ticket.
    const probe = flow.sessionKey + '.probe';
    flow.save(localStorage, probe, { available: true }); flow.remove(localStorage, probe);
    const data = await flow.post(config.apiBaseUrl, 'sessions/complete', { activation_ticket: ticket, code_verifier: pending.verifier });
    if (!data.central_session || data.return_site_id !== pending.siteId) throw Error('로그인 응답을 확인하지 못했습니다. 다시 로그인해 주세요.');
    try {
      localStorage.setItem(flow.sessionKey, data.central_session);
      if (localStorage.getItem(flow.sessionKey) !== data.central_session) throw Error();
    } catch { throw Error('로그인 정보를 저장하지 못했습니다. 브라우저 저장소 설정을 확인해 주세요.'); }
    flow.remove(flow.storage('sessionStorage'), flow.pendingKey);
    location.replace(flow.page(config.pageBaseUrl, 'visit.html', { site_id: data.return_site_id, return_path: data.return_path, attempt_id: pending.visitAttemptId || '' }).href);
  } catch (error) {
    flow.remove(flow.storage('sessionStorage'), flow.pendingKey);
    message.textContent = error.message;
    restart.hidden = !restart.href;
  }
})();
