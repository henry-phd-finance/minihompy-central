(() => {
  'use strict';
  const flow = window.MinihompyLoginFlow, config = window.MINIHOMPY_CENTRAL_CONFIG;
  const params = new URLSearchParams(location.search), form = document.querySelector('#login-form');
  const message = document.querySelector('#message'), submit = document.querySelector('#submit');
  const handle = document.querySelector('#handle');
  let busy = false, cancelled = false;
  let pending = flow.read(flow.storage('sessionStorage'), flow.pendingKey);
  function clear() { flow.remove(flow.storage('sessionStorage'), flow.pendingKey); }
  function goBack() {
    cancelled = true; clear();
    if (pending?.returnUrl && pending.visitAttemptId) { location.replace(flow.page(config.pageBaseUrl, 'visit.html', {site_id: pending.siteId, return_path: pending.returnPath, attempt_id: pending.visitAttemptId}).href); return; }
    if (pending?.returnUrl) { location.replace(pending.returnUrl); return; }
    if (history.length > 1) { history.back(); return; }
    message.textContent = '로그인을 취소했습니다. 미니홈피로 돌아가 주세요.';
    form.hidden = true;
  }
  if (params.get('cancel') === '1') {
    const attemptId = params.get('attempt_id');
    if (pending && (!attemptId || pending.attemptId === attemptId)) { goBack(); return; }
    message.textContent = '종료된 로그인 요청입니다. 미니홈피에서 다시 시작해 주세요.';
    form.hidden = true; return;
  }
  // Starting again discards any previous unfinished exchange in this tab.
  const prior = pending;
  clear(); pending = null;
  const siteId = params.get('site_id'), returnPath = params.get('return_path') || '/';
  if (!siteId) { message.textContent = '미니홈피에서 로그인 버튼을 눌러 시작해 주세요.'; submit.disabled = true; }
  document.querySelector('#cancel').addEventListener('click', goBack);
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !siteId) return;
    busy = true; submit.disabled = handle.disabled = true; message.textContent = '아이디를 확인하고 있습니다.';
    try {
      const verifier = flow.random();
      pending = { verifier, siteId, returnPath, visitAttemptId: params.get('attempt_id') || (prior?.siteId === siteId && prior?.returnPath === returnPath ? prior.visitAttemptId : null), deadline: Date.now() + 7 * 60 * 1000 };
      flow.save(flow.storage('sessionStorage'), flow.pendingKey, pending);
      const data = await flow.post(config.apiBaseUrl, 'login-intents', {
        handle: handle.value.trim().toLowerCase(), return_site_id: siteId, return_path: returnPath,
        code_challenge: await flow.challenge(verifier),
      });
      if (cancelled) return;
      if (!data.attempt_id || !data.redirect_url || !data.return_url) throw Error('로그인 응답을 확인하지 못했습니다.');
      pending = { ...pending, attemptId: data.attempt_id, returnUrl: data.return_url };
      flow.save(flow.storage('sessionStorage'), flow.pendingKey, pending);
      location.assign(data.redirect_url);
    } catch (error) { clear(); message.textContent = error.message; busy = false; submit.disabled = handle.disabled = false; }
  });
  if (siteId) submit.disabled = handle.disabled = false;
})();
