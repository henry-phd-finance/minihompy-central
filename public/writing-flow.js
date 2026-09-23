(() => {
  const flow = window.MinihompyLoginFlow, cfg = window.MINIHOMPY_CENTRAL_CONFIG;
  const p = new URLSearchParams(location.search), message = document.querySelector('#message');
  document.querySelector('#back').addEventListener('click', () => history.back());
  (async () => {
    try {
      if (!/^[0-9a-f-]{36}$/i.test(p.get('state') || '')) throw Error('미니홈피에서 다시 시작해 주세요.');
      const session = localStorage.getItem(flow.sessionKey);
      if (!session) throw Error('미니홈피에서 로그인 후 다시 시도해 주세요.');
      const data = await flow.post(cfg.apiBaseUrl, 'writing-proofs/issue', { central_session: session,
        target_site_id: p.get('site_id'), code_challenge: p.get('code_challenge'), return_path: p.get('return_path') });
      const target = new URL(data.return_url);
      if (target.protocol !== 'https:' || !data.writing_proof) throw Error('복귀 주소를 확인하지 못했습니다.');
      target.hash = new URLSearchParams({ proof: data.writing_proof, state: p.get('state') }).toString();
      location.replace(target.href);
    } catch { message.textContent = '회원 확인에 실패했습니다. 미니홈피로 돌아가 다시 로그인하거나 잠시 후 다시 시도해 주세요.'; }
  })();
})();
