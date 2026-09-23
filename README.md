# 분산 미니홈피 공통 방문자 식별 중앙 허브 (Minihompy Central Identity)

독립된 여러 미니홈피(GitHub Pages + Supabase) 사이에서 동일한 방문자를 식별하고 상태를 연결하는 중앙 식별 서비스입니다.

## 현재 인증 계약 (2026-09-23)

1~5단계 구현과 중앙/A/B 실제 배포·로그인 검증을 완료했다. **UUID만 전달하는 인증과 미확인 사이트의 즉시 등록은 허용하지 않는다.** 개인 Supabase access token 검증, Pages 소유권 확인, 브라우저 검증값과 일회성 티켓을 사용한다.

[API 계약·재검증·배포 순서](docs/identity-v2.md)를 먼저 참고한다. 개인 비밀번호 화면 및 개인 Supabase 로그인 함수와 연결했다. [배포·기존 사이트 전환 안내](docs/deployment.md)에 중앙 DB 1회 전환, 함수/Pages 배포 도구, 개인 CLI 재검증 순서를 정리했다. [실제 배포·통합 검증 결과](docs/verification/login-step5/README.md)를 확인할 수 있다. 검사는 `npm ci && npm test`로 실행한다. 기존 ID를 보존하여 중앙 v2 및 A/B를 재검증했고, 개인 콘텐츠는 변경하지 않았다.

## 아키텍처 및 역할
- **최소 식별 정보만 저장**: 게시물, 사진, 비밀번호 등 개인 콘텐츠나 인증 정보는 저장하지 않으며, 공통 사용자 ID와 미니홈피 사이트 정보만 관리합니다.
- **HMAC-SHA-256 서명 기반 토큰**: `login_intent`, `activation_ticket`, `central_session`, `visit_ticket` 4종 토큰을 안전하게 발행 및 검증합니다.
- **최상위 페이지 리다이렉트 진입점**: 제3자 쿠키나 분할 저장소 제약 없이 중앙 origin `localStorage`의 세션을 안전하게 읽고 원래 미니홈피로 복귀시킵니다.

## 디렉토리 구조
```text
supabase/
  config.toml
  migrations/
    202609180001_identity.sql
  functions/
    _shared/
      tokens.ts (및 tokens.js)
      validation.ts (및 validation.js)
      cors.ts (및 cors.js)
    identity-api/
      index.ts
    identity-page/
      index.ts
scripts/
  verify-shared-identity-protocol.mjs
```

## 검증 실행
```bash
# 1. 프로토콜 및 토큰/보안 검증
node scripts/verify-shared-identity-protocol.mjs

# 2. Step C2: Directory API 및 CORS 검증
node scripts/verify-identity-directory.mjs

# 3. Step C3: Login Intents & Activation Tickets API 검증
node scripts/verify-identity-login.mjs

# 4. Step C4: Sessions Complete API 검증
node scripts/verify-identity-session-complete.mjs

# 5. Step C5: Visits Issue API 검증
node scripts/verify-identity-visit-issue.mjs

# 6. Step C6: Visits Resolve API 검증
node scripts/verify-identity-visit-resolve.mjs

# 7. Step C7: Identity Page (/visit) 검증
node scripts/verify-identity-page-visit.mjs

# 8. Step C8: UI Pages (/login, /complete, /logout) 검증
node scripts/verify-identity-page-ui.mjs

# 전체 검증 일괄 실행
node scripts/verify-all.mjs
```
