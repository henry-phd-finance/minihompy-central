# 중앙 인증·등록 v2 — 1단계 구현

2026-09-23. 이 문서는 현재 중앙 API 계약이다. 2단계에서 중앙 ID/완료 화면과 개인 비밀번호 화면을 연결했다. 실제 프로젝트 설정·CLI 연결·배포는 4단계에 남으며 운영 배포하지 않았다.

2단계 추가 계약:

- `/login-intents` 응답에 `attempt_id`, `expires_at`, `handle`, 검증된 `return_url`을 포함한다. 중앙 ID 페이지는 verifier와 함께 현재 탭에 저장한다.
- `POST /login-context`에 `{ login_intent, site_id }`를 보내면 서명·미사용·만료·계정/바인딩 상태를 확인한 후 `attempt_id`, `handle`, `site_id`, `expires_at`, `return_site_id`, `return_path`만 반환한다. 개인 페이지가 비밀번호 입력 전 대상 ID를 확인하는 용도이며 verifier/소유자 UUID/인증 정보는 반환하지 않는다.
- `/activation-tickets` 응답의 `attempt_id`를 활성화 티켓과 함께 중앙 완료 페이지 fragment로 전달한다. 중앙 완료 페이지는 현재 탭의 시도 ID와 비교한 뒤 저장된 verifier로 교환한다.
- 실제 UI 기준은 `public/login.html` 및 `public/complete.html`이다. 구형 `identity-page` Edge 경로는 `CENTRAL_PAGE_URL`(기본 중앙 Pages 주소)의 대응 `.html`로 302 이동한다. fragment는 브라우저가 보존한다.
- 두 저장소 브라우저 검사는 `scripts/verify-login-browser.mjs /path/to/playwright/index.mjs`로 실행한다. `MINIHOMPY_CLIENT_ROOT`로 개인 저장소 위치를 지정할 수 있다. 개인 Auth는 모의 응답이고 중앙 SQL은 PGlite로 실행한다.

## 신뢰 경계

- 비밀번호는 개인 Supabase로만 보낸다. 중앙 API는 비밀번호를 요구하지 않는다.
- 개인 브라우저가 중앙 `/activation-tickets`에 `Authorization: Bearer <개인 access token>`을 전달한다.
- 중앙은 등록된 `supabase_project_ref`로 **고정된** `https://<ref>.supabase.co/auth/v1/user`에 검증을 요청한다. SDK `getUser(jwt)`와 같은 Auth 엔드포인트다. JWT의 자체 주장인 issuer/subject를 인증 근거로 사용하지 않는다.
- 확인된 사용자가 영구 `authenticated` 계정인지 검사하고, 같은 토큰으로 개인 DB의 `is_minihompy_admin()`을 호출해 소유자 권한을 확인한다. 이미 등록한 소유자 UUID와도 일치해야 한다.
- access token은 검증 호출 중에만 사용하고 DB·로그·URL에 기록하지 않는다. 개인 refresh token과 service role key도 받지 않는다. 중앙 DB 접근용 service role key는 중앙 런타임에만 둔다.
- 중앙이 저장하는 추가 정보는 공개 프로젝트 키, 소유권 확인 상태, 짧게 유효한 로그인 시도와 소유권 확인 요청이다. 개인 콘텐츠·이메일·비밀번호는 등록 데이터에 포함하지 않는다.
- API/소유권 파일 요청에는 5초 타임아웃, 응답 크기 제한, 리다이렉트 금지를 적용한다. 서버가 보내는 오류에 토큰이나 원격 응답을 포함하지 않는다.

## 중앙 환경 설정

- `CENTRAL_TOKEN_SECRET`: 암호학적으로 무작위인 최소 32바이트 전용 서명키. `JWT_SECRET` 또는 코드 기본값으로 대체하지 않는다. 미설정 시 인증 요청은 503으로 실패한다.
- `SUPABASE_URL`: 중앙 프로젝트 URL.
- `CENTRAL_SERVICE_ROLE_KEY` 또는 `SUPABASE_SERVICE_ROLE_KEY`: 중앙 DB 접근 키. anon 키로 대체하지 않는다.
- `CENTRAL_ORIGIN`: 중앙 Pages origin. 개인 사이트 origin은 검증이 완료된 활성 사이트에서만 CORS 허용 목록에 추가한다. 캐시 갱신은 최대 60초 걸린다.
- `identity-api`의 `verify_jwt = false`는 유지한다. 개인 프로젝트 토큰을 중앙 프로젝트 JWT로 해석하는 게이트웨이 검증 대신, API 내부에서 등록된 개인 프로젝트를 대상으로 검증한다.
- `/health`는 프로세스 생존 확인이며 DB/서명키/실제 로그인 readiness를 보장하지 않는다.

## 사이트 등록

등록은 CLI 또는 중앙 origin에서 수행한다. 아직 검증되지 않은 개인 origin은 CORS 허용 목록에 없다.

1. 개인 Supabase에서 소유자 계정으로 인증한다. `is_minihompy_admin()`이 `true`여야 한다.
2. `POST /sites`에 개인 access token을 Authorization 헤더로 보내고 아래 정보를 제출한다.

```json
{
  "handle": "alice",
  "display_name": "앨리스",
  "origin": "https://alice.github.io",
  "base_path": "/minihompy/",
  "homepage_url": "https://alice.github.io/minihompy/",
  "login_url": "https://alice.github.io/minihompy/login/",
  "supabase_project_ref": "<20자 프로젝트 ref>",
  "supabase_publishable_key": "<publishable 또는 해당 프로젝트의 anon 키>"
}
```

3. 응답은 `202`와 `status: pending`, `registration_id`, `verification_url`, `verification_file`, `expires_at`이다. 유효기간은 24시간이다. 이 시점에는 회원/사이트/바인딩을 만들거나 handle을 예약하지 않는다.
4. `verification_file` JSON을 개인 Pages의 `minihompy-identity/<registration_id>.json`에 배포한다. 기본 경로가 `/minihompy/`라면 그 아래에 둔다. 응답의 정확한 `verification_url`에서 읽혀야 한다.
5. 동일 소유자로 다시 인증하여 `POST /sites/verify`에 Authorization 헤더와 `{ "registration_id": "..." }`를 보낸다.
6. 중앙이 해당 소유자 인증과 Pages 파일의 일회성 challenge를 확인한다. SQL 트랜잭션 하나로 회원·사이트·바인딩을 만들고 등록 요청을 소비한다. 중복 handle/프로젝트 등의 오류는 모든 변경을 롤백한다.
7. 응답은 `status: verified`, `member_id`, `site_id`, `handle`이다. 확인 파일은 이후 제거해도 된다.

현재 개인 GitHub Pages `<계정>.github.io` HTTPS origin만 지원한다. origin·홈페이지·로그인 URL·base path는 일치해야 한다. 커스텀 도메인은 별도의 안전한 원격 주소 검증을 마련한 뒤 지원한다. 입력된 임의 호스트로 서버 요청을 보내지 않는다.

## 로그인 교환

### 1. 중앙 ID 화면에서 로그인 의도 생성

중앙 페이지는 암호학적 난수 `code_verifier`(권장 32바이트를 base64url로 인코딩한 43자)를 생성하여 **중앙 origin의 현재 탭 sessionStorage**에 보관한다. `code_challenge = BASE64URL(SHA256(code_verifier))`만 API에 전달한다. verifier는 URL·개인 사이트·로그에 보내지 않는다.

`POST /login-intents`:

```json
{
  "handle": "alice",
  "return_site_id": "<B의 site_id>",
  "return_path": "/minihompy/#/board",
  "code_challenge": "<43자 S256 challenge>"
}
```

`handle` 대신 기존 `member_id` 또는 `site_id` 선택도 지원한다. 대상 A와 복귀 B 모두 검증된 활성 사이트여야 한다. 응답의 `redirect_url`로 이동한다. 서버는 5분 유효한 로그인 시도를 DB에 생성하고 `jti`가 포함된 서명 `login_intent`를 반환한다.

중앙이 verifier를 생성/보관해야 한다. 개인 사이트에서 직접 intent를 발급하는 기존 자동 연결은 이 흐름으로 변경해야 한다. verifier가 없는 구형 요청을 허용하는 호환 우회는 없다.

### 2. A의 개인 페이지에서 인증 후 활성화

`POST /activation-tickets`:

```http
Authorization: Bearer <A의 Supabase access token>
Content-Type: application/json
```

```json
{ "login_intent": "<중앙 의도 토큰>", "site_id": "<A의 site_id>" }
```

`local_user_id`는 필요 없다. 남아 있는 클라이언트가 보내더라도 검증된 사용자와 다르면 거절하며, 이 필드로 최초 바인딩을 만들지 않는다. 서버는 인증·소유자 일치를 확인한 뒤 로그인 시도를 원자적으로 소비하고 2분 유효한 `activation_ticket`을 발급한다. A 페이지는 **이 티켓만** 중앙 완료 페이지 fragment로 전달한다.

### 3. 중앙 완료 페이지에서 세션 생성

중앙 완료 페이지는 fragment를 즉시 제거하고 현재 탭에 저장한 verifier를 읽어 다음 요청을 보낸다.

`POST /sessions/complete`:

```json
{ "activation_ticket": "<활성화 티켓>", "code_verifier": "<해당 탭에 보관한 verifier>" }
```

서버는 challenge 일치·미사용·만료·현재 사용자/바인딩/사이트 상태를 SQL에서 검사하고 티켓을 원자적으로 소비한다. 성공하면 기존 형태의 `central_session`, `session_key`, `user`, `return_site_id`, `return_path`, `return_url`을 반환한다. 중앙 세션은 30일 유효하다. 성공/취소/만료 시 탭의 verifier를 제거한다. URL에서 verifier를 받거나 누락 시 검증을 생략하면 안 된다.

동일 intent 또는 activation ticket의 동시 요청은 한 번만 성공한다. 응답 유실로 소비 여부가 불명확하면 새 로그인 시도를 시작한다. 만료/사용 완료/상태 변경은 409를 반환한다. 중앙 방문 세션 저장과 B 복귀는 후속 화면 구현에서 처리한다.

## 기존 등록 정보 전환

새 SQL `202609230001_verified_identity.sql`은 기존 회원·사이트·소유자 UUID를 삭제하거나 덮어쓰지 않는다. 기존 사이트는 `needs_reverification`이 되고 모든 회원의 `session_version`이 증가해 구형 UUID 기반 세션을 무효화한다. 방문자 티켓도 현재 session version을 확인하므로 구형 티켓은 사용자로 인정하지 않는다.

기존 사이트는 `POST /sites/reverify`에 개인 access token과 `{ "site_id": "...", "supabase_publishable_key": "..." }`를 제출한다. 저장된 사이트 URL/프로젝트/handle을 그대로 사용해 확인 파일을 발급한다. 이후 `/sites/verify`는 신규 등록과 동일하다. 성공해도 기존 `member_id`와 `site_id`는 유지한다.

기존 바인딩이 있으면 같은 활성 소유자 UUID만 재검증할 수 있다. 과거에 잘못 연결된 UUID나 폐기된 연결은 자동으로 바꾸지 않는다. 이런 경우 관리자가 실제 사이트·개인 계정 소유권을 확인한 후 신뢰된 운영 절차로 복구해야 한다. 정지/삭제 사이트나 회원을 재검증으로 활성화할 수 없다.

업그레이드 때는 **새 중앙 전용 서명키로 교체**하고 마이그레이션/중앙 API/새 클라이언트를 맞춰 배포한다. 1단계 API만 운영에 배포하면 구형 개인 클라이언트와 중앙 완료 페이지는 challenge/verifier·Bearer 누락으로 실패한다. 새 화면 연결은 2단계에서 구현했으며 개인 로그인 함수의 Secrets/배포와 CLI·전환 자동화는 4단계에서 완료한다.

기간이 지난 `identity_registrations`와 `identity_login_attempts`는 운영 정리 작업에서 삭제할 수 있다. 데이터가 없어지면 해당 요청은 실패하므로 이미 만료된 행을 정리해도 세션의 신뢰가 약화되지 않는다. 자동 정리 스케줄은 설치·운영 단계에서 설정한다.

## 검증과 한계

이번 실행 결과: `npm test`의 8개 검사 묶음 모두 통과. 새 보안 검사 11개 그룹과 기존 데이터 마이그레이션 검사를 포함한다. Deno 운영 진입점 검사와 `git diff --check`도 통과했다.

```sh
npm ci
npm test
npm run test:security
npx --yes deno check --no-lock --node-modules-dir=none supabase/functions/identity-api/index.ts
```

- API의 단일 구현은 `identity-api/handler.js`와 `secure-auth.js`다. Deno용 `handler.ts`는 이를 재노출해 운영과 검사가 다른 코드를 실행하지 않게 했다.
- 보안 테스트는 실제 마이그레이션/RPC를 PGlite(PostgreSQL)에서 실행한다. 외부 Supabase Auth·GitHub Pages HTTP는 모의 응답이다.
- UUID-only, 타 프로젝트/타인/익명 계정, 소유자 권한 없음, 토큰 변조·만료·재사용, verifier 불일치, 소유권 미확인, 복귀 경로 이탈, DB 실패, 트랜잭션 롤백, 기존 데이터 전환, 브라우저 DB 권한 거절을 검사한다.
- 구형 C3/C4 명령은 새 SQL 기반 보안 검사로 연결했다. C7의 API 주소 비교는 기존 구현의 상대 URL을 실제 origin 기준으로 해석하도록 정정했다.
- 기존 Edge 경로 검사는 새 정적 페이지로의 전달을 확인한다. 별도 브라우저 검사가 정적 페이지의 실제 왕복과 실패 복구를 검사한다. 양쪽 브라우저·실제 Supabase 프로젝트·GitHub Pages 통합 검증은 5단계다.
- 운영 DB 변경, 중앙 함수 배포, 개인 계정 로그인은 이번 단계에서 실행하지 않는다.

참고: [Supabase getUser](https://supabase.com/docs/reference/javascript/auth-getuser), [공개 API 키와 비밀 키](https://supabase.com/docs/guides/getting-started/api-keys).


## 3단계 정적 방문/로그아웃 페이지

`public/visit-flow.js`가 visit.html/logout.html의 공통 흐름을 처리한다. API 요청은 15초 제한이며 실패 시 재시도/이전 화면을 제공한다. 로그아웃은 중앙 localStorage 삭제 및 재조회 성공 후에만 익명 방문표 발급을 진행한다. 저장소 접근 실패를 익명 세션 또는 로그아웃 완료로 숨기지 않는다.

개인에서 전달한 `attempt_id`는 login.js의 탭 pending `visitAttemptId`에 저장하고 complete.js에서 visits/issue로 이어 준다. 개인 탭은 반환 티켓의 시도가 일치해야 표시한다. 로그인 intent의 attemptId와 방문 attemptId는 각각 별개이며 모두 보존한다. 취소는 기존 중앙 세션을 확인하는 방문 흐름으로 돌아간다.

검증: npm test 8개 묶음 및 verify-login-browser.mjs 통과. 브라우저 검사는 A/B/C의 별도 origin에서 방문 인식, 직접 방문/새로고침, 로그아웃, query/hash 유지, 중앙 저장소 삭제 차단, 중앙 장애 복귀/재시도를 확인했다. 외부 Auth는 모의 응답이며 운영 배포는 수행하지 않았다.
