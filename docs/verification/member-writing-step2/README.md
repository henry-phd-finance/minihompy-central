# 회원 작성 인증 증명 — Step 2 완료

2026-09-23. 중앙 로컬 구현 및 검증 완료. 운영 DB, Edge Functions, GitHub Pages에는 배포하지 않았다.

## 구현

- `202609230002_member_writing.sql`: 로그인별 서버 세션, 일회용 작성 증명, 해시로 보관하는 중앙 grant, service_role 전용 트랜잭션 RPC.
- 기존 로그인 완료 RPC를 감싸 같은 트랜잭션에서 `central_session_id`를 생성한다. 기존 회원/사이트/바인딩과 세션 버전은 마이그레이션만으로 변경하지 않는다.
- `writing-auth.js`: 대상 사이트 한정 60초 증명 발행, S256 PKCE 및 서명 검증, 1회 교환, 최대 15분 grant, 서버 확인·폐기 API.
- 회원/원본 사이트/대상 사이트의 활성·검증 상태, 소유자 바인딩과 로그인 당시 소유자, 세션 버전을 확인한다.
- 이름/홈페이지는 중앙 디렉터리에서 반환한다. 작성 이름은 기존 개인 DB 한도에 맞춰 최대 20문자로 투영한다. 중앙 프로필 원본은 바꾸지 않는다. 등록 origin과 base path 내의 HTTPS 홈페이지만 반환한다.
- `/sessions/logout`은 해당 로그인 세션과 소속 grant를 폐기한다. 미소비 증명도 이후 교환할 수 없다. 다른 로그인 세션은 유지한다.
- 새 세션에서 발행한 방문 티켓도 SID를 전달하고 발급/조회 시 서버 폐기를 확인한다. SID 없는 기존 세션은 기존 방문자 인식만 유지하고 회원 작성에는 재로그인이 필요하다.
- 중앙 로그아웃 화면은 서버 폐기 성공 후 브라우저 정보를 지운다. 서버/저장소 오류는 재시도하며 401인 만료/구형 인증은 로컬에서 정리한다.

## Step 3용 API

모든 경로는 `/functions/v1/identity-api` 아래의 POST다. 오류는 `{error:{code,message}}`, 응답은 `Cache-Control: no-store`다.

| 경로 | 요청 | 결과 |
|---|---|---|
| `/writing-proofs/issue` | `central_session,target_site_id,code_challenge,return_path` | `writing_proof,expires_at,return_path` |
| `/writing-proofs/redeem` | `writing_proof,code_verifier,site_id` | `grant,proof_id,central_session_id,site_id,expires_at,member,active` |
| `/writing-grants/check` | Bearer grant + `site_id` | 같은 검증 정보(grant 원문 제외) |
| `/writing-grants/revoke` | Bearer grant + `{}` | `{revoked:true}`; 반복 호출 가능 |
| `/sessions/logout` | `central_session` | `{revoked:true}`; 반복 호출 가능 |

`member`는 `{id,display_name,homepage_url}`다. 개인 서버는 서버 설정의 중앙 주소/site_id를 사용해야 한다. grant 해시는 중앙 공통 `sha256()`의 base64url 형식이다. 개인 세션 token_hash의 hex 형식과 혼동하지 않는다.

개인 비밀번호, refresh token, 로그인 access token을 새 API로 보내지 않는다. 중앙 서명 비밀키를 개인 사이트와 공유하지 않는다. 이번 단계는 API 제공이며 개인 사이트의 증명 발급/갱신 UI와 작성 세션 교환 연결은 Step 3 이후다.

## 검증

- `npm test`: **12개 스위트 통과**.
- 신규 `verify-member-writing.mjs`: **11개 그룹 통과**. 실제 API handler + PGlite의 실제 SQL/RPC/권한 사용.
- 증명 재사용과 병렬 교환 호출에서 하나만 성공, 위조/다른 kind/다른 대상/잘못된 PKCE/서명·DB 만료 거부.
- 회원 정지·사이트 재검증 필요·바인딩 폐기/소유자 변경·session_version 변경·대상 회원 정지 확인.
- grant 자체 폐기/만료, 로그인별 로그아웃, 미사용 증명 폐기, 방문 티켓 무효화, 독립 로그인 유지 확인.
- private 테이블/RPC의 브라우저 접근 차단. verifier·grant 원문·중앙 세션 토큰 DB 미보관 확인.
- 디렉터리 외 이름 주입 무시, 20문자 이름 투영, 등록 경로 내 홈페이지 허용 및 외부 홈페이지 거부.
- DB 오류 시 일반화된 503 응답, 오류 메시지에 내부 데이터 미노출.
- `verify-writing-logout-ui.mjs`: 서버 실패/저장소 실패/재시도/구형·만료 세션 처리 통과.
- `verify-login-browser.mjs`: 실제 Chromium + 로컬 SQL/모의 외부 HTTP로 A/B/C 방문, 계정 전환, 권한 분리, 로그아웃, 오류 복구와 인증값 전송 경계 검사 통과.
- 중앙 Pages 빌드 및 artifact 검사 통과. TS 진입점과 Node 테스트가 동일 JS를 사용하는 기존 검증도 통과.

재실행:

```sh
npm test
CHROMIUM_PATH=/path/to/chrome node scripts/verify-login-browser.mjs /path/to/playwright/index.mjs
node scripts/build-pages.mjs
node scripts/verify-artifact.mjs
```

PGlite의 병렬 호출 검사는 단일 인스턴스에서 실행한다. 여러 PostgreSQL 연결의 실제 경합 및 호스팅 Supabase gateway/Deno 실행은 이 검증 범위가 아니다. 기존 로그인/방문 테스트를 유지하며 배포 환경 검증은 Step 7에서 수행한다.

## 배포 조건

Step 7에서 중앙 v2 마이그레이션 뒤 이 마이그레이션을 적용한 다음 새 함수/페이지를 함께 배포한다. 새 코드의 로그인 완료는 새 DB RPC 반환값(SID/만료)을 필요로 한다. 기존 배포 스크립트의 자동 마이그레이션 대상 추가도 Step 7에 포함해야 한다. 이 문서의 완료는 운영 활성화를 뜻하지 않는다.
