# 중앙 v2 배포와 기존 사이트 전환

2026-09-23, 4단계 도구 구현 기준. 초기 4단계 검수 후 5단계에서 실제 중앙 DB/함수/Pages와 A/B 전환을 완료했다. [최종 검수](verification/login-step5/README.md). 아래는 이후 배포에도 사용하는 절차이며, 이미 적용한 마이그레이션은 반복하지 않는다.

## DB: 기존 데이터를 보존하는 1회 업그레이드

먼저 대상 프로젝트와 DB 백업을 확인한다. `identity_members`, `identity_sites`, `identity_bindings`의 ID/소유자 매핑을 기록한다. 개인 비밀번호나 개인 콘텐츠를 중앙으로 복사하지 않는다.

중앙 저장소에서 Supabase CLI로 대상 프로젝트를 연결하고 `supabase migration list`, `supabase db push --dry-run`으로 적용 대상을 확인한다. 신규 DB는 세 마이그레이션을 순서대로 적용한다. 기존 DB에서 앞선 SQL을 수동 실행했다면, 해당 스키마/권한이 실제 적용된 것을 확인한 뒤 그 버전만 `supabase migration repair <version> --status applied`로 이력에 반영한다. repair는 SQL을 실행하는 명령이 아니다. [공식 마이그레이션 안내](https://supabase.com/docs/guides/deployment/database-migrations).

기존 DB의 기대 신규 적용 대상은 `202609230001_verified_identity.sql` 한 개다. 이전 두 파일이 다시 적용 대상으로 나오거나 DB와 이력이 맞지 않으면 먼저 정합성을 확인한다. v2까지 이미 적용했다면 다시 실행하지 않는다. 대상 확인 후 `supabase db push`를 실행한다. 테이블 drop, bindings 삭제, UUID 재발급, DB reset을 전환 절차로 사용하지 않는다.

v2는 기존 member/site/binding을 보존하고 사이트에 `needs_reverification`을 설정한다. 회원의 session_version을 1회 증가시켜 이전 무증명 중앙 세션을 폐기한다. 개인 Supabase Auth 세션과 DB에는 영향을 주지 않는다. API의 재검증 트랜잭션이 같은 사이트/소유자 연결을 유지하면서 verified로 전환한다. `scripts/verify-identity-upgrade.mjs`가 기존 데이터가 있는 SQL 환경에서 이를 검증한다.

실행 후 사이트별 verification_status와 회원별 session_version을 확인하고 전환 전 기록과 ID가 같은지 비교한다. `private` 스키마는 중앙 service_role API가 접근 가능해야 하며, anon/authenticated의 테이블 권한은 계속 거부되어야 한다. 문제가 생기면 구형 UUID 인증으로 되돌리지 않고 v2를 수정한다. 개인 사이트는 임시로 중앙 연동을 끄고 단독 운영할 수 있다.

## 중앙 함수

환경에 다음 값을 설정한다. `.env`를 자동으로 읽지는 않는다.

| 이름 | 값/보관 위치 |
| --- | --- |
| CENTRAL_PROJECT_REF | 중앙 Supabase project ref |
| CENTRAL_ORIGIN | 중앙 Pages origin, 예: https://henry-phd-finance.github.io |
| CENTRAL_PAGE_URL | 중앙 Pages base URL, 예: https://henry-phd-finance.github.io/minihompy-central |
| CENTRAL_TOKEN_SECRET | 별도 생성한 32바이트 이상 비밀 서명키 |
| SUPABASE_ACCESS_TOKEN | 중앙 프로젝트 배포 권한을 가진 Management token |

```sh
node scripts/deploy-functions.mjs --dry-run
node scripts/deploy-functions.mjs --apply
```

`--apply`에서 DB의 v2 컬럼/등록 RPC/로그인 시도 테이블이 준비되었는지 먼저 확인한다. 미준비이면 Secrets/함수를 변경하지 않는다. 준비되면 중앙 Secrets를 설정하고 `identity-api`, `identity-page`를 배포한다. Supabase CLI는 토큰을 환경변수로 받으며 명령행 인자나 파일에 쓰지 않는다. 함수의 JWT 검사는 앱 내부 프로토콜이 수행하므로 두 함수는 `verify_jwt=false`다. [공식 함수 배포 안내](https://supabase.com/docs/guides/functions/deploy).

GitHub Actions에서도 수동 `Deploy Central Functions`를 실행할 수 있다. `central-functions` environment에 위 공개 값 세 개를 Variables, 서명키와 Management token을 Secrets로 설정한다. DB 마이그레이션은 이 워크플로우가 자동 실행하지 않는다. 키는 매 배포마다 바꾸지 않는다. 키 변경은 모든 중앙 서명 토큰을 무효화한다.

부분 함수 배포 실패는 오류로 종료하며 같은 설정으로 재시도한다. 전용 키가 없을 때 앱은 인증 발급을 거부한다. 기본 키/JWT_SECRET로 대체하지 않는다.

## 중앙 Pages와 개인 전환

`public/config.js`의 apiBaseUrl/pageBaseUrl을 위 함수/Pages 주소와 일치시킨다. Pages source는 GitHub Actions다. `pages.yml`은 `public/` 전체를 무조건 올리는 대신 build allowlist로 `_site`를 만들고 로그인/완료/방문/로그아웃 화면 의존성을 검사한 후 배포한다. workflow 파일 변경도 배포 트리거에 포함된다.

순서는 중앙 DB → 중앙 함수 → 중앙 Pages → 각 개인 `upgrade`(또는 신규 `install`/`register`) → Pages 확인 파일 배포 → 개인 `verify` → 활성 설정 배포다. 기존 개인 설치는 cyworld 저장소 `docs/install-and-upgrade.md`를 따른다. 기존 siteId를 유지하며 같은 개인 소유자로 인증해야 한다. 예전 루트 login_url도 새 개인 로그인 화면으로 연결된다.

재검증 전에는 방문/로그인이 실패할 수 있으므로 전환 구간을 고려한다. 미검증 사이트에 구형 인증을 임시 허용하지 않는다. 실제 로그인은 재검증 이후 다시 수행하며, 다른 개인 origin의 잔존 세션을 자동으로 중앙 로그인으로 바꾸지 않는다.

## 검사와 실행 코드 기준

```sh
npm ci
npm test
npm run build
npm run test:artifact
npx deno check --no-lock --node-modules-dir=none supabase/functions/identity-api/index.ts supabase/functions/identity-page/index.ts
```

JS가 인증 구현의 단일 원본이며 Deno의 TS handler와 공통 모듈은 JS 재내보내기만 한다. `verify-runtime-source.mjs`가 어댑터 외 구현의 재등장을 검사한다. Node 검사와 운영 Deno는 같은 JS를 실행한다. `npm test`는 이 검사와 배포 사전조건 검사까지 포함한 10개 묶음이다.

개인/중앙 CLI 배포 쓰기 검사는 모의 HTTP/프로세스로 수행했다. 5단계에서 실제 Management API, Secrets/함수 배포, Actions/Pages와 기존 A/B 계정 인증을 별도로 확인했다. 신규 개인 계정 생성은 기존 계정을 보존하기 위해 실행하지 않았다.
