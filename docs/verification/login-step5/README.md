# 5단계 완료 — 실제 배포와 두 사이트 통합 검증

2026-09-23, 운영 배포와 실제 A/B 로그인 검증 완료.

| 대상 | 배포 주소 | Supabase 프로젝트 |
| --- | --- | --- |
| A / henry91-jung | https://henry-phd-finance.github.io/minihompy/ | itkymmxnbjylyzbmdxdb |
| B / henry-hs-jung | https://henry-hs-jung.github.io/minihompy/ | zcaodcujqbjrogffwalk |
| 중앙 | https://henry-phd-finance.github.io/minihompy-central/login.html | pcwovvdgggpbghvqraex |

로그인은 A/B 미니홈피의 로그인 버튼에서 시작한다. 중앙 ID 화면은 원래 방문 사이트 정보 없이 직접 열면 로그인 시작 안내를 표시한다.

## 실제 변경

중앙 기존 회원 2개·사이트 2개·바인딩 1개를 비공개 위치에 백업한 뒤 v2 마이그레이션을 1회 적용했다. 회원/siteId와 기존 소유자 연결은 보존했다. 이전 중앙 세션은 session_version 증가로 폐기했다. 기존 A/B의 개인 Auth 계정·콘텐츠 DB는 재생성하거나 마이그레이션하지 않았다.

중앙 함수 identity-api/identity-page와 중앙 Pages, A/B 개인 owner-login 함수/Secrets, 개인 최신 런타임을 배포했다. A/B 모두 실제 소유자 인증과 각 Pages 확인 파일로 재검증하여 기존 siteId를 유지한 verified 상태가 되었다. 없던 소유자 바인딩은 검증된 계정으로 생성했다. 기존 서명키를 유지했고, 오래된 중앙 service-role 설정은 현재 프로젝트 키로 동기화했다. 비밀값은 Git/보고서에 넣지 않았다.

A 저장소의 미배포 로컬 커밋 3개도 반영했다. 원본 작업 파일을 보존하면서 A/중앙 로컬 브랜치를 배포 이력에 맞췄고 이전 로컬 이력은 pre-deployment-20260923 브랜치에 남겼다. B는 별도 체크아웃에서 배포하여 A와 다른 프로젝트/사이트 설정을 유지했다.

## 발견하고 수정한 문제

- 구형 중앙 Edge HTML이 실제로 text/plain과 스크립트 차단 CSP로 응답하여 왕복이 멈췄다. 로그인·방문 UI를 GitHub Pages로 배포하고 Edge 경로는 해당 Pages로 이동시킨다.
- B 공개 Supabase URL 끝의 /rest/v1 때문에 SDK 요청이 /rest/v1/rest/v1로 나갔다. 프로젝트 origin만 설정하도록 수정했다. A/B 모두 기본 6개 메뉴와 설정 조회가 정상이다.
- 초기 페이지 로딩 중 리다이렉트가 원래 방문 기록을 대체하는 문제를 수정했다. load 이후 이동하며 지연은 제한한다.
- 중앙 로그인 JS 초기화 전 네이티브 폼 제출로 복귀 정보가 사라지는 문제를 수정했다. 입력창/버튼은 이벤트 연결 후 활성화한다. 지연된 스크립트 회귀 검사도 통과했다.
- Supabase Secrets 저장 성공 응답에 JSON 본문이 없는 경우 배포 도구가 실패하던 문제를 수정하고 빈 204 응답 회귀 검사를 추가했다.

## 실제 검증 근거

- [최종 사전점검 및 정상 로그인](live-result.json): 최신 런타임 해시/설정/프로토콜 검사 28/28 통과. B에서 A 로그인과 원래 게시판 복귀, 새로고침, A→B 직접 방문, 방문자 로그아웃, 잔존 개인 세션의 자동 중앙 로그인 방지, B로 계정 전환 후 A에서 방문자 인식, 본인 사이트 개인+중앙 로그아웃, 관리자 권한 분리 통과.
- [실제 서버 오류 경로](live-failures.json): 잘못된 비밀번호 거부와 입력 삭제, 소비한 활성화 티켓 재사용 거부, 명시적 로그인에서 개인 세션 재사용, 실제 시간이 경과한 방문 티켓 만료 거부 통과. 저장소 차단/중앙 네트워크 장애는 실제 배포 페이지에 브라우저 측 결함을 주입하여 재시도·안전한 복귀를 확인했다. 중앙 서비스를 실제로 중단하지 않았다.
- [배포 상태와 기존 ID](deployed-state.json): 두 사이트 verified 및 소유자 바인딩, 런타임 배포 커밋/Actions 실행 기록.
- 비밀번호·refresh token·이메일은 중앙 요청 본문에서 검출되지 않았다. 비밀번호 값/토큰/쿠키/storageState/요청 본문은 보고서에 저장하지 않았다. 테스트는 Auth/중앙 로그인 상태를 생성하지만 게시물·댓글·프로필을 쓰지 않는다.

로컬 검증도 중앙 10개 검사 묶음, A/B/C 브라우저 통합, 초기 스크립트 지연, CLI/산출물 검사를 통과했다. 실제로 배포한 개인 사이트는 A/B 두 개다. 세 번째 origin 방문은 모의 C로 검증했으며 실제 C 사이트를 임의 생성하지 않았다. 이 기록은 Chromium 검사이고 Safari/실물 모바일 검수를 의미하지 않는다.

## 재검수

```sh
# GET-only, 로그인하지 않음
node scripts/verify-live-identity.mjs

# MINIHOMPY_TEST_A_PASSWORD / MINIHOMPY_TEST_B_PASSWORD 환경변수 필요
CHROMIUM_PATH=/path/to/chromium node scripts/verify-live-identity.mjs \
  --login --playwright /path/to/playwright/index.mjs

# 실제 오류 경로: 첫 소유자 비밀번호 사용, 자연 만료까지 약 90초 대기
# 비공개 env 파일에서는 pwA도 지원한다. 비밀값을 명령행 인자로 넣지 않는다.
CHROMIUM_PATH=/path/to/chromium node scripts/verify-live-failures.mjs \
  --playwright /path/to/playwright/index.mjs --env-file /private/path/.env
```

access-inventory.json은 권한 제공 전의 최초 조사 기록이다. 이후 사용자가 개인 Supabase 토큰과 B GitHub 배포 토큰을 제공했고 배포 및 실제 인증까지 완료했다. 이전 미배포/403 결과를 현재 상태로 해석하지 않는다. 중앙 마이그레이션은 Management SQL API로 적용했으므로 향후 Supabase CLI로 DB 변경을 배포할 때 기존 적용 이력을 먼저 대조하고, 이미 적용한 v2 SQL을 다시 실행하지 않는다.
