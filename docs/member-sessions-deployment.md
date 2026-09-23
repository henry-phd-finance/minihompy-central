# 자동 회원 세션 v2 운영 갱신

기존 중앙 기본·회원 작성·회원 이동 마이그레이션이 적용된 설치에서 실행한다. 신규 중앙도 해당 설치를 먼저 완료한다.

```sh
CENTRAL_PROJECT_REF=<project-ref> node scripts/deploy-member-sessions.mjs
CENTRAL_PROJECT_REF=<project-ref> SUPABASE_ACCESS_TOKEN=<private-environment-value> node scripts/deploy-member-sessions.mjs --apply
```

실제 토큰은 환경변수로 주입한다. 004 SQL을 트랜잭션/해시 이력으로 적용한 뒤 identity-api와 identity-page를 배포한다. 중앙 서명키와 기존 Secrets는 교체하지 않는다. 기존 회원·사이트·소유자 연결은 그대로 둔다. 추적되지 않은 갱신 스키마나 이미 적용된 SQL의 해시 변경은 자동 처리하지 않는다.

health의 member_session_protocol:2를 확인하고 개인 사이트의 writing 설치로 009 SQL과 함수를 적용한다. 중앙 Pages 배포를 완료한 뒤 개인 Pages를 자동 인증 화면으로 전환한다. 서버는 기존 v1 화면과 호환된다.

화면 복구는 이전 Pages 런타임을 후속 일반 커밋으로 재배포한다. DB 전체 복원이나 signing key 교체로 세션/콘텐츠를 되돌리지 않는다. v2 DB에 이전 SQL/함수를 덮어쓰지 않고 새 family·delegation 및 이후 데이터를 유지하며 순방향 수정한다.

이번 배포: identity-api 15, identity-page 13. A/B 개인 함수와 운영/실제 만료 검증은 개인 저장소의 docs/verification/member-session-step7에 기록한다.
