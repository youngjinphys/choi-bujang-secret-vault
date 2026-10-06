# BYTE BACK 방어전 · 5단계 저장점

현재 단계는 **5단계**입니다. 브라우저의 메모 읽기·추가·수정·삭제는 Vercel 서버 함수만 통과시키고, 원본 Supabase Data API 주소를 제출 설정에 기록합니다. 브라우저의 Supabase 사용은 로그인/Auth에만 남깁니다.

## 현재 구조

1. 브라우저 자료 CRUD는 `/api/notes`, `/api/notes/:id`만 호출합니다. `supabase.from(...)` 또는 `/rest/v1/learning_notes` 직접 자료 호출은 **없습니다**.
2. Supabase Auth의 `signInWithPassword()`, `signOut()`, `getSession()`은 그대로 유지합니다.
3. Vercel 서버 함수는 틀의 `src/verify-login.mjs`로 Bearer 토큰을 검증하고, 검증된 `userId`만 신뢰합니다.
4. 목록·한 건 조회·수정·삭제는 모두 `owner_id = 검증된 userId` 조건을 적용하고 POST는 그 userId를 `owner_id`로 저장합니다.
5. 서버는 `SUPABASE_SECRET_KEY`로 DB에 접근하며 이 값은 브라우저·응답·로그·Git에 넣지 않습니다.

## 원본 자료 API

`aleph.config.json.originalApiUrl`:

```text
https://ytvwpdjfrpwxwtucclpe.supabase.co/rest/v1/learning_notes
```

쿼리 문자열·키·토큰을 넣지 않은 원본 HTTPS 테이블 경로입니다. 심판은 별도로 anon/publishable key를 사용해 이 경로의 직접 접근이 차단되었는지 확인할 수 있습니다.

## 브라우저 직접 자료 호출 점검

현재 `public/index.html`의 Supabase SDK 호출은 Auth뿐입니다. 메모 목록/추가/수정/삭제는 전부 같은 출처의 Vercel 서버 함수로 요청합니다. 따라서 이 항목 때문에 브라우저 자료 호출 코드는 변경하지 않았습니다.

## A CRUD 확인 상태

현재 Supabase `auth.users`는 **0명**이라 실제 A 계정 로그인 E2E는 실행할 수 없습니다. 실제 비밀번호나 JWT를 만들거나 요구하지 않았습니다.

대신 확인한 항목:
- 무로그인 Vercel 자료 API는 HTTP 401로 거부됩니다.
- 서버 DB 역할은 SELECT/INSERT/UPDATE/DELETE 권한이 있어 CRUD 자체를 수행할 수 있습니다.
- POST는 검증된 로그인 userId를 `owner_id`에 저장합니다.
- 목록/GET/PUT/DELETE 모두 같은 검증된 userId의 `owner_id` 조건을 사용합니다.

실제 A 계정을 Supabase Dashboard의 Authentication → Users에서 만든 뒤에는 A 로그인 → 추가 → 수정 → 삭제 → 같은 id GET 404를 최종 E2E로 확인하세요.

## 직접 DB 권한 회수 SQL

검토용 SQL은 `supabase/step5_revoke_direct_access.sql`에 있습니다. **이번 커밋에서는 DB에 실행하지 않습니다.**

현재 학습 DB를 조회한 결과 `PUBLIC`·`anon`·`authenticated`의 `public.learning_notes` 직접 table grant는 이미 0건입니다. 따라서 SQL은 현재 상태를 재현·확인하는 idempotent 방어 설정입니다.

적용 전:
- `information_schema.role_table_grants`로 세 역할의 권한을 확인합니다.
- `has_table_privilege(...)`로 SELECT/INSERT/UPDATE/DELETE를 확인합니다.

적용:
```sql
revoke all privileges on table public.learning_notes from public, anon, authenticated;
```

적용 후:
- 세 역할의 grant 조회는 0행이어야 합니다.
- anon/authenticated의 SELECT/INSERT/UPDATE/DELETE는 모두 `false`여야 합니다.
- `service_role`, RLS, 정책, 다른 테이블은 건드리지 않습니다.

## 설정

- `step`: 5
- `identityProvider`: 기존 Supabase Auth issuer/audience/JWKS 유지
- `allowedRoutes`: `/api/notes`, `/api/notes/:id`
- `originalApiUrl`: 쿼리 없는 Supabase REST 원본 자료 경로
- `restoreRoute`: 아직 없음

## 남은 확인

사용자가 SQL을 검토·실행한 뒤:
1. A 계정으로 화면 CRUD가 계속 동작하는지 확인합니다.
2. publishable/anon key로 `originalApiUrl`을 직접 요청했을 때 자료가 반환되지 않는지 확인합니다.
3. 서버 함수 경유 A 요청은 정상이어야 하고, 다른 사용자 자료는 404로 취급되어야 합니다.

## 과거 노출

이전 공개 Git 커밋·Vercel 배포는 별도 이력입니다. 현재 권한을 회수해도 과거 공개 배포 자체가 자동 삭제된 것은 아니므로 과거 노출까지 해소됐다고 기록하지 않습니다.

## 실행

로컬 정적 빌드:

```bash
npm run build -- --local
```

제출 묶음은 `bundle-notes.json`을 로컬에 만든 뒤 `npm run bundle`로 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 커밋하지 않습니다.
