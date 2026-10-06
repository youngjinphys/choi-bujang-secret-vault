# BYTE BACK 방어전 · 4단계 저장점

현재 단계는 **4단계**입니다. Supabase Auth 로그인과 서버 토큰 검증은 유지하면서, Vercel 자료 API가 검증된 사용자 ID와 DB의 `owner_id`를 비교해 본인 메모만 읽기·추가·수정·삭제하도록 제한합니다.

> 이 저장소에는 앞서 만들어진 5단계 검토 파일이 이미 있었기 때문에 삭제하지 않고 보존했습니다. 현재 활성 제출 단계는 `aleph.config.json.step = 4`이며 4단계 SQL은 별도 파일로 추가했습니다.

## 현재 작동 구조

1. 브라우저는 Supabase Auth로 로그인하고 자료 CRUD는 Vercel `/api/notes` 계열만 호출합니다.
2. 서버는 기존 `src/verify-login.mjs`가 검증한 `userId`만 신뢰하며 URL·본문의 userId/role/owner_id를 권한 근거로 사용하지 않습니다.
3. 목록은 `owner_id = 검증된 userId`로 제한하고 POST는 그 userId를 `owner_id`로 저장합니다.
4. 한 건 GET·PUT·DELETE는 DB의 기존 `owner_id`를 먼저 확인하고 일치하지 않으면 404로 기본 거부합니다.
5. PUT은 `{title,body}`만 받아 새 행의 `owner_id`도 검증된 userId로 고정합니다.

## API 계약과 허용 경로

`aleph.config.json.allowedRoutes`:

- `GET /api/notes`
- `POST /api/notes`
- `GET /api/notes/:id`
- `PUT /api/notes/:id`
- `DELETE /api/notes/:id`

응답 계약은 그대로 유지합니다.

- 목록 GET → `[{id,title,body}, ...]`
- POST `{id?,title,body}` → `{id}`
- 한 건 GET → `{id,title,body}`
- PUT body → `{title,body}`
- DELETE → `{id}`
- 없는 메모와 타인 메모는 모두 404로 취급해 존재 여부도 노출하지 않습니다.

## A/B 소유자 seed SQL

검토용 파일: `supabase/step4_seed_owners.sql`

실제 이메일은 Git에 넣지 않았습니다. SQL Editor에서 실행하기 직전에 `[A_EMAIL]`, `[B_EMAIL]` placeholder를 실습 계정 이메일로 바꿉니다.

SQL은 다음 조건을 모두 만족할 때만 진행합니다.

- 두 이메일이 `auth.users`에서 각각 정확히 한 계정에 대응
- A와 B가 서로 다른 계정
- 현재 `learning_notes`가 정확히 4개의 미소유 가상 메모 상태

적용 결과는 **A 3건 + B 공개 가능한 시험 메모 1건**, `owner_id IS NULL` 0건이어야 합니다.

## RLS/최소 권한 SQL — 제안만, 아직 미적용

검토용 파일: `supabase/step4_owner_rls.sql`

이번 저장점에서는 이 SQL을 DB에 실행하지 않습니다. 현재 실제 DB를 읽기 전용으로 확인한 결과:

- `learning_notes`: 4행
- 소유자 연결 전: 4행 모두 `owner_id IS NULL`
- 현재 RLS policy: 0개
- `anon`: SELECT/INSERT/UPDATE/DELETE 모두 false
- `authenticated`: SELECT/INSERT/UPDATE/DELETE 모두 false

제안 SQL은 먼저:

```sql
revoke all on table public.learning_notes from public, anon, authenticated;
```

로 기존 권한을 회수한 뒤 `authenticated`에 SELECT·INSERT·UPDATE·DELETE만 GRANT합니다. 이후 SELECT/DELETE는 `USING`, INSERT는 `WITH CHECK`, UPDATE는 `USING + WITH CHECK` 모두 `(select auth.uid()) = owner_id`일 때만 허용합니다. 다른 테이블은 건드리지 않습니다.

적용 후 기대 권한:

- anon: SELECT/INSERT/UPDATE/DELETE = false
- authenticated: SELECT/INSERT/UPDATE/DELETE = true
- 실제 행 접근은 RLS 때문에 본인 `owner_id`로만 제한

직접 Data API 검증은 **anon/publishable key 역할만 점수용으로 확인**하고, 심판이 재현할 수 없는 authenticated 직접 접근은 점수 근거로 삼지 않습니다.

## 확인 절차

SQL 적용 뒤 화면에서:

1. A 로그인 → A 메모 3건만 보이는지 확인
2. B 로그인 → B 시험 메모 1건만 보이고 A 메모는 안 보이는지 확인
3. A/B 각각 자기 메모 추가·수정·삭제가 되는지 확인
4. 상대 메모 UUID로 GET·PUT·DELETE 시 404인지 확인
5. PUT/POST 본문에 `owner_id`를 추가한 요청은 허용된 API 계약이 아니므로 거부되는지 확인

RLS SQL을 적용한 뒤 SQL Editor에서 `information_schema.role_table_grants`와 `has_table_privilege` 결과도 전후 비교합니다.

## 아직 실행하지 않은 것

- A/B 이메일이 이 대화에 실제 값으로 제공되지 않았으므로 seed SQL은 **제안만** 했고 DB에는 적용하지 않았습니다.
- RLS/GRANT SQL도 사용자 검토 전에는 DB에 적용하지 않았습니다.
- 따라서 A/B 실제 로그인 E2E는 두 SQL을 적용한 뒤 최종 확인해야 합니다.

## 설정

- `step`: 4
- `identityProvider`: 기존 Supabase Auth issuer/audience/JWKS 유지
- `allowedRoutes`: 위 5개 method + path
- 기존 5단계 `originalApiUrl` 값과 `supabase/step5_revoke_direct_access.sql`은 다른 작업 보존 원칙에 따라 삭제하지 않았습니다.

## 과거 노출

현재 소유자 격리를 추가해도 과거 공개 Git 커밋과 이전 Vercel 배포 자체가 삭제되는 것은 아닙니다. 과거 노출까지 해소됐다고 기록하지 않습니다.

## 실행

```bash
npm run build -- --local
```

4단계 저장점 커밋 뒤 제출 묶음은 로컬의 ignored `bundle-notes.json`을 사용해:

```bash
npm run bundle
```

로 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 커밋하지 않습니다.
