# BYTE BACK 방어전 · 3단계 진짜 로그인을 붙입니다

현재 단계는 **3단계**입니다. 2단계의 Supabase 학습용 DB를 그대로 사용하면서 Supabase Auth 이메일·비밀번호 로그인/로그아웃을 붙이고, Vercel 자료 API가 틀의 `src/verify-login.mjs`로 Bearer 토큰을 검증합니다.

## 현재 작동 구조

1. 브라우저는 공개용 Supabase Project URL과 publishable key로 공식 `@supabase/supabase-js`의 `signInWithPassword()`, `signOut()`, `getSession()` 흐름을 사용합니다.
2. `/api/notes`와 `/api/notes/:id`는 요청의 `Authorization: Bearer ...`만 `src/verify-login.mjs`에 넘겨 검증하며 브라우저가 보낸 userId·role은 사용하지 않습니다.
3. 토큰이 없거나 검증에 실패하면 자료 없이 HTTP 401로 거부합니다. 정상 로그인 토큰은 검증된 `userId`를 얻습니다.
4. POST는 검증된 `userId`를 `owner_id`로 저장하고, UUID `id`가 없으면 서버가 생성합니다. GET/POST/PUT/DELETE CRUD를 지원합니다.
5. **의도된 3단계 약점:** 아직 소유자 권한 검사는 하지 않습니다. 인증된 B가 A의 메모 UUID를 알면 한 건 GET·PUT·DELETE가 가능하며 이것은 4단계에서 막습니다.

## API 계약

- `GET /api/notes` → 로그인 후 메모 배열 `[{id,title,body}, ...]`
- `POST /api/notes` body `{id?,title,body}` → `{id}`
- `GET /api/notes/:id` → `{id,title,body}`, 없으면 404
- `PUT /api/notes/:id` body `{title,body}` → 수정된 `{id,title,body}`
- `DELETE /api/notes/:id` → `{id}`, 이후 같은 GET은 404
- 모든 자료 API는 로그인 토큰 없이는 401

`aleph.config.json`의 `allowedRoutes`에는 실제 경로인 `/api/notes`, `/api/notes/:id`를 기록합니다.

## 로그인 발급자

`aleph.config.json.identityProvider`에는 Supabase Auth 공개 검증 정보만 기록합니다.

- issuer: 현재 프로젝트의 `/auth/v1`
- audience: `authenticated`
- jwksUrl: issuer 아래 `/.well-known/jwks.json`

서버 전용 `SUPABASE_SECRET_KEY`는 기존 Vercel 비밀 환경변수에서만 읽으며 브라우저·응답·로그·Git에 넣지 않습니다. 브라우저에 들어가는 publishable key는 공개용 키입니다.

## DB 상태

`public.learning_notes.id`는 3단계 API 계약에 맞춰 UUID로 전환했습니다. 기존 가상 메모 4건은 보존했고, `owner_id uuid`·RLS 활성 상태와 `anon`/`authenticated` 직접 DB 권한 차단도 유지합니다.

`supabase/step3_auth_crud.sql`은 같은 최종 스키마를 재현합니다. 3단계에서는 owner 기반 RLS 정책을 일부러 추가하지 않습니다. Vercel 서버가 secret으로 DB를 사용하며 로그인만 검사하고, 소유자 권한 검사는 4단계 과제입니다.

## 실행과 확인

로컬 정적 빌드 확인:

```bash
npm run build -- --local
```

Supabase Dashboard → **Authentication → Users**에서 실습용 A 계정(필요하면 B 계정도)을 직접 만들고 비밀번호는 채팅·Git에 남기지 않습니다. 현재 DB에는 Auth 사용자가 없으므로 계정을 만든 뒤 실제 로그인 성공 시험을 진행합니다.

정상 결과:
- 로그아웃 상태에서는 로그인 폼만 보이고 자료 영역은 숨겨집니다.
- A 로그인 후 자료 목록과 추가·수정·삭제 UI가 나타납니다.
- POST로 만든 메모의 `owner_id`는 서버가 검증한 A의 사용자 UUID입니다.
- 삭제 후 같은 `GET /api/notes/:id`는 404입니다.

거부되어야 할 결과:
- 시크릿 창이나 Authorization 헤더 없는 `GET /api/notes`와 `GET /api/notes/:id`는 자료 없이 401입니다.
- 임의 userId·role을 요청 본문에 넣어도 서버 신원으로 인정하지 않습니다.

## 4단계로 남기는 허점

3단계는 **authentication만 구현하고 authorization은 아직 구현하지 않습니다.** 따라서 로그인한 B가 A 메모의 UUID를 알면 한 건 조회·수정·삭제가 가능합니다. 이 동작은 이번 단계에서 숨기거나 고치지 않고 4단계의 BOLA/IDOR 개선 대상으로 명시합니다.

## 과거 노출 기록

1~2단계의 옛 Git 커밋과 옛 Vercel 배포는 별도 이력입니다. 현재 3단계에서 로그인 보호를 붙여도 과거 공개 배포가 자동으로 사라진 것은 아니므로 과거 노출까지 해소됐다고 기록하지 않습니다.

## 코딩 도구 규칙

후속 작업 전에는 [AGENTS.md](AGENTS.md)를 먼저 확인합니다. 실제 비밀번호·JWT·토큰·개인키·서버 전용 키·실제 개인정보는 코드, 로그, 제출 묶음에 넣지 않습니다. `src/verify-login.mjs`는 3단계 틀의 검증 도우미 그대로 사용하며 수정하지 않습니다.
