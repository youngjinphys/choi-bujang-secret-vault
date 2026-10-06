# BYTE BACK 방어전 · 5단계 저장점

현재 단계는 **5단계**입니다. 기본 조건뿐 아니라 가산점 3개를 모두 만족하도록 제출 경로를 보강했습니다.

## 100점 가산점 대응

1. **`/aleph.json.allowedRoutes`**
   - production manifest가 `aleph.config.json.allowedRoutes`를 그대로 포함합니다.
   - 현재 경로는 `/api/notes`, `/api/notes/:id`입니다.
2. **첫 화면 보안 헤더**
   - `vercel.json`의 `/` 응답에 `X-Content-Type-Options: nosniff`를 명시했습니다.
   - 첫 화면은 `Cache-Control: no-store`도 적용합니다.
3. **화면 코드에서 Supabase 공개 키 제거**
   - 브라우저에서 Supabase SDK와 `sb_publishable_...` 값을 완전히 제거했습니다.
   - 공개 키는 Vercel의 server-only `SUPABASE_PUBLISHABLE_KEY` 환경변수에만 둡니다.
   - 로그인·세션 갱신·로그아웃은 `/api/auth/login`, `/api/auth/session`, `/api/auth/logout` 서버 함수가 Supabase Auth를 호출합니다.

## 인증 구조

브라우저는 비밀번호를 로그인 서버 함수에만 보내고, 서버 함수가 Supabase 공식 `signInWithPassword()` 흐름을 사용합니다. refresh token은 `HttpOnly; SameSite=Strict` 쿠키로 두어 JavaScript가 읽지 못하게 했고, 화면에는 서버가 반환한 access token만 메모리에 유지합니다.

페이지를 새로 열면 `/api/auth/session`이 HttpOnly refresh cookie로 세션을 갱신합니다. 메모 요청은 기존처럼 Bearer access token을 `/api/notes`에 보내며, 기존 `src/verify-login.mjs`와 owner 검사는 변경하지 않았습니다.

## 메모 API

`aleph.config.json.allowedRoutes`:

- `/api/notes`
- `/api/notes/:id`

실제 메서드는 GET/POST/PUT/DELETE를 유지합니다. 브라우저의 메모 CRUD는 Supabase Data API를 직접 호출하지 않습니다.

## 원본 자료 API

```text
https://ytvwpdjfrpwxwtucclpe.supabase.co/rest/v1/learning_notes
```

쿼리·키·JWT가 없는 HTTPS 테이블 경로입니다. PUBLIC·anon·authenticated 직접 table privilege는 현재 모두 false이고 service_role CRUD는 유지되어 있습니다. `supabase/step5_revoke_direct_access.sql`은 사용자가 검토 후 직접 실행하는 재현용 SQL이며 이번 변경에서 DB 권한은 바꾸지 않았습니다.

## 자기점검

5단계 `npm run bundle`은 production을 대상으로 다음을 기록합니다.

- 무로그인 `/api/notes` → 401
- `/aleph.json.originalApiUrl` 일치
- `/aleph.json.allowedRoutes`가 1개 이상
- 첫 화면 응답에 `nosniff` 또는 CSP
- 첫 화면 코드에 Supabase publishable/anon key 없음
- key 없는 원본 Data API 직접 요청 거부

## Vercel 환경변수

서버 함수에 다음 설정이 필요합니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY` — 메모 DB 서버 접근 전용
- `SUPABASE_PUBLISHABLE_KEY` — Auth 서버 함수 전용

실제 값은 Git·README·브라우저 응답에 기록하지 않습니다.

## 남은 검증 한계

현재 학습 프로젝트에는 Auth 사용자가 없어 실제 A 계정 로그인 E2E는 실행하지 못했습니다. 비밀번호/JWT를 임의 생성하지 않았습니다. production에서는 무로그인 거부, manifest, 헤더, 공개 키 부재와 서버 런타임을 검증합니다.

## 실행

```bash
npm run test:r5
npm run test:package
npm run build -- --local
npm run bundle
```

`bundle-notes.json`과 `artifacts/submission.json`은 ignored 파일이며 Git에 커밋하지 않습니다.
