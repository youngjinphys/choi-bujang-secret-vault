# BYTE BACK 방어전 · 2단계 자료를 코드 밖으로 옮기기

현재 단계는 **2단계**입니다. 1단계의 정적 `data.json` 공개를 끝내고, 자료 본문은 Supabase의 `public.learning_notes` 테이블로 옮깁니다. 브라우저는 Supabase에 직접 접속하지 않고 Vercel 서버 함수 `/api/notes`만 호출합니다.

## 현재 작동 구조

1. `supabase/step2_notes.sql`은 `owner_id uuid`를 포함한 `public.learning_notes`를 만들고 RLS를 켭니다. `owner_id`에는 `auth.users` 외래키를 걸지 않습니다.
2. `anon`과 `authenticated`에는 테이블 권한을 주지 않으며 SELECT 정책도 만들지 않습니다.
3. `/api/notes`만 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 읽어 `id`, `title`, `content`만 반환합니다. 키 값은 응답·로그·브라우저 파일에 넣지 않습니다.
4. `/`은 `/api/notes`를 호출해 카드를 그립니다. 정적 `/data.json`의 `notes`는 빈 배열입니다.
5. **남은 약점:** 2단계의 `/api/notes` 주소 자체에는 아직 사용자 인증이 없습니다. 서버 키가 숨겨져 있어도 누구나 이 공개 함수를 호출해 자료를 읽을 수 있으므로 다음 단계의 접근 통제가 필요합니다.

## Supabase SQL Editor에서 실행

`supabase/step2_notes.sql`을 SQL Editor에서 실행합니다. 그 다음 Table Editor 또는 아래 확인 쿼리로 `owner_id`와 RLS를 확인합니다.

```sql
select column_name, data_type
from information_schema.columns
where table_schema = 'public' and table_name = 'learning_notes'
order by ordinal_position;

select relrowsecurity
from pg_class
where oid = 'public.learning_notes'::regclass;

select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'learning_notes'
  and grantee in ('anon', 'authenticated');
```

마지막 쿼리는 행이 없어야 합니다. 네 건의 학습용 자료는 **SQL Editor에서만** 입력하고 그 실제 문장을 저장소 파일에 복사하지 않습니다.

```sql
insert into public.learning_notes (owner_id, title, content)
values
  (null, '<첫 번째 제목>', '<첫 번째 본문>'),
  (null, '<두 번째 제목>', '<두 번째 본문>'),
  (null, '<세 번째 제목>', '<세 번째 본문>'),
  (null, '<네 번째 제목>', '<네 번째 본문>');
```

## Vercel 환경변수

Vercel Project Settings의 환경변수에 다음 **이름만** 등록합니다. 실제 값은 Vercel의 비밀 입력란에 직접 넣고 Git, 채팅, 로그에 복사하지 않습니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY` — 서버 전용 secret/service key. 브라우저용 변수가 아닙니다.

값이 없으면 `/api/notes`는 503으로 실패하며 키를 대신 노출하지 않습니다.

## 다시 실행

```bash
npm run build -- --local
```

Vercel에 환경변수와 DB 자료를 넣은 뒤 배포 화면을 새로고침합니다. 정상 상태에서는 `/`에 네 카드가 보이고 `/data.json`의 `notes`는 빈 배열입니다.

## 현재 GitHub 최신 파일과 현재 배포 정적 파일 검색

실제 문장을 README나 명령 기록에 다시 남기지 않기 위해 검사할 한 문장을 셸 변수로만 입력합니다.

```bash
read -r CHECK_TEXT
git grep -nF -- "$CHECK_TEXT" HEAD -- . || true
APP='https://skt-aleph-defense.vercel.app'
{ curl -fsS "$APP/"; curl -fsS "$APP/data.json"; } | grep -nF -- "$CHECK_TEXT" || true
```

두 검색 모두 출력이 없어야 합니다. 공개 API의 남은 약점은 본문을 출력하지 않고 건수만 확인합니다.

```bash
curl -fsS "$APP/api/notes" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).notes.length))"
```

환경변수와 DB가 준비된 2단계에서는 `4`가 나오면 화면이 읽는 공개 API가 네 건을 반환한다는 뜻입니다. 이것은 **현재 단계의 남은 공개 접근 약점**이지 보호 완료의 증거가 아닙니다.

## 최근 검증 기록

2026-10-05 기준으로 저장소 문구가 아니라 실제 GitHub HEAD·Supabase·Vercel production을 각각 다시 확인했습니다.

- GitHub 최신 HEAD에서 1단계 가상 메모 본문 네 문장을 각각 검색한 결과: **0건**.
- 현재 production의 `/` 정적 HTML과 `/data.json`에는 가상 메모 본문이 없고, `/data.json`은 `notes: []`입니다.
- Supabase `public.learning_notes`: **4행**, `owner_id uuid`, RLS 활성화, 외래키 0개, `anon`·`authenticated` 테이블 권한 0개, 공개 읽기 정책 0개로 확인했습니다.
- Vercel production에는 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`가 등록되어 있으며, 키 값은 이 문서·응답·로그에 기록하지 않습니다.
- 현재 production의 `/api/notes`는 인증 없이 **HTTP 200으로 가상 자료 4건을 반환**합니다. 화면은 이 공개 API를 통해 네 카드를 읽습니다. 이는 2단계의 의도된 남은 약점이며 **3단계 전까지 실제 개인정보나 비밀 자료를 넣으면 안 됩니다.**
- 1단계 커밋과 그때 생성된 Vercel 배포는 여전히 접근 가능하고, 옛 `/data.json`에서 가상 메모 본문을 읽을 수 있음을 확인했습니다. 따라서 **과거 공개 노출은 해소되지 않았습니다.**

## 과거 노출에 대한 기록

현재 HEAD와 새 배포의 정적 파일에서 문장을 지워도 **옛 공개 Git 커밋이나 옛 Vercel 배포가 접근 가능한 동안 과거 노출이 해소됐다고 기록하면 안 됩니다.** 이번 단계가 증명하는 것은 새 정적 파일과 현재 GitHub 최신 파일에서 본문을 제거했다는 것뿐입니다. 과거 커밋·배포의 제거 또는 접근 불가 여부는 별도로 확인해야 합니다.

## 코딩 도구 규칙

후속 작업 전에는 [AGENTS.md](AGENTS.md)를 먼저 확인합니다. 실제 키·토큰·개인키·실제 개인정보는 코드, Git, 로그, 제출 묶음에 넣지 않습니다. `src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 운영 심판 판정이 아닙니다.
