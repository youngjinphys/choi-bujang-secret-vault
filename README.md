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

## 보너스 xdr-01 · Wazuh 무차별 로그인 공격

- 입력: 가상 Wazuh 경보 28건 (xdr/fixtures/brute-force.json). 원본 경보는 읽기 전용이며, read-alerts.mjs는 시각/출발 주소/계정/규칙 수준/비밀값을 제거한 설명 5개 필드만 추출합니다.
- 패턴: xdr/brute-force/patterns.json, MITRE ATT&CK T1110/T1110.001/T1110.003. 반복 로그인 실패·다계정 password spraying을 기반으로 판정하며 번호나 정답을 직접 비교하지 않습니다.
- 판정: xdr/brute-force/decide.mjs 의 decide(alert). 명확한 패턴은 block (0.85 이상), 애매한 인증 실패는 격리 환경용 보수적 alert (0.65), 정상은 record. 심판 판정 경로는 외부 호출 없이 alert (0.65)로 유지합니다. 수치는 운영상의 점수이며 검증된 실제 공격 확률은 아닙니다.
- Jev 격리 제약: 심판의 단일 파일 실행 계약에 맞춰 decide.mjs에서 외부 호출을 제거했습니다. 애매한 경보는 외부 응답을 기다리지 않고 alert로 반환하며, 제3자 API 전송은 일어나지 않습니다. 향후 Jev 추가 검토는 격리 판정 파일 밖에서 별도로 수행해야 합니다.
- 후보 규칙: xdr/brute-force/deny-rules.json 은 sourceAddress + account 조합, 근거 경보 ID, startsAt/expiresAt (원 경보 시각부터 15분)의 오프라인 후보입니다. xdr/alerts.log 는 비밀값 없는 JSONL 경보 알림이며 재실행 시 같은 항목은 중복 추가하지 않습니다.
- 판정기 연결: xdr/brute-force/ztna-gate.mjs 의 checkZTNAExtra()는 원래 판정이 allow 이고, 서버가 검증한 주소/계정/시각이 있는 경우에만 deny 후보를 추가 검사합니다. 기존 deny/step_up 은 그대로 유지합니다. 현재 docs/DECIDER_REQUEST.md 의 18개 요청 필드에는 검증된 출발 주소와 Wazuh 계정 매핑이 없고 src/decider.mjs도 전부 거부 시작점이므로, 본 보너스는 **격리된 오프라인 후보/어댑터**이지 운영 ZTNA 강제 차단이 아닙니다. 운영에 연결하려면 엔진이 검증한 네트워크 주소·사용자 매핑과 등록된 이유 코드를 제공해야 합니다.
- 주의: 학습용 IP는 RFC 5737 문서 예시 대역이고, 경보 시각이 지난 시점의 후보는 자동 만료됩니다. 과거 경보를 재생해 현재 새 차단을 만들지 않습니다. 공유 IP만으로 광범위하게 차단하지 않습니다.

재현 명령: npm run test:xdr && npm run xdr:run -- brute-force && npm run xdr:run -- brute-force

실행 뒤 xdr/brute-force/result.json 의 counts, deny-rules.json 의 후보/만료, xdr/alerts.log 의 단일 JSONL 행을 확인하세요. 정상 이벤트는 record, 추가 확인 대상은 alert, 근거가 충분한 실패만 block 으로 나와야 합니다. 서버 검증 주소/계정이 없거나 규칙이 만료된 경우에는 추가 차단되지 않아야 합니다. 이 실행은 운영 심판 점수나 실제 네트워크 차단 증거가 아닙니다.

### 보너스 xdr-01 · 차단 누락 점검

이전 로컬 점검은 block 10 · alert 9 · record 9였으나, 심판은 명확한 공격 차단 부족이라고 보고했습니다. 비공개 정답이나 심판 입력은 확인하지 못했습니다. Wazuh \`rule.level\`은 실패 횟수가 아니라 심각도이며, 기존 분류기는 \`level >= 10\`과 소수의 한국어 설명 형태를 차단의 필수 조건으로 삼아 누락 가능성이 있었습니다.

지금은 출발지·계정·실패 횟수·시간창·동일 비밀번호 다계정 시도·성공 여부를 함께 판정합니다. 반복 실패의 하위 유형에는 짧은 창에서 같은 계정의 실패 및 같은 주소의 반복 실패를 추가했습니다. Wazuh 원본과 안전한 5필드 투영 모두 수용하며, 별도 실패 횟수 필드도 처리합니다. 낮은 수준의 실패라도 조건이 충분하면 학습용 차단 후보로 처리합니다. 다만 적은 실패 횟수만으로 실제 운영 주소를 자동 차단하는 것은 오탐 위험이 있으므로, 현재 후보는 \`simulation_only\`이며 운영 차단은 연결하지 않습니다.

검증: \`npm run test:xdr && npm run xdr:run -- brute-force && npm run xdr:run -- brute-force\`. XDR 결과는 \`xdr/brute-force/result.json\`, 근거 경보 번호와 만료 시각은 \`deny-rules.json\`에서 확인합니다. 정상 이벤트 차단 0건을 필수 조건으로 검사합니다. 본 결과는 별도로 수행한 자체 테스트이며 공식 심판 점수를 의미하지 않습니다.

### 보너스 xdr-01 · 심판 격리 호환 수정

심판이 커밋 a3ff4d767aa1의 decide 실행을 거부한 원인은 decide.mjs의 전이 의존성이 node:fs/node:net/node:crypto를 사용하고, Jev 외부 호출 가능성이 있던 구조입니다. 이제 패턴 기준을 decide.mjs 상단의 상수로 고정했습니다. 이 파일은 decide(alert)만 export하며 import/파일 입출력/네트워크/환경변수를 전혀 사용하지 않고 즉시 응답합니다.

기존 로컬 차단 후보/만료 시각/alert 로그 적재는 scripts/xdr-run.mjs가 ztna-gate.mjs를 **별도로** 로딩해 수행하므로 격리 판정 경로와 분리됩니다. 운영 ZTNA 판정기 기존 규칙은 수정하지 않았습니다.

재현: npm run test:xdr && npm run xdr:run -- brute-force. test:xdr에는 decide.mjs 파일만 빈 임시 폴더로 복사하고, 네트워크를 비활성화한 하위 Node 프로세스에서 로딩·판정하는 검증을 추가했습니다. 공식 점수는 심판 재실행 후 확인해야 합니다.


## 보너스 xdr-02 · Wazuh 웹 주입 공격 판별 (MITRE ATT&CK T1190)

- **입력:** `xdr/fixtures/web-injection.json` 가상 경보 26건. 원본은 수정하지 않습니다. `xdr/web-injection/read-alerts.mjs`는 시각·출발 IP·계정·규칙 수준·비밀값을 제거한 설명 5개 필드만 추출합니다. 원본 URL 쿼리와 비밀값은 출력하지 않습니다.
- **패턴:** `xdr/web-injection/patterns.json`. MITRE ATT&CK T1190의 공개 웹 앱 악용과 DET0080의 비정상 요청 탐지에 기반해 반복 SQL 주입, 스크립트 삽입, 경로 이탈, 명령 구분자 입력을 구분합니다. 단일 `select` 수업명이나 검색용 따옴표는 차단 근거가 아닙니다. 패턴 문서: https://attack.mitre.org/techniques/T1190/
- **격리 심판:** `xdr/web-injection/decide.mjs` **하나만** 가져가도 실행됩니다. 패턴은 파일 맨 위 상수로 내장했으며, 이 파일은 `decide(alert)`만 export합니다. 다른 파일/npm/Node 내장 모듈을 import하지 않고 파일·네트워크·환경변수도 접근하지 않습니다. 확신도 기준은 block 0.85+, alert 0.5+, record 그 아래입니다.
- **부작용 분리:** `xdr/web-injection/respond.mjs`는 오프라인 차단 후보 `deny-rules.json`과 `xdr/alerts.log` JSONL 알림을 생성합니다. 차단 후보는 명확한 공격만 사용하며 `sourceAddress + path`로 범위를 좁히고 경보 발생 시각으로부터 15분 뒤 만료됩니다. IP 공유 위험을 줄이기 위해 같은 출발지에 정상 관측이 있으면 자동 후보를 제외합니다. 알림에는 경보 ID·시간·행동·패턴 이름만 넣고 원문 URL/IP/계정은 넣지 않습니다. 재실행해도 같은 알림은 중복 추가하지 않습니다.
- **기존 판정기 우선:** `checkZTNAExtra`는 upstream 판정이 `allow`이고, **서버가 검증한** 출발 주소·경로·시각이 있을 때만 후보를 추가 검사합니다. 기존 `src/decider.mjs`와 그 판정·등록 규칙은 그대로 유지됩니다. 현재 `docs/DECIDER_REQUEST.md` v1에는 출발 IP가 없으므로 실제 ZTNA 서버 차단은 연동되지 않았고 후보 파일에는 `simulation_only`를 기록했습니다. 과거 실습 경보를 재실행해도 만료된 IP 차단을 되살리지 않습니다.

재현: `npm run test:xdr && npm run xdr:run -- web-injection && npm run xdr:run -- web-injection`

확인: `xdr/web-injection/result.json` 의 block/alert/record, `xdr/web-injection/deny-rules.json`의 근거 경보 번호·만료시각, `xdr/alerts.log`의 중복 없는 JSONL 행을 확인하세요. `npm run test:xdr`는 심판처럼 `decide.mjs` 파일 **하나만 빈 임시 폴더에 복사**해 오프라인으로 실행하는 테스트를 포함합니다. 자체 시험은 공식 심판 채점이 아닙니다.
