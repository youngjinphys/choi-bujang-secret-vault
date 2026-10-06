// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
const appUrl = (config) => {
  let app;
  try { app = new URL(config.publicAppUrl); } catch { throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.'); }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
};

const safeJson = async (response) => {
  try { return await response.json(); } catch { return null; }
};

export async function runAttackChecks(config) {
  const app = appUrl(config);

  if (config.step === 1) {
    if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
      throw new Error('가상 자료 확인 표시를 넣어 주세요.');
    }
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const data = response.ok ? await safeJson(response) : null;
    const visible = data?.sampleMarker === config.sampleMarker
      && Array.isArray(data.notes) && data.notes.length > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 자료를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 자료 확인 표시가 보임'
        : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  if (config.step === 2) {
    const staticResponse = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const staticCache = staticResponse.headers.get('cache-control') || '';
    const staticData = staticResponse.ok ? await safeJson(staticResponse) : null;
    const staticEmpty = Array.isArray(staticData?.notes) && staticData.notes.length === 0
      && !Object.hasOwn(staticData, 'sampleMarker') && /\bno-store\b/iu.test(staticCache);

    const identityResponse = await fetch(new URL('/aleph.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const identityCache = identityResponse.headers.get('cache-control') || '';
    const identityData = identityResponse.ok ? await safeJson(identityResponse) : null;
    const identityClean = identityData?.step === 2
      && !Object.hasOwn(identityData, 'sampleMarker') && /\bno-store\b/iu.test(identityCache);

    const apiResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    const apiCache = apiResponse.headers.get('cache-control') || '';
    const apiData = apiResponse.ok ? await safeJson(apiResponse) : null;
    const apiCount = Array.isArray(apiData?.notes) ? apiData.notes.length : null;

    return [
      { attackId: 'static_note_copy_removed', expected: '정적 /data.json은 메모·1단계 표시 없이 notes=[]이고 no-store',
        observed: staticEmpty ? '정적 /data.json은 notes=[]·표시 없음·Cache-Control=no-store'
          : `정적 /data.json 검증 실패 (HTTP ${staticResponse.status}, Cache-Control=${staticCache || '없음'})` },
      { attackId: 'step1_marker_removed', expected: '2단계 /aleph.json은 1단계 표시 없이 no-store',
        observed: identityClean ? '2단계 /aleph.json은 표시 없음·Cache-Control=no-store'
          : `/aleph.json 검증 실패 (HTTP ${identityResponse.status}, Cache-Control=${identityCache || '없음'})` },
      { attackId: 'public_notes_api_remains', expected: '비로그인 /api/notes는 4건을 반환하고 no-store이며 공개 주소 약점이 남음',
        observed: apiCount === null ? `공개 API가 자료 목록을 반환하지 않음 (HTTP ${apiResponse.status})`
          : `비로그인 /api/notes가 ${apiCount}건 반환·Cache-Control=${/\bno-store\b/iu.test(apiCache) ? 'no-store' : (apiCache || '없음')}·공개 주소 유지` },
    ];
  }

  if (config.step === 3) {
    const listResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    const listBody = await safeJson(listResponse);
    const listDenied = listResponse.status === 401
      && !Array.isArray(listBody) && !Array.isArray(listBody?.notes);

    const itemResponse = await fetch(new URL('/api/notes/00000000-0000-4000-8000-000000000000', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    const itemBody = await safeJson(itemResponse);
    const itemDenied = itemResponse.status === 401
      && !itemBody?.title && !itemBody?.body;

    return [
      { attackId: 'anonymous_note_list_denied', expected: '무로그인 목록 GET은 자료 없이 401 거부',
        observed: listDenied ? '무로그인 /api/notes가 자료 없이 HTTP 401로 거부됨'
          : `무로그인 목록 거부 검증 실패 (HTTP ${listResponse.status})` },
      { attackId: 'anonymous_note_item_denied', expected: '무로그인 한 건 GET은 자료 없이 401 거부',
        observed: itemDenied ? '무로그인 /api/notes/:id가 자료 없이 HTTP 401로 거부됨'
          : `무로그인 한 건 거부 검증 실패 (HTTP ${itemResponse.status})` },
    ];
  }

  if (config.step === 4) {
    const listResponse = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    const listBody = await safeJson(listResponse);
    const listDenied = listResponse.status === 401
      && !Array.isArray(listBody) && !Array.isArray(listBody?.notes);

    const itemResponse = await fetch(new URL('/api/notes/00000000-0000-4000-8000-000000000000', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { Accept: 'application/json' },
    });
    const itemBody = await safeJson(itemResponse);
    const itemDenied = itemResponse.status === 401
      && !itemBody?.title && !itemBody?.body;

    return [
      { attackId: 'anonymous_note_list_denied', expected: '4단계 무로그인 목록 GET은 자료 없이 401 거부',
        observed: listDenied ? '무로그인 /api/notes가 자료 없이 HTTP 401로 거부됨'
          : `무로그인 목록 거부 검증 실패 (HTTP ${listResponse.status})` },
      { attackId: 'anonymous_note_item_denied', expected: '4단계 무로그인 한 건 GET은 자료 없이 401 거부',
        observed: itemDenied ? '무로그인 /api/notes/:id가 자료 없이 HTTP 401로 거부됨'
          : `무로그인 한 건 거부 검증 실패 (HTTP ${itemResponse.status})` },
    ];
  }

  if (config.step !== 5) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');

  let original;
  try { original = new URL(config.originalApiUrl); } catch { throw new Error('5단계 원본 자료 API 주소를 확인해 주세요.'); }
  if (original.protocol !== 'https:' || original.username || original.password
      || original.search || original.hash || original.pathname.endsWith('/')) {
    throw new Error('5단계 originalApiUrl은 쿼리 없는 HTTPS 자료 경로여야 합니다.');
  }

  const listResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Accept: 'application/json' },
  });
  const listBody = await safeJson(listResponse);
  const listDenied = listResponse.status === 401
    && !Array.isArray(listBody) && !Array.isArray(listBody?.notes);

  const manifestResponse = await fetch(new URL('/aleph.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Accept: 'application/json' },
  });
  const manifestBody = manifestResponse.ok ? await safeJson(manifestResponse) : null;
  const manifestMatches = manifestBody?.step === 5
    && manifestBody?.originalApiUrl === config.originalApiUrl;
  const manifestRoutes = Array.isArray(manifestBody?.allowedRoutes)
    && manifestBody.allowedRoutes.length > 0;

  const screenResponse = await fetch(app, {
    redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Accept: 'text/html' },
  });
  const screenText = screenResponse.ok ? await screenResponse.text() : '';
  const contentTypeOptions = screenResponse.headers.get('x-content-type-options') || '';
  const contentSecurityPolicy = screenResponse.headers.get('content-security-policy') || '';
  const screenHardened = contentTypeOptions.toLowerCase() === 'nosniff'
    || Boolean(contentSecurityPolicy.trim());
  const publicKeyAbsent = !/sb_publishable_[A-Za-z0-9_-]+/u.test(screenText)
    && !/eyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}/u.test(screenText);

  const originResponse = await fetch(original, {
    redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Accept: 'application/json' },
  });
  const originBody = await safeJson(originResponse);
  const originDenied = [401, 403].includes(originResponse.status)
    && !Array.isArray(originBody);

  return [
    { attackId: 'anonymous_note_list_denied', expected: '무로그인 Vercel 자료 API는 자료 없이 401 거부',
      observed: listDenied ? '무로그인 /api/notes가 자료 없이 HTTP 401로 거부됨'
        : `무로그인 목록 거부 검증 실패 (HTTP ${listResponse.status})` },
    { attackId: 'deployment_manifest_original_api', expected: '/aleph.json의 originalApiUrl이 제출 설정과 일치',
      observed: manifestMatches ? '배포 /aleph.json의 step=5와 originalApiUrl이 제출 설정과 일치함'
        : `배포 manifest 원본 주소 검증 실패 (HTTP ${manifestResponse.status})` },
    { attackId: 'deployment_manifest_allowed_routes', expected: '/aleph.json의 allowedRoutes에 허용 경로가 하나 이상 있음',
      observed: manifestRoutes ? `배포 /aleph.json allowedRoutes에 ${manifestBody.allowedRoutes.length}개 경로가 있음`
        : '배포 /aleph.json allowedRoutes가 비어 있거나 없음' },
    { attackId: 'first_screen_security_header', expected: '첫 화면 응답에 nosniff 또는 CSP 보안 헤더가 있음',
      observed: screenHardened ? `첫 화면 보안 헤더 확인: ${contentTypeOptions || 'CSP'}`
        : `첫 화면 보안 헤더 없음 (HTTP ${screenResponse.status})` },
    { attackId: 'screen_public_key_absent', expected: '첫 화면 코드에 Supabase publishable/anon 키가 없음',
      observed: publicKeyAbsent ? '첫 화면 코드에 Supabase 공개 키 패턴이 없음'
        : '첫 화면 코드에서 Supabase 공개 키 패턴을 발견함' },
    { attackId: 'direct_origin_without_key_denied', expected: '원본 자료 HTTPS 경로는 키 없는 직접 요청을 거부',
      observed: originDenied ? `원본 자료 경로가 자료 없이 HTTP ${originResponse.status}로 거부됨`
        : `원본 자료 직접 요청 거부 검증 실패 (HTTP ${originResponse.status})` },
  ];
}
