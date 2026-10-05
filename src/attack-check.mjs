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

export async function runAttackChecks(config) {
  const app = appUrl(config);

  if (config.step === 1) {
    if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
      throw new Error('가상 자료 확인 표시를 넣어 주세요.');
    }
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes) && data.notes.length > 0;
      } catch {}
    }
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 자료를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 자료 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
  }

  if (config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  const staticResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const staticCache = staticResponse.headers.get('cache-control') || '';
  const staticNoStore = /\bno-store\b/iu.test(staticCache);
  let staticEmpty = false;
  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      staticEmpty = Array.isArray(data.notes) && data.notes.length === 0
        && !Object.hasOwn(data, 'sampleMarker') && staticNoStore;
    } catch {}
  }

  const identityResponse = await fetch(new URL('/aleph.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const identityCache = identityResponse.headers.get('cache-control') || '';
  const identityNoStore = /\bno-store\b/iu.test(identityCache);
  let identityClean = false;
  if (identityResponse.ok) {
    try {
      const data = await identityResponse.json();
      identityClean = data?.step === 2 && !Object.hasOwn(data, 'sampleMarker') && identityNoStore;
    } catch {}
  }

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const apiCache = apiResponse.headers.get('cache-control') || '';
  const apiNoStore = /\bno-store\b/iu.test(apiCache);
  let apiCount = null;
  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      if (Array.isArray(data.notes)) apiCount = data.notes.length;
    } catch {}
  }

  return [
    { attackId: 'static_note_copy_removed', expected: '정적 /data.json은 메모·1단계 표시 없이 notes=[]이고 no-store',
      observed: staticEmpty ? '정적 /data.json은 notes=[]·표시 없음·Cache-Control=no-store'
        : `정적 /data.json 검증 실패 (HTTP ${staticResponse.status}, Cache-Control=${staticCache || '없음'})` },
    { attackId: 'step1_marker_removed', expected: '2단계 /aleph.json은 1단계 표시 없이 no-store',
      observed: identityClean ? '2단계 /aleph.json은 표시 없음·Cache-Control=no-store'
        : `/aleph.json 검증 실패 (HTTP ${identityResponse.status}, Cache-Control=${identityCache || '없음'})` },
    { attackId: 'public_notes_api_remains', expected: '비로그인 /api/notes는 4건을 반환하고 no-store이며 공개 주소 약점이 남음',
      observed: apiCount === null ? `공개 API가 자료 목록을 반환하지 않음 (HTTP ${apiResponse.status})`
        : `비로그인 /api/notes가 ${apiCount}건 반환·Cache-Control=${apiNoStore ? 'no-store' : (apiCache || '없음')}·공개 주소 유지` },
  ];
}
