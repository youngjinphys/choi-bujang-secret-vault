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
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 자료 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
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
  let staticEmpty = false;
  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();
      staticEmpty = Array.isArray(data.notes) && data.notes.length === 0;
    } catch {}
  }

  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let apiCount = null;
  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      if (Array.isArray(data.notes)) apiCount = data.notes.length;
    } catch {}
  }

  return [
    { attackId: 'static_note_copy_removed', expected: '정적 /data.json에는 메모 본문이 없음',
      observed: staticEmpty ? '정적 /data.json의 notes 배열이 비어 있음' : `정적 파일 확인 실패 또는 notes가 남아 있음 (HTTP ${staticResponse.status})` },
    { attackId: 'public_notes_api_remains', expected: '2단계에서는 /api/notes 공개 주소 약점을 기록',
      observed: apiCount === null ? `공개 API가 자료 목록을 반환하지 않음 (HTTP ${apiResponse.status})` : `비로그인 공개 API가 ${apiCount}건을 반환함` },
  ];
}
