const explanationText = value => {
  if (typeof value !== 'string') throw new Error('bundle-notes.json의 explanation은 문자열이어야 합니다.');
  const trimmed = value.trim();
  if (trimmed.length < 10 || trimmed.length > 1500) {
    throw new Error('bundle-notes.json의 explanation은 10자 이상 1500자 이하로 적어 주세요.');
  }
  const lines = trimmed.split(/\r?\n/u).map(line => line.trim()).filter(Boolean);
  if (lines.length !== 3) {
    throw new Error('bundle-notes.json의 explanation은 빈 줄을 제외하고 정확히 세 줄로 적어 주세요.');
  }
  return { trimmed, lines };
};

const includesAny = (text, patterns) => patterns.some(pattern => pattern.test(text));

export function validateBundleNotes(notes, step) {
  if (!notes || typeof notes !== 'object' || Array.isArray(notes)) {
    throw new Error('bundle-notes.json은 JSON 객체여야 합니다.');
  }
  const { trimmed } = explanationText(notes.explanation);
  if (step !== 2) return trimmed;

  const text = trimmed.normalize('NFKC');
  const requirements = [
    {
      label: '정적 자료를 Supabase/DB로 이동한 내용',
      ok: includesAny(text, [/supabase/iu, /\bdb\b/iu, /데이터베이스/u])
        && includesAny(text, [/data\.json/iu, /정적/u, /static/iu, /코드 밖/u, /옮/u, /이동/u, /move/iu]),
    },
    {
      label: 'Vercel 서버 함수와 서버 전용 secret 사용',
      ok: includesAny(text, [/\/api\/notes/iu, /서버\s*함수/u, /server\s*function/iu, /vercel\s*function/iu])
        && includesAny(text, [/SUPABASE_SECRET_KEY/u, /서버\s*전용/u, /server[-\s]*only/iu, /secret/iu]),
    },
    {
      label: '현재 /api/notes가 비로그인 공개라는 남은 약점',
      ok: /\/api\/notes/iu.test(text)
        && includesAny(text, [/비로그인/u, /인증[^\n]{0,20}없/u, /공개/u, /unauthenticated/iu, /public/iu]),
    },
    {
      label: '과거 Git 커밋과 이전 배포 노출이 해소되지 않았다는 한계',
      ok: includesAny(text, [/과거/u, /이전/u, /old/iu, /previous/iu])
        && includesAny(text, [/커밋/u, /commit/iu])
        && includesAny(text, [/배포/u, /deployment/iu])
        && includesAny(text, [/해소[^\n]{0,20}않/u, /남아/u, /접근/u, /remain/iu, /not\s+resolved/iu]),
    },
  ];
  const missing = requirements.filter(item => !item.ok).map(item => item.label);
  if (missing.length) {
    throw new Error(`2단계 explanation 필수 내용 누락: ${missing.join(' / ')}`);
  }
  return trimmed;
}
