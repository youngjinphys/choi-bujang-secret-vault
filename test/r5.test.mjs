import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { validateBundleNotes } from '../scripts/bundle-notes-validation.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'STEP1_FIXTURE_MARKER',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('step 2 deployment identity omits the step 1 marker', () => {
  const step2 = { step: 2, judgeIssuer: config.judgeIssuer, publicAppUrl: config.publicAppUrl };
  assert.deepEqual(deploymentIdentity(env, step2), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
  });
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'STEP1_FIXTURE_MARKER', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 2 attack checks reject static remnants and keep the public API weakness visible', async () => {
  const originalFetch = globalThis.fetch;
  const step2 = { step: 2, publicAppUrl: 'https://student-defense.vercel.app' };
  try {
    globalThis.fetch = async (url) => {
      const path = new URL(String(url)).pathname;
      if (path === '/data.json') return new Response(JSON.stringify({ notes: [] }), { status: 200, headers: { 'cache-control': 'no-store' } });
      if (path === '/aleph.json') {
        return new Response(JSON.stringify({ schema: 'aleph.defense.deployment.v1', step: 2 }), { status: 200, headers: { 'cache-control': 'no-store' } });
      }
      if (path === '/api/notes') {
        return new Response(JSON.stringify({ notes: [{}, {}, {}, {}] }), { status: 200, headers: { 'cache-control': 'no-store' } });
      }
      return new Response('', { status: 404 });
    };
    const results = await runAttackChecks(step2);
    assert.equal(results.length, 3);
    assert.match(results[0].observed, /표시 없음/u);
    assert.match(results[1].observed, /표시 없음/u);
    assert.match(results[2].observed, /4건/u);
    assert.match(results[2].observed, /no-store/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});


test('step 2 bundle explanation requires the three-line security story', () => {
  const valid = [
    '정적 data.json의 자료 본문을 코드 밖 Supabase DB로 이동했습니다.',
    '브라우저는 /api/notes Vercel 서버 함수만 호출하고 SUPABASE_SECRET_KEY는 서버 전용으로 사용합니다.',
    '/api/notes는 아직 비로그인 공개이며 과거 Git 커밋과 이전 Vercel 배포의 노출도 해소되지 않고 남아 있습니다.',
  ].join('\n');
  assert.equal(validateBundleNotes({ explanation: valid }, 2), valid);
  assert.throws(() => validateBundleNotes({ explanation: 'Supabase로 옮겼습니다.\n서버 함수를 붙였습니다.\n공개 API입니다.' }, 2), /필수 내용 누락/u);
  assert.throws(() => validateBundleNotes({ explanation: '한 줄 설명만 있습니다.' }, 2), /정확히 세 줄/u);
  assert.throws(() => validateBundleNotes({ explanation: '가'.repeat(1501) + '\n나\n다' }, 2), /1500자 이하/u);
});

test('step 3 deployment identity is supported without a step 1 marker', () => {
  const step3 = { step: 3, judgeIssuer: config.judgeIssuer, publicAppUrl: config.publicAppUrl };
  assert.deepEqual(deploymentIdentity(env, step3), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
  });
});

test('step 3 attack checks require anonymous list and item denial', async () => {
  const originalFetch = globalThis.fetch;
  const step3 = { step: 3, publicAppUrl: 'https://student-defense.vercel.app' };
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
    const results = await runAttackChecks(step3);
    assert.equal(results.length, 2);
    assert.match(results[0].observed, /401/u);
    assert.match(results[1].observed, /401/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 5 deployment identity is supported', () => {
  const step5 = { step: 5, judgeIssuer: config.judgeIssuer, publicAppUrl: config.publicAppUrl };
  assert.equal(deploymentIdentity(env, step5).step, 5);
});

test('step 5 attack check validates server denial and queryless original URL', async () => {
  const originalFetch = globalThis.fetch;
  const step5 = {
    step: 5,
    publicAppUrl: 'https://student-defense.vercel.app',
    originalApiUrl: 'https://project.supabase.co/rest/v1/learning_notes',
  };
  try {
    globalThis.fetch = async (url) => {
      const target = new URL(String(url));
      if (target.hostname === 'student-defense.vercel.app') {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401, headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ message: 'No API key found in request' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks(step5);
    assert.equal(results.length, 2);
    assert.match(results[0].observed, /401/u);
    assert.match(results[1].observed, /401/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('server note queries keep verified owner filtering', async () => {
  const source = await (await import('node:fs/promises')).readFile(
    new URL('../api/notes.js', import.meta.url), 'utf8');
  assert.ok((source.match(/\.eq\('owner_id', identity\.userId\)/gu) ?? []).length >= 4);
  assert.match(source, /owner_id:\s*identity\.userId/u);
});
