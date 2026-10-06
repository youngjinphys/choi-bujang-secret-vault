import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { NOTE_ROUTES, validateAllowedRoutes, validateOriginalApiUrl } from '../scripts/config-contract.mjs';
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
  const step3 = { step: 3, judgeIssuer: config.judgeIssuer, publicAppUrl: config.publicAppUrl, allowedRoutes: [...NOTE_ROUTES] };
  assert.deepEqual(deploymentIdentity(env, step3), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    allowedRoutes: step3.allowedRoutes,
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

test('step 5 deployment identity exposes only a queryless HTTPS original API URL', () => {
  const step5 = {
    step: 5,
    judgeIssuer: config.judgeIssuer,
    publicAppUrl: config.publicAppUrl,
    identityProvider: { issuer: 'https://project.supabase.co/auth/v1' },
    allowedRoutes: [...NOTE_ROUTES],
    originalApiUrl: 'https://project.supabase.co/rest/v1/learning_notes',
  };
  assert.deepEqual(deploymentIdentity(env, step5), {
    schema: 'aleph.defense.deployment.v1',
    step: 5,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    allowedRoutes: step5.allowedRoutes,
    originalApiUrl: step5.originalApiUrl,
  });
  assert.throws(() => deploymentIdentity(env, { ...step5, originalApiUrl: 'http://project.supabase.co/rest/v1/learning_notes' }));
  assert.throws(() => deploymentIdentity(env, { ...step5, originalApiUrl: 'https://project.supabase.co/rest/v1/learning_notes?select=*' }));
  assert.throws(() => deploymentIdentity(env, { ...step5, originalApiUrl: 'https://other.supabase.co/rest/v1/learning_notes' }));
  assert.throws(() => deploymentIdentity(env, { ...step5, allowedRoutes: ['GET /api/notes', 'GET /api/notes/:id'] }));
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
      if (target.hostname === 'student-defense.vercel.app' && target.pathname === '/api/notes') {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401, headers: { 'content-type': 'application/json' },
        });
      }
      if (target.hostname === 'student-defense.vercel.app' && target.pathname === '/aleph.json') {
        return new Response(JSON.stringify({
          step: 5,
          originalApiUrl: step5.originalApiUrl,
          allowedRoutes: ['/api/notes'],
        }), {
          status: 200, headers: { 'content-type': 'application/json' },
        });
      }
      if (target.hostname === 'student-defense.vercel.app' && target.pathname === '/') {
        return new Response('<!doctype html><title>clean</title>', {
          status: 200,
          headers: { 'content-type': 'text/html', 'x-content-type-options': 'nosniff' },
        });
      }
      return new Response(JSON.stringify({ message: 'No API key found in request' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks(step5);
    assert.equal(results.length, 6);
    assert.match(results[0].observed, /401/u);
    assert.match(results[1].observed, /일치/u);
    assert.match(results[2].observed, /경로/u);
    assert.match(results[3].observed, /nosniff/u);
    assert.match(results[4].observed, /공개 키 패턴이 없음/u);
    assert.match(results[5].observed, /401/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('server note queries keep verified owner filtering', async () => {
  const source = await (await import('node:fs/promises')).readFile(
    new URL('../api/notes.js', import.meta.url), 'utf8');
  assert.match(source, /data\.owner_id !== userId/u);
  assert.match(source, /\.eq\('owner_id', identity\.userId\)/u);
  assert.match(source, /owner_id:\s*identity\.userId/u);
});

test('step 4 deployment identity is supported', () => {
  const step4 = { step: 4, judgeIssuer: config.judgeIssuer, publicAppUrl: config.publicAppUrl, allowedRoutes: [...NOTE_ROUTES] };
  assert.equal(deploymentIdentity(env, step4).step, 4);
});

test('step 4 attack checks keep anonymous requests denied', async () => {
  const originalFetch = globalThis.fetch;
  const step4 = { step: 4, publicAppUrl: 'https://student-defense.vercel.app' };
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers: { 'content-type': 'application/json' },
    });
    const results = await runAttackChecks(step4);
    assert.equal(results.length, 2);
    assert.match(results[0].observed, /401/u);
    assert.match(results[1].observed, /401/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 4 server API enforces verified owner boundaries', async () => {
  const source = await (await import('node:fs/promises')).readFile(
    new URL('../api/notes.js', import.meta.url), 'utf8');
  assert.match(source, /data\.owner_id !== userId/u);
  assert.match(source, /owner_id:\s*identity\.userId/u);
  assert.match(source, /\.eq\('owner_id', identity\.userId\)/u);
  assert.match(source, /new Set\(\['title', 'body'\]\)/u);
});

test('step 5 config contract keeps canonical path-only routes and bound origin', () => {
  const checked = {
    step: 5,
    identityProvider: { issuer: 'https://project.supabase.co/auth/v1' },
    allowedRoutes: [...NOTE_ROUTES],
    originalApiUrl: 'https://project.supabase.co/rest/v1/learning_notes',
  };
  assert.deepEqual(validateAllowedRoutes(checked), NOTE_ROUTES);
  assert.equal(validateOriginalApiUrl(checked), checked.originalApiUrl);
  assert.throws(() => validateAllowedRoutes({ ...checked, allowedRoutes: ['GET /api/notes', '/api/notes/:id'] }));
  assert.throws(() => validateOriginalApiUrl({ ...checked, originalApiUrl: 'https://evil.example/rest/v1/learning_notes' }));
});

test('step 5 browser code contains no Supabase public API key and uses server auth routes', async () => {
  const source = await (await import('node:fs/promises')).readFile(
    new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /sb_publishable_[A-Za-z0-9_-]+/u);
  assert.doesNotMatch(source, /createClient\s*\(/u);
  assert.match(source, /\/api\/auth\/\$\{action\}/u);
  assert.match(source, /\/api\/notes/u);
});

test('root response is configured with nosniff', async () => {
  const source = await (await import('node:fs/promises')).readFile(
    new URL('../vercel.json', import.meta.url), 'utf8');
  const config = JSON.parse(source);
  const root = config.headers.find((entry) => entry.source === '/');
  assert.ok(root);
  assert.equal(root.headers.find((header) => header.key === 'X-Content-Type-Options')?.value, 'nosniff');
});
