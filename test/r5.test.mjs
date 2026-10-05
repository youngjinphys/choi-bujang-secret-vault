import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

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
      if (path === '/data.json') return new Response(JSON.stringify({ notes: [] }), { status: 200 });
      if (path === '/aleph.json') {
        return new Response(JSON.stringify({ schema: 'aleph.defense.deployment.v1', step: 2 }), { status: 200 });
      }
      if (path === '/api/notes') {
        return new Response(JSON.stringify({ notes: [{}, {}, {}, {}] }), { status: 200 });
      }
      return new Response('', { status: 404 });
    };
    const results = await runAttackChecks(step2);
    assert.equal(results.length, 3);
    assert.match(results[0].observed, /표시가 없고/u);
    assert.match(results[1].observed, /표시가 없음/u);
    assert.match(results[2].observed, /4건/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
