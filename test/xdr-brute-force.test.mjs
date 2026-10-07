import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { readAlerts, extractAlert } from '../xdr/brute-force/read-alerts.mjs';
import { createDecider } from '../xdr/brute-force/decide.mjs';
import { buildDenyCandidates, checkZTNAExtra } from '../xdr/brute-force/ztna-gate.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixturePath = join(root, 'xdr/fixtures/brute-force.json');
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
const patterns = JSON.parse(await readFile(join(root, 'xdr/brute-force/patterns.json'), 'utf8'));

test('읽기 모듈이 경보마다 5개 허용 필드만 추출하며 원본을 보존', async () => {
  const before = await readFile(fixturePath, 'utf8');
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['at', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  assert.equal(rows[0].sourceAddress, '203.0.113.10');
  assert.equal(await readFile(fixturePath, 'utf8'), before);
  const sensitive = extractAlert({
    timestamp: fixture.alerts[0].timestamp,
    data: { srcip: '203.0.113.1', srcuser: 'user01', password: 'DO_NOT_PRINT' },
    rule: { level: 8, description: '실패 password=hunter123 token=unsafe_sketch' },
  });
  assert.equal('password' in sensitive, false);
  assert.doesNotMatch(sensitive.description, /hunter123|unsafe_sketch/u);
});

test('모든 MITRE T1110 패턴에 조건과 한 줄의 근거가 있음', () => {
  assert.equal(patterns.technique, 'T1110');
  assert.ok(patterns.patterns.length >= 2);
  for (const p of patterns.patterns) {
    assert.match(p.name, /^[a-z][a-z0-9_]+$/u);
    assert.ok(Object.keys(p.condition).length);
    assert.match(p.evidence, /T1110/u);
    assert.equal(p.evidence.includes('\n'), false);
  }
});

test('명확 12 · 애매 7 · 정상 9 분리, Jev 질의는 애매한 경보에만', async () => {
  let jevCalls = 0;
  const decide = createDecider({ askJev: async () => { jevCalls += 1; return 0.99; } });
  const decisions = await Promise.all(fixture.alerts.map((alert) => decide(alert)));
  assert.deepEqual(decisions.reduce((acc, d) => {
    acc[d.action] += 1; return acc;
  }, { block: 0, alert: 0, record: 0 }), { block: 12, alert: 7, record: 9 });
  assert.equal(jevCalls, 7);
  assert.ok(decisions.every((d) => d.confidence >= 0 && d.confidence <= 1));
  assert.ok(decisions.filter((d) => d.action === 'alert').every((d) => d.confidence < 0.85));
  assert.ok(decisions.filter((d) => d.action === 'record').every((d) => d.confidence < 0.5));
});

test('Jev 미응답 · API 오류는 alert 0.65, 정상은 record', async () => {
  const missing = createDecider({ askJev: async () => null });
  const failed = createDecider({ askJev: async () => { throw new Error('failure'); } });
  for (const decide of [missing, failed]) {
    assert.deepEqual(await decide(fixture.alerts[10]), {
      action: 'alert', confidence: 0.65, reason: 'review_login_failures',
    });
    assert.equal((await decide(fixture.alerts[19])).action, 'record');
  }
});

test('ZTNA 추가 확인은 강한 경보만 후보로, 정상·공유 IP·만료시각은 통과', async () => {
  const decide = createDecider({ askJev: async () => null });
  const decisions = await Promise.all(fixture.alerts.map(async (a) => ({
    alertId: a.id, ...(await decide(a)),
  })));
  const rules = buildDenyCandidates(fixture.alerts, decisions);
  assert.equal(rules.length, 11); // bf-01/bf-02 share source and account.
  assert.ok(rules.every((r) => r.evidenceAlertIds.length >= 1
    && Date.parse(r.expiresAt) > Date.parse(r.startsAt)));
  assert.ok(rules.every((r) => r.evidenceAlertIds.every((id) => {
    const original = fixture.alerts.find((a) => a.id === id);
    return decisions.find((d) => d.alertId === original.id).action === 'block';
  })));
  const strong = fixture.alerts[0];
  const context = {
    verifiedByServer: true, sourceAddress: strong.data.srcip,
    account: strong.data.srcuser, at: strong.timestamp,
  };
  assert.equal(checkZTNAExtra({ upstreamDecision: 'allow', trustedContext: context, rules }).action, 'deny');
  assert.equal(checkZTNAExtra({ upstreamDecision: 'deny', trustedContext: context, rules }).action, 'preserve');
  assert.equal(checkZTNAExtra({ upstreamDecision: 'step_up', trustedContext: context, rules }).action, 'preserve');
  assert.equal(checkZTNAExtra({ upstreamDecision: 'allow', trustedContext: { ...context, verifiedByServer: false }, rules }).action, 'pass');
  assert.equal(checkZTNAExtra({ upstreamDecision: 'allow', trustedContext: { ...context, account: 'another-user' }, rules }).action, 'pass');
  assert.equal(checkZTNAExtra({ upstreamDecision: 'allow', trustedContext: { ...context, sourceAddress: '192.0.2.99' }, rules }).action, 'pass');
  assert.equal(checkZTNAExtra({ upstreamDecision: 'allow', trustedContext: { ...context, at: '2026-10-08T06:00:00+09:00' }, rules }).action, 'pass');
  // Even a forged block label cannot turn a normal event into a deny rule.
  const forged = decisions.map((d) => d.alertId === 'bf-20'
    ? { ...d, action: 'block', confidence: 0.99, reason: 'rapid_source_login_failures' } : d);
  assert.equal(buildDenyCandidates(fixture.alerts, forged).length, rules.length);
  for (const normalAlert of fixture.alerts.slice(19)) {
    const verdict = checkZTNAExtra({
      upstreamDecision: 'allow',
      trustedContext: {
        verifiedByServer: true, sourceAddress: normalAlert.data.srcip,
        account: normalAlert.data.srcuser, at: normalAlert.timestamp,
      },
      rules,
    });
    assert.equal(verdict.action, 'pass', normalAlert.id);
  }
  const normal = fixture.alerts[19];
  assert.equal(checkZTNAExtra({
    upstreamDecision: 'allow',
    trustedContext: {
      verifiedByServer: true, sourceAddress: normal.data.srcip,
      account: normal.data.srcuser, at: normal.timestamp,
    },
    rules,
  }).action, 'pass');
});
test('Wazuh 수준이 낮아도 강한 반복 증거는 차단하고 정상 성공은 제외', async () => {
  const decide = createDecider({ askJev: async () => null });
  const lowLevel = structuredClone(fixture.alerts[0]);
  lowLevel.rule.level = 6;
  assert.equal((await decide(lowLevel)).action, 'block');

  const english = {
    id: 'synthetic-en',
    timestamp: '2026-10-08T06:00:00+09:00',
    rule: { level: 6, description: '45 failed login attempts from the same IP within 2 minutes', mitre: ['T1110'] },
    data: { srcip: '192.0.2.110', srcuser: 'user99', failures: '45' },
  };
  assert.equal((await decide(english)).action, 'block');

  const success = structuredClone(fixture.alerts[0]);
  success.rule.description = '같은 주소에서 2분 안 로그인 실패 48건 뒤에 성공했습니다.';
  assert.equal((await decide(success)).action, 'alert');

  const weak = structuredClone(fixture.alerts[13]);
  weak.rule.mitre = [];
  assert.equal((await decide(weak)).action, 'alert');
  assert.equal((await decide(fixture.alerts[21])).action, 'record');
});

test('readAlerts의 정규화된 5필드 경보도 명확한 대량 실패를 탐지', async () => {
  const rows = await readAlerts();
  const decide = createDecider({ askJev: async () => null });
  assert.equal((await decide(rows[0])).action, 'block');
  assert.equal((await decide(rows[19])).action, 'record');
});
