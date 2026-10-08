import assert from 'node:assert/strict';
import { copyFile, mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { readAlerts, extractAlert } from '../xdr/brute-force/read-alerts.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';
import { matchStrongPattern } from '../xdr/brute-force/match.mjs';
import { respond } from '../xdr/brute-force/respond.mjs';
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

test('명확 10 · 애매 9 · 정상 9를 비동기 대기 없이 분리', () => {
  const decisions = fixture.alerts.map((alert) => decide(alert));
  assert.deepEqual(decisions.reduce((acc, d) => {
    acc[d.action] += 1; return acc;
  }, { block: 0, alert: 0, record: 0 }), { block: 10, alert: 9, record: 9 });
  assert.ok(decisions.every((result) => typeof result.then !== 'function'));
  assert.ok(decisions.every((result) => Object.keys(result).sort().join(',') === 'action,confidence,reason'));
  assert.ok(decisions.every((result) => !result.reason.includes('\n')));
  assert.ok(decisions.every((d) => d.confidence >= 0 && d.confidence <= 1));
  assert.ok(decisions.filter((d) => d.action === 'alert').every((d) => d.confidence < 0.85));
  assert.ok(decisions.filter((d) => d.action === 'record').every((d) => d.confidence < 0.5));
});

test('Jev 네트워크 없이 애매하면 alert 0.65, 정상은 record', () => {
  assert.deepEqual(decide(fixture.alerts[10]), {
    action: 'alert', confidence: 0.65, reason: 'review_login_failures',
  });
  assert.equal(decide(fixture.alerts[19]).action, 'record');
});

test('ZTNA 추가 확인은 강한 경보만 후보로, 정상·공유 IP·만료시각은 통과', async () => {
  const decisions = await Promise.all(fixture.alerts.map(async (a) => ({
    alertId: a.id, ...(await decide(a)),
  })));
  const rules = buildDenyCandidates(fixture.alerts, decisions);
  assert.equal(rules.length, 9); // bf-01/bf-02 share source and account.
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
  assert.equal((await decide(rows[0])).action, 'block');
  assert.equal((await decide(rows[19])).action, 'record');
});

test('심판 격리: decide.mjs 단일 파일을 의존성 없이 로딩하고 동기 판정', async () => {
  const sourcePath = join(root, 'xdr', 'brute-force', 'decide.mjs');
  const source = await readFile(sourcePath, 'utf8');
  assert.doesNotMatch(source, /^\s*(?:import\b|export\s+(?:\*|\{[^}]*\})\s+from\b)/mu);
  assert.doesNotMatch(source, /\b(?:require\s*\(|fetch\s*\(|process\.|XMLHttpRequest\b|node:(?:fs|net|crypto|http|https))/u);
  assert.equal((source.match(/\bexport\s+function\s+decide\s*\(/gu) || []).length, 1);
  const temp = await mkdtemp(join(tmpdir(), 'aleph-xdr-isolated-'));
  try {
    await copyFile(sourcePath, join(temp, 'decide.mjs'));
    const sample = [fixture.alerts[0], fixture.alerts[10], fixture.alerts[19]];
    const script = [
      'globalThis.fetch = () => { throw new Error("Network is disabled"); };',
      'const mod = await import("./decide.mjs");',
      'if (Object.keys(mod).join(",") !== "decide") throw new Error("Unexpected exports");',
      'const input = ' + JSON.stringify(sample) + ';',
      'const results = input.map((a) => mod.decide(a));',
      'if (results.some((r) => r && typeof r.then === "function")) throw new Error("Async response");',
      'process.stdout.write(JSON.stringify(results));',
    ].join('\n');
    const run = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
      cwd: temp, encoding: 'utf8', timeout: 3000,
      env: { PATH: process.env.PATH ?? '', JEV_API_KEY: 'dummy-no-network' },
    });
    assert.equal(run.status, 0, run.stderr || String(run.error));
    assert.equal(run.stderr, '');
    const results = JSON.parse(run.stdout);
    assert.deepEqual(results.map((r) => r.action), ['block', 'alert', 'record']);
    assert.ok(results.every((r) => Object.keys(r).sort().join(',') === 'action,confidence,reason'));
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('약한 단시간 실패/불규칙한 출발지 실패는 차단하지 않고 alert로 분류', () => {
  for (const id of ['bf-14', 'bf-18']) {
    const alert = fixture.alerts.find(item => item.id === id);
    assert.equal(decide(alert).action, 'alert', id);
    assert.equal(matchStrongPattern(alert), null, id);
  }
  for (const alert of fixture.alerts) {
    assert.equal(decide(alert).action === 'block', Boolean(matchStrongPattern(alert)), alert.id);
  }
});

test('respond가 alert만 기록하고 과거 block을 제거하며 재실행에 중복되지 않음', async () => {
  const tmp = await mkdtemp(join(tmpdir(), 'aleph-xdr-respond-'));
  try {
    await mkdir(join(tmp, 'xdr'), { recursive: true });
    const log = join(tmp, 'xdr', 'alerts.log');
    const unrelated = JSON.stringify({ moduleKey: 'web-injection', alertId: 'unrelated-01', action: 'alert' });
    const legacy = JSON.stringify({ moduleKey: 'brute-force', alertId: 'bf-14', action: 'block' });
    await writeFile(log, [unrelated, legacy].join('\n') + '\n');
    const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const first = await respond({ root: tmp, alerts: fixture.alerts, decisions });
    assert.equal(first.written, 9);
    assert.equal(first.preservedOther, 1);
    const once = await readFile(log, 'utf8');
    const rows = once.trim().split('\n').map(JSON.parse);
    assert.equal(rows.length, 10);
    assert.deepEqual(rows[0], JSON.parse(unrelated));
    const current = rows.filter(row => row.moduleKey === 'brute-force');
    assert.equal(current.length, 9);
    assert.ok(current.every(row => row.action === 'alert'));
    assert.ok(current.some(row => row.alertId === 'bf-14'));
    assert.ok(current.some(row => row.alertId === 'bf-18'));
    assert.ok(current.every(row => !('sourceAddress' in row) && !('account' in row)));
    await respond({ root: tmp, alerts: fixture.alerts, decisions });
    assert.equal(await readFile(log, 'utf8'), once);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test('Wazuh 일부 식별 정보가 누락된 모호한 실패는 alert, 정상 성공은 record', () => {
  const ambiguous = structuredClone(fixture.alerts[13]);
  delete ambiguous.timestamp;
  delete ambiguous.data.srcip;
  delete ambiguous.data.srcuser;
  assert.equal(decide(ambiguous).action, 'alert');
  assert.equal(matchStrongPattern(ambiguous), null);
  const normal = structuredClone(fixture.alerts[19]);
  delete normal.timestamp;
  assert.equal(decide(normal).action, 'record');
});
