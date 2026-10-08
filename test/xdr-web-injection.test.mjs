import assert from 'node:assert/strict';
import { copyFile, mkdtemp, readFile, rm, mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { decide } from '../xdr/web-injection/decide.mjs';
import { readAlerts, extractAlert } from '../xdr/web-injection/read-alerts.mjs';
import { buildDenyCandidates, checkZTNAExtra, respondToDecisions } from '../xdr/web-injection/respond.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixturePath = join(root, 'xdr/fixtures/web-injection.json');
const fixtureText = await readFile(fixturePath, 'utf8');
const fixture = JSON.parse(fixtureText);
const patterns = JSON.parse(await readFile(join(root, 'xdr/web-injection/patterns.json'), 'utf8'));
const cases = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decide(alert) }));

function countsOf(decisions) {
  return decisions.reduce((acc, decision) => {
    acc[decision.action] += 1;
    return acc;
  }, { block: 0, alert: 0, record: 0 });
}

test('원본 유지 · 정확히 26줄 · 허용된 5개 필드만 추출하고 비밀값 마스킹', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['at', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  assert.equal(rows[0].sourceAddress, fixture.alerts[0].data.srcip);
  assert.equal(rows[0].account, null);
  assert.equal(rows[17].account, fixture.alerts[17].data.srcuser);
  const sample = structuredClone(fixture.alerts[0]);
  sample.data.extraSecret = 'ignore_extra_field';
  sample.rule.description = 'SQL attack ' + 'password' + '=' + 'sentinel_should_not_echo';
  const projected = extractAlert(sample);
  assert.equal('extraSecret' in projected, false);
  assert.equal(projected.description, '[REDACTED]');
  assert.equal(await readFile(fixturePath, 'utf8'), fixtureText);
});

test('MITRE T1190 패턴의 조건·확신도·한 줄의 근거가 모두 존재', () => {
  assert.equal(patterns.technique, 'T1190');
  assert.ok(patterns.patterns.length >= 4);
  const seen = new Set();
  for (const p of patterns.patterns) {
    assert.match(p.name, /^[a-z][a-z0-9_]+$/u);
    assert.equal(seen.has(p.name), false);
    seen.add(p.name);
    assert.ok(p.condition && typeof p.condition === 'object');
    assert.ok(typeof p.condition.signal === 'string' && p.condition.signal);
    assert.match(p.evidence, /T1190/u);
    assert.equal(p.evidence.includes('\n'), false);
    assert.ok(p.confidence >= 0 && p.confidence <= 1);
  }
});

test('분류는 명확 8 · 애매 9 · 정상 9이며 정상 이벤트 차단 0', async () => {
  assert.deepEqual(countsOf(cases), { block: 8, alert: 9, record: 9 });
  assert.ok(cases.every((d) => Object.keys(d).sort().join(',') === 'action,alertId,confidence,reason'));
  assert.ok(cases.every((d) => !d.reason.includes('\n') && d.confidence >= 0 && d.confidence <= 1));
  assert.ok(cases.filter((d) => d.action === 'block').every((d) => d.confidence >= 0.85));
  assert.ok(cases.filter((d) => d.action === 'alert').every((d) => d.confidence >= 0.5 && d.confidence < 0.85));
  assert.ok(cases.filter((d) => d.action === 'record').every((d) => d.confidence < 0.5));
  assert.ok(fixture.alerts.slice(17).every((a) => decide(a).action === 'record'));
  assert.ok((await readAlerts()).slice(17).every((row) => decide(row).action === 'record'));
});

test('단발 SQL/스크립트 용어, 정상 수업명, 악성 문구 위조는 block 안 함', () => {
  const sqlOnce = structuredClone(fixture.alerts[0]);
  sqlOnce.data.count = '1';
  assert.equal(decide(sqlOnce).action, 'alert');
  const scriptWord = structuredClone(fixture.alerts[10]);
  scriptWord.rule.level = 12;
  scriptWord.data.count = '30';
  assert.notEqual(decide(scriptWord).action, 'block');
  const className = structuredClone(fixture.alerts[9]);
  className.data.count = '25';
  className.rule.level = 12;
  assert.notEqual(decide(className).action, 'block');
  const untagged = structuredClone(fixture.alerts[0]);
  untagged.rule.mitre = [];
  untagged.rule.level = 3;
  assert.notEqual(decide(untagged).action, 'block');
  assert.equal(decide(null).action, 'record');
});

test('문자열이 아닌 비정상 경보와 임의 계정이 있어도 판정은 동기식·3필드', () => {
  const event = { timestamp: '2026-10-08T12:00:00+09:00',
    rule: { level: 11, mitre: ['T1190'], description: 'SQL 구문 같은 주소에서 12번 반복' },
    data: { srcip: '203.0.113.40', count: '12', srcuser: 17 } };
  const answer = decide(event);
  assert.equal(answer.action, 'block');
  assert.deepEqual(Object.keys(answer).sort(), ['action', 'confidence', 'reason']);
  assert.equal('then' in answer, false);
});

test('심판 격리: decide.mjs 파일 하나만 복사하고 외부 네트워크 없이 동기 실행', async () => {
  const sourcePath = join(root, 'xdr/web-injection/decide.mjs');
  const source = await readFile(sourcePath, 'utf8');
  assert.doesNotMatch(source, /^\s*(?:import\b|export\s+(?:\*|\{[^}]*\})\s+from\b)/mu);
  assert.doesNotMatch(source, /\b(?:require|fetch|process|XMLHttpRequest|node:fs|node:crypto|node:net)\b/u);
  assert.match(source, /const\s+PATTERNS\s*=/u);
  for (const p of patterns.patterns) {
    assert.ok(source.includes("name: '" + p.name + "'"), p.name);
    assert.ok(source.includes('confidence: ' + p.confidence), String(p.confidence));
  }
  assert.equal((source.match(/\bexport\s+function\s+decide\s*\(/gu) || []).length, 1);
  const temp = await mkdtemp(join(tmpdir(), 'aleph-xdr02-isolated-'));
  try {
    await copyFile(sourcePath, join(temp, 'decide.mjs'));
    const sample = [fixture.alerts[0], fixture.alerts[8], fixture.alerts[17]];
    const script = [
      'globalThis.fetch = () => { throw new Error("network disabled"); };',
      'const mod = await import("./decide.mjs");',
      'if (Object.keys(mod).join(",") !== "decide") throw new Error("Unexpected exports");',
      'const inputs = ' + JSON.stringify(sample) + ';',
      'const out = inputs.map((item) => mod.decide(item));',
      'if (out.some((r) => r && typeof r.then === "function")) throw new Error("async answer");',
      'process.stdout.write(JSON.stringify(out));',
    ].join('\n');
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
      cwd: temp, encoding: 'utf8', timeout: 4000,
      env: { PATH: process.env.PATH ?? '' },
    });
    assert.equal(result.status, 0, result.stderr || String(result.error));
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout).map((r) => r.action), ['block', 'alert', 'record']);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('ZTNA 추가 규칙은 신뢰된 IP + 동일 경로 + 유효 기간만 거부', () => {
  const candidates = buildDenyCandidates(fixture.alerts, cases);
  assert.equal(candidates.length, 8);
  assert.ok(candidates.every((c) => c.evidenceAlertIds.length > 0
    && c.confidence >= 0.85 && Date.parse(c.expiresAt) > Date.parse(c.startsAt)));
  const event = fixture.alerts[0];
  const trusted = {
    verifiedByServer: true,
    sourceAddress: event.data.srcip,
    path: new URL(event.data.url, 'https://offline.invalid').pathname,
    at: event.timestamp,
  };
  const argument = { upstreamDecision: 'allow', trustedContext: trusted, rules: candidates };
  assert.equal(checkZTNAExtra(argument).action, 'deny');
  assert.equal(checkZTNAExtra({ ...argument, upstreamDecision: 'deny' }).action, 'preserve');
  assert.equal(checkZTNAExtra({ ...argument, upstreamDecision: 'step_up' }).action, 'preserve');
  assert.equal(checkZTNAExtra({ ...argument, trustedContext: { ...trusted, verifiedByServer: false } }).action, 'pass');
  assert.equal(checkZTNAExtra({ ...argument, trustedContext: { ...trusted, path: '/unrelated' } }).action, 'pass');
  assert.equal(checkZTNAExtra({ ...argument, trustedContext: { ...trusted, at: '2026-10-08T12:00:00+09:00' } }).action, 'pass');
  for (const normal of fixture.alerts.slice(17)) {
    const verdict = checkZTNAExtra({
      upstreamDecision: 'allow', rules: candidates,
      trustedContext: {
        verifiedByServer: true, sourceAddress: normal.data.srcip,
        path: new URL(normal.data.url, 'https://offline.invalid').pathname, at: normal.timestamp,
      },
    });
    assert.equal(verdict.action, 'pass', normal.id);
  }
  const fake = cases.map((d) => d.alertId === 'wi-18'
    ? { ...d, action: 'block', confidence: 0.99, reason: 'repeated_sql_injection' } : d);
  assert.equal(buildDenyCandidates(fixture.alerts, fake).length, candidates.length);
  const shared = structuredClone(fixture.alerts[17]);
  shared.data.srcip = event.data.srcip;
  const withSharedNormal = [...fixture.alerts, shared];
  const withDecision = [...cases, { alertId: 'wi-18-shadow', ...decide(shared) }];
  withSharedNormal[withSharedNormal.length - 1].id = 'wi-18-shadow';
  assert.equal(buildDenyCandidates(withSharedNormal, withDecision).some((r) => r.sourceAddress === event.data.srcip), false);
});

test('respond는 로컬 후보 파일을 만들고 알림 로그를 중복 없이 추가하며 다른 모듈 로그 보존', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-xdr02-respond-'));
  try {
    await mkdir(join(dir, 'xdr'), { recursive: true });
    const existing = JSON.stringify({
      at: '2026-09-27T09:12:01+09:00',
      moduleKey: 'brute-force', alertId: 'bf-01',
      action: 'block', reason: 'rapid_source_login_failures',
    }) + '\n';
    await writeFile(join(dir, 'xdr/alerts.log'), existing);
    const first = await respondToDecisions({ root: dir, alerts: fixture.alerts, decisions: cases });
    assert.equal(first.length, 8);
    const once = await readFile(join(dir, 'xdr/alerts.log'), 'utf8');
    const logs = once.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(logs.filter((line) => line.moduleKey === 'web-injection').length, 17);
    assert.equal(logs.filter((line) => line.moduleKey === 'brute-force').length, 1);
    assert.ok(logs.every((line) => !('url' in line) && !('sourceAddress' in line) && !('account' in line)));
    await respondToDecisions({ root: dir, alerts: fixture.alerts, decisions: cases });
    assert.equal(await readFile(join(dir, 'xdr/alerts.log'), 'utf8'), once);
    const policy = JSON.parse(await readFile(join(dir, 'xdr/web-injection/deny-rules.json'), 'utf8'));
    assert.equal(policy.mode, 'simulation_only');
    assert.equal(policy.rules.length, 8);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});