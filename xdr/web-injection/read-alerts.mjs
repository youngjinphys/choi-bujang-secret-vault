import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

const FIXTURE_URL = new URL('../fixtures/web-injection.json', import.meta.url);

// Fail closed on secret-bearing descriptions rather than echoing partial tokens.
export function sanitizeDescription(value) {
  if (typeof value !== 'string') return '';
  const limited = value.slice(0, 4096);
  if (/(?:password|passwd|pwd|secret|api[_-]?key|authorization|bearer|token|cookie|private[\s_-]*key|ghp_|github_pat_|sb_secret_|sb_publishable_|sk-proj-|eyJ[A-Za-z0-9_-]{12,}\.)/iu.test(limited)) {
    return '[REDACTED]';
  }
  return limited.replace(/[\r\n\t\u0000-\u001f]+/gu, ' ').slice(0, 512);
}

export function extractAlert(raw) {
  const address = raw?.data?.srcip ?? raw?.sourceAddress;
  const account = raw?.data?.srcuser ?? raw?.account;
  const time = raw?.timestamp ?? raw?.at;
  const level = raw?.rule?.level ?? raw?.ruleLevel;
  const description = raw?.rule?.description ?? raw?.description;
  return {
    at: typeof time === 'string' && Number.isFinite(Date.parse(time)) ? time : null,
    sourceAddress: typeof address === 'string' && isIP(address) ? address : null,
    account: typeof account === 'string'
      && /^[a-z][a-z0-9._-]{0,47}$/iu.test(account)
      && !/^(?:password|secret|token|api[_-]?key)/iu.test(account) ? account : null,
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: sanitizeDescription(description),
  };
}

export async function readAlerts(source = FIXTURE_URL) {
  const fixture = JSON.parse(await readFile(source, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
    || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('web-injection Wazuh 경보 묶음 형식이 아닙니다.');
  }
  const rows = fixture.alerts.map(extractAlert);
  if (rows.length !== fixture.alerts.length) {
    throw new Error('경보 건수와 추출한 줄 수가 다릅니다.');
  }
  return rows;
}