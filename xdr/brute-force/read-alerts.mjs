import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

const FIXTURE = new URL('../fixtures/brute-force.json', import.meta.url);

// Project only the approved fields. Never spread an untrusted Wazuh data object.
export function sanitizeDescription(value) {
  if (typeof value !== 'string') return '';
  return value.slice(0, 2048)
    .replace(/-----BEGIN [\s\S]*?PRIVATE KEY-----[\s\S]*?-----END [\s\S]*?PRIVATE KEY-----/gi, '[REDACTED]')
    .replace(/\bBearer\s+[^\s;,]+/gi, '[REDACTED]')
    .replace(/\b(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*["']?[^\s;,\"']+/gi, '[REDACTED]')
    .replace(/\b(?:sk-|ghp_|github_pat_|sb_secret_|sb_publishable_)[A-Za-z0-9_-]{8,}/g, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{48,}\b/g, '[REDACTED]')
    .replace(/[\r\n\t]+/g, ' ')
    .slice(0, 512);
}

export function extractAlert(alert) {
  const address = alert?.data?.srcip;
  const account = alert?.data?.srcuser;
  const safeAccount = typeof account === 'string'
    && /^[a-z][a-z0-9._-]{0,47}$/i.test(account)
    && !/^(?:password|token|secret|apikey)/i.test(account) ? account : null;
  const level = alert?.rule?.level;
  const at = alert?.timestamp;
  return {
    at: typeof at === 'string' && Number.isFinite(Date.parse(at)) ? at : null,
    sourceAddress: typeof address === 'string' && isIP(address) ? address : null,
    account: safeAccount,
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: sanitizeDescription(alert?.rule?.description),
  };
}

export async function readAlerts(file = FIXTURE) {
  const input = JSON.parse(await readFile(file, 'utf8'));
  if (input?.schema !== 'aleph.xdr.fixture.v1'
    || input.moduleKey !== 'brute-force'
    || !Array.isArray(input.alerts)) {
    throw new Error('brute-force 경보 묶음 형식이 아닙니다.');
  }
  const rows = input.alerts.map(extractAlert);
  if (rows.length !== input.alerts.length) {
    throw new Error('경보 건수와 추출한 행 수가 다릅니다.');
  }
  return rows;
}