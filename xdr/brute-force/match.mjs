import { readFileSync } from 'node:fs';
import { extractAlert } from './read-alerts.mjs';

const document = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
if (document.schema !== 'aleph.xdr.brute-force.patterns.v1'
  || document.technique !== 'T1110' || !Array.isArray(document.patterns)) {
  throw new Error('brute-force 패턴 구성이 올바르지 않습니다.');
}
const patternByName = new Map(document.patterns.map((p) => [p.name, p]));

export function failureCount(alert) {
  const raw = alert?.data?.count;
  if (typeof raw !== 'string' && typeof raw !== 'number') return 0;
  const value = String(raw);
  return /^\d{1,5}$/.test(value) ? Number(value) : 0;
}

export function hasT1110(alert) {
  return Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.some((id) => id === 'T1110' || /^T1110\.\d{3}$/.test(id));
}

export function isFailureDescription(text) {
  return /실패|같은 비밀번호.*(?:넣었|시도)|비밀번호.*(?:바꿔|추측)/u.test(text);
}

function withinShortWindow(text, minutes) {
  const windows = [...text.matchAll(/(\d{1,2})분/gu)].map((match) => Number(match[1]));
  return windows.some((value) => value > 0 && value <= minutes);
}

// Independently check the raw alert's trusted summary before accepting a block.
export function matchStrongPattern(alert) {
  const row = extractAlert(alert);
  const text = row.description;
  const count = failureCount(alert);
  if (!row.at || !row.sourceAddress || !row.account || !hasT1110(alert)
    || row.ruleLevel === null || !isFailureDescription(text)) return null;

  const matches = {
    rapid_source_login_failures: (p) => row.ruleLevel >= p.condition.minRuleLevel
      && count >= p.condition.minFailures
      && withinShortWindow(text, p.condition.maxMinutes),
    cross_account_password_spray: (p) => row.ruleLevel >= p.condition.minRuleLevel
      && /같은 비밀번호/u.test(text)
      && /여러 계정|서로 다른 계정|계정\s*\d+\s*개/u.test(text),
    regular_multi_account_failures: (p) => row.ruleLevel >= p.condition.minRuleLevel
      && count >= p.condition.minAccounts
      && /계정\s*\d+\s*개/u.test(text) && /같은 간격/u.test(text),
    iterative_password_guessing: (p) => row.ruleLevel >= p.condition.minRuleLevel
      && count >= p.condition.minFailures
      && /비밀번호/u.test(text) && /한 글자씩|조합을 바꿔|차례로 변경/u.test(text),
    sustained_failed_login_streak: (p) => row.ruleLevel >= p.condition.minRuleLevel
      && count >= p.condition.minFailures
      && /이어졌|연속|성공은 없습니다|성공 없음/u.test(text),
  };
  for (const pattern of document.patterns) {
    const test = matches[pattern.name];
    if (test && test(pattern)) return { name: pattern.name, confidence: pattern.confidence };
  }
  return null;
}

export function isSuspiciousFailure(alert) {
  const row = extractAlert(alert);
  const review = patternByName.get('review_login_failures');
  return Boolean(review && row.at && row.sourceAddress && row.account
    && hasT1110(alert) && row.ruleLevel >= review.condition.minRuleLevel
    && isFailureDescription(row.description));
}

export function weakPattern() {
  return patternByName.get('review_login_failures');
}