import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { extractAlert, sanitizeDescription } from './read-alerts.mjs';

const document = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
if (document.schema !== 'aleph.xdr.brute-force.patterns.v1'
  || document.technique !== 'T1110' || !Array.isArray(document.patterns)) {
  throw new Error('brute-force 패턴 구성이 올바르지 않습니다.');
}
const patternByName = new Map(document.patterns.map((p) => [p.name, p]));

function rowOf(alert) {
  if (alert && Object.hasOwn(alert, 'sourceAddress')) {
    // Normalized readAlerts() output, still checked against five-field contract.
    const at = typeof alert.at === 'string' && Number.isFinite(Date.parse(alert.at)) ? alert.at : null;
    const sourceAddress = typeof alert.sourceAddress === 'string'
      && isIP(alert.sourceAddress) ? alert.sourceAddress : null;
    const account = typeof alert.account === 'string'
      && /^[a-z][a-z0-9._-]{0,47}$/iu.test(alert.account)
      && !/^(?:password|token|secret|apikey)/iu.test(alert.account)
      ? alert.account : null;
    const level = alert.ruleLevel;
    return {
      at, sourceAddress, account,
      ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
      description: sanitizeDescription(alert.description),
    };
  }
  return extractAlert(alert);
}

export function failureCount(alert) {
  const raw = alert?.data || {};
  const numeric = [
    raw.count, raw.failures, raw.failure_count, raw.failCount,
    raw.attempts, raw.login_failures, alert?.failedAttempts,
  ].filter(value => (typeof value === 'string' || typeof value === 'number')
    && /^\d{1,5}$/.test(String(value))).map(Number);
  if (numeric.length) return Math.max(...numeric);
  // Textual counts must be attached to failures, not to account counts.
  const description = String(alert?.rule?.description ?? alert?.description ?? '');
  const patterns = [
    /(?:로그인|인증|비밀번호)?\s*실패(?:가|를|는|이)?\s*(\d{1,5})\s*(?:건|번|회)/giu,
    /(\d{1,5})\s*(?:건|번|회)\s*(?:로그인|인증)?\s*실패/giu,
    /(\d{1,5})\s*(?:failed|unsuccessful)\s*(?:login|sign[- ]?in|authentication|attempt)/giu,
  ];
  const values = patterns.flatMap(re => [...description.matchAll(re)].map(m => Number(m[1])));
  return values.length ? Math.max(...values) : 0;
}

export function hasT1110(alert) {
  return Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.some((id) => id === 'T1110' || /^T1110\.\d{3}$/.test(id));
}

export function isFailureDescription(text) {
  return /실패|같은 비밀번호.*(?:넣었|시도)|비밀번호.*(?:바꿔|추측)|failed\s*(?:login|sign[- ]?in|authentication|password|attempts?)|(?:login|authentication)\s*fail|password\s*(?:guess|spray)/iu.test(text);
}

function withinShortWindow(text, minutes) {
  const windows = [...text.matchAll(/(\d{1,2})분/gu)].map((match) => Number(match[1]));
  return windows.some((value) => value > 0 && value <= minutes);
}

// Independently check the raw alert's trusted summary before accepting a block.
export function matchStrongPattern(alert) {
  const row = rowOf(alert);
  const text = row.description;
  const count = failureCount(alert);
  const tagged = hasT1110(alert);
  if (!row.at || !row.sourceAddress || !row.account || row.ruleLevel === null
    || !isFailureDescription(text)) return null;

  // A successful login following minor mistakes is not an automatic deny.
  // "성공은 없습니다" and "no success" are negative statements, not success.
  const withoutNoSuccess = text.replace(
    /성공(?:은|이)?\s*없(?:습니다|었(?:습니다)?|다)?|성공\s*없음|no\s+success(?:ful(?:\s+logins?)?)?|zero\s+successful\s+logins?/giu, '',
  );
  if (/(?:뒤에|후에|이후)\s*성공|성공했|성공했습니다|로그인이\s*성공|변경이\s*성공|(?:login|sign[\s-]?in)\s*success|successfully\s+logged/iu.test(withoutNoSuccess)) return null;

  const windows = [...text.matchAll(/(\d{1,3})\s*(초|분|시간|seconds?|secs?|minutes?|mins?|hours?)/giu)]
    .map(m => /초|sec/iu.test(m[2]) ? Number(m[1]) / 60
      : /시간|hour/iu.test(m[2]) ? Number(m[1]) * 60 : Number(m[1]));
  const shortWindow = windows.some(value => value > 0 && value <= 10);
  const sameSource = /(?:같은|동일(?:한)?)\s*(?:주소|IP)|한\s*주소|same\s*(?:IP|source|address)|from\s+(?:one|the\s+same)\s*(?:IP|source|address)/iu.test(text);
  const sameAccount = /(?:같은|동일(?:한)?)\s*(?:계정|사용자)|한\s*계정|same\s*(?:account|user)/iu.test(text);
  const spray = /같은\s*비밀번호|동일한?\s*비밀번호|same\s+password|identical\s+password|password\s*spray/iu.test(text)
    && /여러\s*계정|서로\s*다른\s*계정|계정\s*\d+\s*개|(?:multiple|different)\s+(?:accounts?|users?)/iu.test(text);
  const regular = /같은\s*간격|일정한\s*간격|regular\s+intervals?/iu.test(text)
    && /계정\s*\d+\s*개|(?:\d+)\s*(?:accounts?|users?)/iu.test(text);
  const accountMatch = /계정\s*(\d+)\s*개|(\d+)\s*(?:accounts?|users?)/iu.exec(text);
  const accountCount = accountMatch ? Number(accountMatch[1] ?? accountMatch[2]) : 0;
  const iterative = /비밀번호.{0,35}(?:한\s*글자씩|바꿔|변형|추측)|password.{0,35}(?:guess|variation|changed)/iu.test(text);
  const streak = /연속|이어졌|연달아|쌓였|consecutive|repeated|in\s+a\s+row/iu.test(text);
  const noSuccess = /성공(?:은|이)?\s*없|성공\s*없음|no\s+success|zero\s+successful/iu.test(text);

  const matches = {
    rapid_source_login_failures: (p) => count >= p.condition.minFailures
      && shortWindow && (sameSource || sameAccount || tagged || row.ruleLevel >= 10),
    cross_account_password_spray: (p) => spray && (tagged || row.ruleLevel >= p.condition.minRuleLevel),
    regular_multi_account_failures: (p) => regular && accountCount >= p.condition.minAccounts
      && sameSource && (tagged || row.ruleLevel >= 10),
    iterative_password_guessing: (p) => count >= p.condition.minFailures
      && iterative && (tagged || row.ruleLevel >= p.condition.minRuleLevel),
    sustained_failed_login_streak: (p) => count >= p.condition.minFailures
      && (streak || noSuccess) && (tagged || row.ruleLevel >= p.condition.minRuleLevel),
  };
  for (const pattern of document.patterns) {
    const test = matches[pattern.name];
    if (test && test(pattern)) return { name: pattern.name, confidence: pattern.confidence };
  }
  return null;
}

export function isSuspiciousFailure(alert) {
  const row = rowOf(alert);
  const review = patternByName.get('review_login_failures');
  return Boolean(review
    && (hasT1110(alert) || (row.ruleLevel !== null && row.ruleLevel >= review.condition.minRuleLevel))
    && isFailureDescription(row.description));
}

export function weakPattern() {
  return patternByName.get('review_login_failures');
}