// Isolated judge entry point. No file, package, network or environment access.
// All pattern thresholds are embedded: the judge receives only this module.
const PATTERNS = Object.freeze([
  { name: 'rapid_source_login_failures', condition: { minFailures: 20, maxMinutes: 10, minRuleLevel: 10 }, confidence: 0.96 },
  { name: 'cross_account_password_spray', condition: { minRuleLevel: 10 }, confidence: 0.97 },
  { name: 'regular_multi_account_failures', condition: { minAccounts: 15, minRuleLevel: 10 }, confidence: 0.91 },
  { name: 'iterative_password_guessing', condition: { minFailures: 30, minRuleLevel: 10 }, confidence: 0.90 },
  { name: 'sustained_failed_login_streak', condition: { minFailures: 50, minRuleLevel: 11 }, confidence: 0.88 },
  { name: 'short_window_same_account_failures', condition: { minFailures: 5, maxMinutes: 10 }, confidence: 0.86 },
  { name: 'repeated_same_source_failures', condition: { minFailures: 8, minRuleLevel: 8 }, confidence: 0.85 },
  { name: 'review_login_failures', condition: { minFailures: 2, minRuleLevel: 5 }, confidence: 0.65 },
]);

function validIPv4(value) {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)) return false;
  return value.split('.').every((part) => Number(part) <= 255);
}

function validAddress(value) {
  if (typeof value !== 'string' || value.length > 45 || value.length === 0) return false;
  if (validIPv4(value)) return true;
  if (!value.includes(':') || !/^[a-fA-F0-9:.]+$/u.test(value)) return false;
  let normalized = value;
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    if (lastColon < 0 || !validIPv4(normalized.slice(lastColon + 1))) return false;
    normalized = normalized.slice(0, lastColon) + ':0:0';
  }
  const sides = normalized.split('::');
  if (sides.length > 2) return false;
  const parts = sides.flatMap((side) => side ? side.split(':') : []);
  if (parts.some((part) => !/^[a-fA-F0-9]{1,4}$/u.test(part))) return false;
  return sides.length === 2 ? parts.length < 8 : parts.length === 8;
}

function readRow(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return null;
  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const at = alert.timestamp ?? alert.at;
  const sourceAddress = data.srcip ?? alert.sourceAddress;
  const account = data.srcuser ?? alert.account;
  const level = alert.rule?.level ?? alert.ruleLevel;
  const description = alert.rule?.description ?? alert.description;
  return {
    at: typeof at === 'string' && Number.isFinite(Date.parse(at)) ? at : null,
    sourceAddress: validAddress(sourceAddress) ? sourceAddress : null,
    account: typeof account === 'string'
      && /^[a-z][a-z0-9._-]{0,47}$/iu.test(account)
      && !/^(?:password|token|secret|apikey)/iu.test(account) ? account : null,
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    // The description is inspected only. It is never returned or logged.
    description: typeof description === 'string' ? description.slice(0, 1024) : '',
  };
}

function failureCount(alert, description) {
  const raw = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const candidates = [
    raw.count, raw.failures, raw.failure_count, raw.failCount,
    raw.attempts, raw.login_failures, alert?.failedAttempts,
  ].filter((value) => (typeof value === 'string' || typeof value === 'number')
    && /^\d{1,5}$/u.test(String(value))).map(Number);
  if (candidates.length) return Math.max(...candidates);
  const expressions = [
    /(?:로그인|인증|비밀번호)?\s*실패(?:가|를|는|이)?\s*(\d{1,5})\s*(?:건|번|회)/giu,
    /(\d{1,5})\s*(?:건|번|회)\s*(?:로그인|인증)?\s*실패/giu,
    /(\d{1,5})\s*(?:failed|unsuccessful)\s*(?:login|sign[- ]?in|authentication|attempt)/giu,
  ];
  const extracted = expressions.flatMap((re) => [...description.matchAll(re)].map((match) => Number(match[1])));
  return extracted.length ? Math.max(...extracted) : 0;
}

function hasT1110(alert) {
  const raw = alert?.rule?.mitre ?? alert?.mitre;
  const labels = Array.isArray(raw) ? raw
    : Array.isArray(raw?.id) ? raw.id
      : typeof raw?.id === 'string' ? [raw.id] : [];
  return labels.some((id) => id === 'T1110' || /^T1110\.\d{3}$/u.test(id));
}

function hasFailedAuthentication(text) {
  return /실패|같은 비밀번호.*(?:넣었|시도)|비밀번호.*(?:바꿔|추측)|failed\s*(?:login|sign[- ]?in|authentication|password|attempts?)|(?:login|authentication)\s*fail|password\s*(?:guess|spray)/iu.test(text);
}

function hasSuccessAfterFailures(text) {
  const withoutNegation = text.replace(
    /성공(?:은|이)?\s*없(?:습니다|었(?:습니다)?|다)?|성공\s*없음|no\s+success(?:ful(?:\s+logins?)?)?|zero\s+successful\s+logins?/giu,
    '',
  );
  return /(?:뒤에|후에|이후)\s*성공|성공했|성공했습니다|로그인이\s*성공|변경이\s*성공|(?:login|sign[\s-]?in)\s*success|successfully\s+logged/iu.test(withoutNegation);
}

function timeWindowMinutes(text) {
  return [...text.matchAll(/(\d{1,3})\s*(초|분|시간|seconds?|secs?|minutes?|mins?|hours?)/giu)]
    .map((match) => /초|sec/iu.test(match[2]) ? Number(match[1]) / 60
      : /시간|hour/iu.test(match[2]) ? Number(match[1]) * 60 : Number(match[1]));
}

function strongPattern(alert, row) {
  if (!row?.at || !row.sourceAddress || !row.account || row.ruleLevel === null
    || !hasFailedAuthentication(row.description) || hasSuccessAfterFailures(row.description)) return null;
  const text = row.description;
  const count = failureCount(alert, text);
  const tagged = hasT1110(alert);
  const shortWindow = timeWindowMinutes(text).some((value) => value > 0 && value <= 10);
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

  for (const pattern of PATTERNS) {
    const p = pattern.condition;
    let matched = false;
    switch (pattern.name) {
      case 'rapid_source_login_failures':
        matched = count >= p.minFailures && shortWindow
          && (sameSource || sameAccount || tagged || row.ruleLevel >= p.minRuleLevel);
        break;
      case 'cross_account_password_spray':
        matched = spray && (tagged || row.ruleLevel >= p.minRuleLevel);
        break;
      case 'regular_multi_account_failures':
        matched = regular && accountCount >= p.minAccounts
          && sameSource && (tagged || row.ruleLevel >= p.minRuleLevel);
        break;
      case 'iterative_password_guessing':
        matched = count >= p.minFailures && iterative && (tagged || row.ruleLevel >= p.minRuleLevel);
        break;
      case 'sustained_failed_login_streak':
        matched = count >= p.minFailures && (streak || noSuccess)
          && (tagged || row.ruleLevel >= p.minRuleLevel);
        break;
      case 'short_window_same_account_failures':
        matched = count >= p.minFailures && shortWindow && sameAccount && tagged;
        break;
      case 'repeated_same_source_failures':
        matched = count >= p.minFailures && sameSource && tagged && row.ruleLevel >= p.minRuleLevel;
        break;
      default:
        break;
    }
    if (matched) return pattern;
  }
  return null;
}

// The only judge-facing export. It is synchronous and side-effect-free.
export function decide(alert) {
  const row = readRow(alert);
  if (row === null) {
    return { action: 'record', confidence: 0.1, reason: 'no_matching_t1110_pattern' };
  }
  const strong = strongPattern(alert, row);
  if (strong !== null) {
    return { action: 'block', confidence: strong.confidence, reason: strong.name };
  }
  const review = PATTERNS[PATTERNS.length - 1];
  if (row.at && row.sourceAddress && row.account && row.ruleLevel !== null
    && (hasT1110(alert) || row.ruleLevel >= review.condition.minRuleLevel)
    && hasFailedAuthentication(row.description)) {
    // No external AI response is available inside the judge. Fail open to
    // human alerting, never to automated address denial.
    return { action: 'alert', confidence: review.confidence, reason: review.name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_matching_t1110_pattern' };
}
