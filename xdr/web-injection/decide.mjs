// Isolated judge entry: all detection patterns are embedded here.
// This file exports only decide(alert), performs synchronous calculation,
// and does not touch files, packages, external services or global state.
const PATTERNS = Object.freeze([
  { name: 'repeated_sql_injection', condition: { minCount: 8, source: 'same_ip', signal: 'sql_syntax_or_explicit_injection_summary' }, confidence: 0.95 },
  { name: 'repeated_script_injection', condition: { minCount: 8, source: 'same_ip', signal: 'script_tag_or_explicit_insertion_summary' }, confidence: 0.94 },
  { name: 'repeated_path_traversal', condition: { minCount: 8, source: 'same_ip', signal: 'dotdot_path_or_explicit_traversal_summary' }, confidence: 0.93 },
  { name: 'repeated_command_delimiter', condition: { minCount: 8, source: 'same_ip', signal: 'command_delimiter_or_explicit_command_injection_summary' }, confidence: 0.90 },
  { name: 'review_suspicious_web_input', condition: { minCount: 1, signal: 'T1190_or_suspicious_single_request' }, confidence: 0.65 },
]);

function validAddress(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 45) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)) {
    return value.split('.').every((part) => part.length <= 3 && Number(part) <= 255);
  }
  if (!/^[A-Fa-f0-9:.]+$/u.test(value) || !value.includes(':')) return false;
  const double = value.split('::');
  if (double.length > 2) return false;
  const groups = double.flatMap((part) => part ? part.split(':') : []);
  if (groups.some((part) => !/^[A-Fa-f0-9]{1,4}$/u.test(part))) return false;
  return double.length === 2 ? groups.length < 8 : groups.length === 8;
}

function readRow(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return null;
  const data = alert.data && typeof alert.data === 'object' && !Array.isArray(alert.data) ? alert.data : {};
  const rule = alert.rule && typeof alert.rule === 'object' ? alert.rule : {};
  const when = alert.timestamp ?? alert.at;
  const address = data.srcip ?? alert.sourceAddress;
  const level = rule.level ?? alert.ruleLevel;
  const summary = rule.description ?? alert.description;
  const url = data.url ?? alert.url;
  const count = data.count ?? alert.count ?? alert.requestCount;
  const ids = rule.mitre ?? alert.mitre ?? [];
  const mitreIds = Array.isArray(ids) ? ids
    : Array.isArray(ids.id) ? ids.id
      : typeof ids.id === 'string' ? [ids.id] : [];
  const tagged = mitreIds.includes('T1190');
  let repetitions = 0;
  if ((typeof count === 'string' || typeof count === 'number')
    && /^\d{1,5}$/u.test(String(count))) {
    repetitions = Number(count);
  } else if (typeof summary === 'string') {
    const matches = [...summary.matchAll(/(\d{1,5})\s*(?:번|회|건)(?:\s|[이가을를은에.])/gu)];
    repetitions = matches.length ? Math.max(...matches.map((match) => Number(match[1]))) : 0;
  }
  let request = typeof url === 'string' ? url.slice(0, 2048) : '';
  // For encoded malicious input, decode twice at most; never evaluate it.
  for (let i = 0; i < 2; i += 1) {
    try {
      const next = decodeURIComponent(request);
      if (next === request) break;
      request = next.slice(0, 2048);
    } catch {
      break;
    }
  }
  return {
    at: typeof when === 'string' && Number.isFinite(Date.parse(when)) ? when : null,
    source: validAddress(address) ? address : null,
    level: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: typeof summary === 'string' ? summary.slice(0, 1024) : '',
    request,
    tagged,
    repetitions,
  };
}

function signalMatches(row) {
  const summary = row.description;
  const request = row.request;
  return {
    repeated_sql_injection:
      /SQL\s*(?:구문|표식|삽입|주입)|데이터베이스\s*조회.{0,40}(?:이어\s*붙|결합)|sql\s*injection/iu.test(summary)
      || /\bunion\s+(?:all\s+)?select\b|\bselect\b.{0,30}\bfrom\b|(?:'|")\s*(?:or|and)\s+\d+\s*=\s*\d+|\b(?:drop|alter)\s+table\b|;\s*(?:select|insert|delete|update)\b/iu.test(request),
    repeated_script_injection:
      /스크립트\s*(?:삽입|표식|태그|주입)|script\s*(?:tag|injection)|xss\s*(?:payload|attempt)/iu.test(summary)
      || /<\s*script\b|onerror\s*=|onload\s*=|javascript\s*:|<\s*svg\b.{0,60}\bonload\s*=/iu.test(request),
    repeated_path_traversal:
      /경로.{0,24}(?:거슬러|이탈|벗어|상위\s*디렉터리)|디렉터리.{0,24}(?:거슬러|이탈|탈출)|(?:path|directory)\s*traversal/iu.test(summary)
      || /(?:\.\.[\\/]){1,}/u.test(request),
    repeated_command_delimiter:
      /명령\s*구분자|명령\s*(?:삽입|주입)|command\s*(?:injection|separator)/iu.test(summary)
      || /;\s*(?:id|whoami|uname|curl|wget|sh|select|drop)\b|\$\([^)]{1,80}\)/iu.test(request),
  };
}

function clearlyNotExploit(summary) {
  return /(?:수업명|수업\s*단어|수업\s*공지|수업\s*제목|공격\s*표기(?:는|가)\s*없|삽입\s*표식은\s*아닙니다|반복(?:은|이)?\s*없|정상\s*조회|정상적인?\s*요청|ordinary\s*search|not\s+(?:an?\s+)?(?:attack|injection))/iu.test(summary);
}

// The single judge-facing export. No asynchronous response or side effects.
export function decide(alert) {
  const row = readRow(alert);
  if (row === null) {
    return { action: 'record', confidence: 0.1, reason: 'no_t1190_pattern' };
  }
  const corroborated = row.tagged || (row.level !== null && row.level >= 9);
  const repeated = /(?:반복|연속|같은\s*주소|한\s*주소|\d+\s*번|repeated|consecutive|same\s+(?:ip|source|address))/iu.test(row.description);
  if (row.at && row.source && corroborated && row.repetitions >= 8
    && repeated && !clearlyNotExploit(row.description)) {
    const signals = signalMatches(row);
    for (const pattern of PATTERNS) {
      if (pattern.condition.source === 'same_ip'
        && row.repetitions >= pattern.condition.minCount && signals[pattern.name]) {
        return { action: 'block', confidence: pattern.confidence, reason: pattern.name };
      }
    }
  }
  const review = PATTERNS[PATTERNS.length - 1];
  if (row.at && row.source && (
    row.tagged || (row.level !== null && row.level >= 5 && (
      /(?:sql|스크립트|script|주입|삽입|이상한|경로|구분\s*문자|따옴표|select|traversal|injection)/iu.test(row.description)
      || Object.values(signalMatches(row)).some(Boolean)
    ))
  )) {
    return { action: 'alert', confidence: review.confidence, reason: review.name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_t1190_pattern' };
}