import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { decide } from './decide.mjs';
import { extractAlert } from './read-alerts.mjs';

const RULE_TTL_MS = 15 * 60 * 1000;

function safeRoute(url) {
  if (typeof url !== 'string' || url.length > 2048 || !url.startsWith('/')) return null;
  try {
    const parsed = new URL(url, 'https://offline.invalid');
    if (parsed.origin !== 'https://offline.invalid'
      || !parsed.pathname.startsWith('/') || parsed.pathname.length > 256) return null;
    return parsed.pathname; // Drop queries, fragments, credentials, and payloads.
  } catch {
    return null;
  }
}

function corroboratedDecision(alert, proposal) {
  const local = decide(alert);
  return proposal?.action === 'block'
    && proposal.confidence >= 0.85
    && local.action === 'block'
    && proposal.reason === local.reason
    && proposal.confidence === local.confidence
    ? local : null;
}

// Produce a separate, offline candidate set. An IP alone is not enough to
// override any authorization policy or deny an unrelated route.
export function buildDenyCandidates(alerts, decisions) {
  if (!Array.isArray(alerts) || !Array.isArray(decisions)
    || alerts.length !== decisions.length) {
    throw new Error('경보와 판정 건수가 일치하지 않습니다.');
  }
  const decisionsById = new Map(decisions.map((item) => [item.alertId, item]));
  // Conservative NAT protection: an IP that also generates normal evidence
  // is not promoted to an address-blocking candidate in this fixture.
  const normalSources = new Set();
  for (const alert of alerts) {
    if (!alert?.data?.srcip || !isIP(alert.data.srcip)) continue;
    if (decide(alert).action === 'record') normalSources.add(alert.data.srcip);
  }
  const grouped = new Map();
  for (const alert of alerts) {
    if (!/^wi-[A-Za-z0-9-]{1,40}$/u.test(alert?.id || '')) continue;
    const outcome = corroboratedDecision(alert, decisionsById.get(alert.id));
    if (!outcome) continue;
    const row = extractAlert(alert);
    const sourceAddress = row.sourceAddress;
    const path = safeRoute(alert?.data?.url);
    const observedAt = Date.parse(row.at);
    if (!sourceAddress || !path || !Number.isFinite(observedAt)
      || normalSources.has(sourceAddress)) continue;
    const key = sourceAddress + '\0' + path;
    const expires = observedAt + RULE_TTL_MS;
    if (!Number.isFinite(expires)) continue;
    const known = grouped.get(key);
    if (known) {
      if (!known.evidenceAlertIds.includes(alert.id)) known.evidenceAlertIds.push(alert.id);
      if (Date.parse(known.expiresAt) < expires) known.expiresAt = new Date(expires).toISOString();
      if (Date.parse(known.startsAt) > observedAt) known.startsAt = row.at;
      known.confidence = Math.max(known.confidence, outcome.confidence);
      if (!known.patterns.includes(outcome.reason)) known.patterns.push(outcome.reason);
    } else {
      grouped.set(key, {
        id: 'xdr.t1190.' + createHash('sha256').update(key).digest('hex').slice(0, 16),
        sourceAddress,
        path,
        startsAt: row.at,
        expiresAt: new Date(expires).toISOString(),
        evidenceAlertIds: [alert.id],
        patterns: [outcome.reason],
        confidence: outcome.confidence,
      });
    }
  }
  return [...grouped.values()].sort((a, b) => a.id.localeCompare(b.id));
}

// This is an additive local gate, not a replacement for src/decider.mjs.
// Only server-attested source/path/time may be supplied as trustedContext.
export function checkZTNAExtra({ upstreamDecision, trustedContext, rules }) {
  if (upstreamDecision !== 'allow') {
    return { action: 'preserve', reason: 'upstream_policy_first' };
  }
  if (trustedContext?.verifiedByServer !== true || !Array.isArray(rules)) {
    return { action: 'pass', reason: 'missing_trusted_context' };
  }
  const { sourceAddress, path, at } = trustedContext;
  const now = Date.parse(at);
  if (!Number.isFinite(now) || !isIP(sourceAddress || '') || typeof path !== 'string') {
    return { action: 'pass', reason: 'invalid_trusted_context' };
  }
  const rule = rules.find((item) => item.sourceAddress === sourceAddress
    && item.path === path
    && Number.isFinite(Date.parse(item.startsAt))
    && Date.parse(item.startsAt) <= now
    && now < Date.parse(item.expiresAt)
    && Array.isArray(item.evidenceAlertIds) && item.evidenceAlertIds.length > 0
    && item.confidence >= 0.85);
  return rule
    ? { action: 'deny', reason: rule.patterns[0], ruleId: rule.id }
    : { action: 'pass', reason: 'no_active_scoped_rule' };
}

export async function respondToDecisions({ root, alerts, decisions }) {
  const rules = buildDenyCandidates(alerts, decisions);
  const directory = join(root, 'xdr', 'web-injection');
  await mkdir(directory, { recursive: true });
  await writeFile(join(directory, 'deny-rules.json'), JSON.stringify({
    schema: 'aleph.xdr.ztna-candidates.v1',
    moduleKey: 'web-injection',
    mode: 'simulation_only',
    note: 'No server-verified source IP is available in the current ZTNA engine request contract.',
    rules,
  }, null, 2) + '\n', 'utf8');
  const path = join(root, 'xdr', 'alerts.log');
  let old = '';
  try { old = await readFile(path, 'utf8'); } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const unique = new Set();
  for (const line of old.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    try {
      const item = JSON.parse(line);
      if (item?.moduleKey === 'web-injection') {
        unique.add(item.alertId + '\0' + item.action);
      }
    } catch { /* Preserve all unrelated log records without echoing them. */ }
  }
  const added = [];
  for (let i = 0; i < alerts.length; i += 1) {
    const decision = decisions[i];
    if (decision?.alertId !== alerts[i]?.id
      || !['block', 'alert'].includes(decision.action)
      || !/^wi-[A-Za-z0-9-]{1,40}$/u.test(decision.alertId)
      || !/^[a-z][a-z0-9_]{0,63}$/u.test(decision.reason)) continue;
    const row = extractAlert(alerts[i]);
    if (!row.at) continue;
    const key = decision.alertId + '\0' + decision.action;
    if (unique.has(key)) continue;
    unique.add(key);
    // Excludes raw URL, source, account and all sensitive request content.
    added.push(JSON.stringify({
      at: row.at, moduleKey: 'web-injection', alertId: decision.alertId,
      action: decision.action, reason: decision.reason,
    }));
  }
  if (added.length) await appendFile(path, added.join('\n') + '\n', 'utf8');
  return rules;
}