import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { extractAlert } from './read-alerts.mjs';
import { matchStrongPattern } from './match.mjs';

const RULE_TTL_MS = 15 * 60 * 1000;

// Candidates are scoped to source AND account. The class engine's v1 request
// has neither a verified source IP nor a verified Wazuh-account mapping.
export function buildDenyCandidates(alerts, decisions) {
  const decisionById = new Map(decisions.map((d) => [d.alertId, d]));
  const byPair = new Map();
  for (const alert of alerts) {
    if (typeof alert?.id !== 'string' || !/^bf-[a-zA-Z0-9-]{1,40}$/.test(alert.id)) continue;
    const choice = decisionById.get(alert.id);
    const evidence = matchStrongPattern(alert);
    if (!choice || choice.action !== 'block' || choice.confidence < 0.85
      || !evidence || choice.reason !== evidence.name) continue;
    const row = extractAlert(alert);
    const start = Date.parse(row.at);
    if (!Number.isFinite(start) || !row.sourceAddress || !row.account) continue;
    const key = row.sourceAddress + '\0' + row.account;
    const prior = byPair.get(key);
    const expiresAt = new Date(start + RULE_TTL_MS).toISOString();
    if (prior) {
      prior.evidenceAlertIds.push(alert.id);
      if (Date.parse(prior.expiresAt) < start + RULE_TTL_MS) prior.expiresAt = expiresAt;
      if (Date.parse(prior.startsAt) > start) prior.startsAt = row.at;
      prior.confidence = Math.max(prior.confidence, choice.confidence);
    } else {
      byPair.set(key, {
        id: 'xdr.t1110.' + createHash('sha256').update(key).digest('hex').slice(0, 16),
        sourceAddress: row.sourceAddress,
        account: row.account,
        startsAt: row.at,
        expiresAt,
        evidenceAlertIds: [alert.id],
        pattern: evidence.name,
        confidence: choice.confidence,
      });
    }
  }
  return [...byPair.values()].sort((a, b) => a.id.localeCompare(b.id));
}

// An additive server-side check only. Never call this with browser-supplied
// source/account claims, and never change a preexisting deny or step_up to allow.
export function checkZTNAExtra({ upstreamDecision, trustedContext, rules }) {
  if (upstreamDecision !== 'allow') {
    return { action: 'preserve', reason: 'upstream_policy_first' };
  }
  if (!trustedContext?.verifiedByServer || !Array.isArray(rules)) {
    return { action: 'pass', reason: 'missing_trusted_context' };
  }
  const { sourceAddress, account, at } = trustedContext;
  const now = Date.parse(at);
  if (!Number.isFinite(now)) return { action: 'pass', reason: 'invalid_time' };
  const active = rules.find((rule) => rule.sourceAddress === sourceAddress
    && rule.account === account
    && Date.parse(rule.startsAt) <= now
    && now < Date.parse(rule.expiresAt)
    && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0);
  return active
    ? { action: 'deny', reason: active.pattern, ruleId: active.id }
    : { action: 'pass', reason: 'no_active_scoped_rule' };
}

export async function writeIntegrationArtifacts({ root, alerts, decisions }) {
  if (!Array.isArray(alerts) || !Array.isArray(decisions)
    || alerts.length !== decisions.length) {
    throw new Error('경보와 판단 결과 건수가 일치하지 않습니다.');
  }
  const directory = join(root, 'xdr', 'brute-force');
  await mkdir(directory, { recursive: true });
  const candidates = buildDenyCandidates(alerts, decisions);
  await writeFile(join(directory, 'deny-rules.json'), JSON.stringify({
    schema: 'aleph.xdr.ztna-candidates.v1',
    mode: 'simulation_only',
    note: 'Validated server-side IP and identity mapping are unavailable in aleph.decision.v1.',
    rules: candidates,
  }, null, 2) + '\n', 'utf8');

  const logPath = join(root, 'xdr', 'alerts.log');
  let existing = '';
  try { existing = await readFile(logPath, 'utf8'); } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const logged = new Set();
  for (const line of existing.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    try {
      const item = JSON.parse(line);
      if (item.moduleKey === 'brute-force') {
        logged.add(item.alertId + '\0' + item.action);
      }
    } catch { /* Preserve existing log lines without trusting their content. */ }
  }
  const added = [];
  for (let i = 0; i < alerts.length; i += 1) {
    const choice = decisions[i];
    if (!['block', 'alert'].includes(choice.action) || choice.alertId !== alerts[i]?.id) continue;
    if (!/^[a-z][a-z0-9_]{0,63}$/u.test(choice.reason)) continue;
    const row = extractAlert(alerts[i]);
    const key = choice.alertId + '\0' + choice.action;
    if (!row.at || logged.has(key)) continue;
    logged.add(key);
    // No raw message, IP, username, password or token goes into the audit log.
    added.push(JSON.stringify({
      at: row.at, moduleKey: 'brute-force', alertId: choice.alertId,
      action: choice.action, reason: choice.reason,
    }));
  }
  if (added.length) await appendFile(logPath, added.join('\n') + '\n', 'utf8');
}