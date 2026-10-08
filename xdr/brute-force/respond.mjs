import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { extractAlert } from './read-alerts.mjs';

// Exclusive owner of xdr/alerts.log for the brute-force module.
// The isolated decide(alert) cannot read or write files.
export async function respond({ root, alerts, decisions }) {
  if (!root || !Array.isArray(alerts) || !Array.isArray(decisions)
      || alerts.length !== decisions.length) {
    throw new Error('경보와 판정 결과 건수가 일치하지 않습니다.');
  }
  const logPath = join(root, 'xdr', 'alerts.log');
  await mkdir(join(root, 'xdr'), { recursive: true });

  let previous = '';
  try { previous = await readFile(logPath, 'utf8'); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }

  // Keep unrelated module lines untouched, while reconciling the current
  // brute-force notifications. Stale "block" and duplicate entries disappear.
  const preserved = [];
  for (const line of previous.split(/\r?\n/u)) {
    if (!line.trim()) continue;
    try {
      if (JSON.parse(line)?.moduleKey === 'brute-force') continue;
    } catch { /* Do not silently erase unrelated pre-existing records. */ }
    preserved.push(line);
  }

  const notifications = [];
  const seen = new Set();
  for (let i = 0; i < alerts.length; i += 1) {
    const entry = alerts[i];
    const outcome = decisions[i];
    if (outcome?.action !== 'alert') continue;
    const alertId = entry?.id;
    if (!/^[a-z][a-z0-9-]{1,40}$/u.test(alertId ?? '')
        || outcome.alertId !== alertId
        || !/^[a-z][a-z0-9_]{0,63}$/u.test(outcome.reason ?? '')
        || !Number.isFinite(outcome.confidence)
        || outcome.confidence < 0.5 || outcome.confidence >= 0.85) {
      throw new Error('경보의 알림 판정 값이 잘못되었습니다.');
    }
    if (seen.has(alertId)) continue;
    seen.add(alertId);
    const row = extractAlert(entry);
    if (!row.at) throw new Error('경보 시각이 잘못되었습니다.');
    // No raw descriptions, addresses, account names, secrets or tokens.
    notifications.push(JSON.stringify({
      at: row.at,
      moduleKey: 'brute-force',
      alertId,
      action: 'alert',
      reason: outcome.reason,
    }));
  }

  const lines = [...preserved, ...notifications];
  await writeFile(logPath, lines.length ? lines.join('\n') + '\n' : '', 'utf8');
  return { written: notifications.length, preservedOther: preserved.length };
}
