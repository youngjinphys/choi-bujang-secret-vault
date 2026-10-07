import { extractAlert } from './read-alerts.mjs';
import { failureCount, isSuspiciousFailure, matchStrongPattern, weakPattern } from './match.mjs';
export { writeIntegrationArtifacts } from './ztna-gate.mjs';

const JEV_ENDPOINT = 'https://api.typesafe.ai/v1/systemone';

// Noul is the probability of the "yes" answer, not a separate Jev confidence field.
// Never send IPs, accounts, passwords, credential lists or full raw events to Jev.
async function askJevLive(alert) {
  const key = process.env.JEV_API_KEY;
  if (!key) return null;
  const row = extractAlert(alert);
  const state = JSON.stringify({
    ruleLevel: row.ruleLevel,
    description: row.description,
    failedAttempts: failureCount(alert),
    mitreTechnique: 'T1110',
  });
  try {
    const response = await fetch(JEV_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + key,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'jev-latest',
        state,
        questions: {
          brute_force_likelihood: {
            type: 'noul',
            instructions: 'Does this weak failed-login signal plausibly indicate a brute-force attack rather than ordinary user mistakes? Do not infer data not in the state.',
          },
        },
      }),
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) return null;
    const payload = await response.json();
    const probability = payload?.answers?.brute_force_likelihood?.noul;
    return typeof probability === 'number' && Number.isFinite(probability)
      && probability >= 0 && probability <= 1 ? probability : null;
  } catch {
    return null;
  }
}

export function createDecider({ askJev = askJevLive } = {}) {
  return async function decideOne(alert) {
    const strong = matchStrongPattern(alert);
    if (strong) {
      return { action: 'block', confidence: strong.confidence, reason: strong.name };
    }
    if (!isSuspiciousFailure(alert)) {
      return { action: 'record', confidence: 0.1, reason: 'no_matching_t1110_pattern' };
    }

    // The Jev path is only for weak/ambiguous signals. AI alone cannot promote
    // such a signal into an IP deny; require a deterministic strong pattern.
    let probability = null;
    try {
      probability = await askJev(alert);
    } catch {
      // No token, rate limit, timeout, unexpected model shape: alert only.
    }
    const fallback = weakPattern();
    const confidence = typeof probability === 'number' && Number.isFinite(probability)
      && probability >= 0 && probability <= 1
      ? Math.max(0.5, Math.min(0.84, probability))
      : fallback.confidence;
    return { action: 'alert', confidence, reason: fallback.name };
  };
}

export const decide = createDecider();