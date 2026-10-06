const NOTE_ROUTES = Object.freeze(['/api/notes', '/api/notes/:id']);
const ORIGINAL_PATH = '/rest/v1/learning_notes';

const cleanHttpsUrl = (value, errorCode) => {
  if (typeof value !== 'string' || value !== value.trim()) throw new TypeError(errorCode);
  let url;
  try { url = new URL(value); } catch { throw new TypeError(errorCode); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new TypeError(errorCode);
  }
  return url;
};

export function validateAllowedRoutes(config) {
  if ((config?.step ?? 0) < 3) return [];
  if (!Array.isArray(config.allowedRoutes) || !config.allowedRoutes.length
      || new Set(config.allowedRoutes).size !== config.allowedRoutes.length
      || config.allowedRoutes.some((route) => typeof route !== 'string'
        || !/^\/[A-Za-z0-9._~:/-]+$/u.test(route))
      || !NOTE_ROUTES.every((route) => config.allowedRoutes.includes(route))) {
    throw new TypeError('invalid_allowed_routes');
  }
  return [...config.allowedRoutes];
}

export function validateOriginalApiUrl(config) {
  if ((config?.step ?? 0) < 5) return null;
  const original = cleanHttpsUrl(config?.originalApiUrl, 'invalid_original_api_url');
  const issuer = cleanHttpsUrl(config?.identityProvider?.issuer, 'invalid_identity_provider');
  if (issuer.pathname !== '/auth/v1' || original.origin !== issuer.origin
      || original.pathname !== ORIGINAL_PATH) {
    throw new TypeError('invalid_original_api_url');
  }
  return original.href;
}

export { NOTE_ROUTES };
