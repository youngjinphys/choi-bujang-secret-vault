import { createClient } from '@supabase/supabase-js';

const COOKIE = 'aleph_refresh';
const MAX_BODY_BYTES = 8192;
const MAX_REFRESH_AGE = 7 * 24 * 60 * 60;

const noStore = (response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('CDN-Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
};

const bodyObject = (request) => {
  if (request.body && typeof request.body === 'object' && !Array.isArray(request.body)) return request.body;
  if (typeof request.body !== 'string' || Buffer.byteLength(request.body) > MAX_BODY_BYTES) return null;
  try {
    const parsed = JSON.parse(request.body);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const cookies = (header = '') => Object.fromEntries(header.split(';').flatMap((part) => {
  const index = part.indexOf('=');
  if (index < 1) return [];
  const key = part.slice(0, index).trim();
  const raw = part.slice(index + 1).trim();
  try { return [[key, decodeURIComponent(raw)]]; } catch { return []; }
}));

const setRefreshCookie = (response, token) => {
  const parts = [
    `${COOKIE}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/api/auth',
    `Max-Age=${MAX_REFRESH_AGE}`,
  ];
  if (process.env.VERCEL === '1' || process.env.NODE_ENV === 'production') parts.push('Secure');
  response.setHeader('Set-Cookie', parts.join('; '));
};

const clearRefreshCookie = (response) => {
  const parts = [`${COOKIE}=`, 'HttpOnly', 'SameSite=Strict', 'Path=/api/auth', 'Max-Age=0'];
  if (process.env.VERCEL === '1' || process.env.NODE_ENV === 'production') parts.push('Secure');
  response.setHeader('Set-Cookie', parts.join('; '));
};

const client = () => {
  const url = process.env.SUPABASE_URL;
  const publishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!url || !publishableKey) return null;
  return createClient(url, publishableKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
};

const publicSession = (session) => ({
  accessToken: session.access_token,
  expiresAt: session.expires_at ?? null,
  user: { email: session.user?.email ?? null },
});

export default async function handler(request, response) {
  noStore(response);
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabase = client();
  if (!supabase) return response.status(503).json({ error: 'AUTH_BACKEND_NOT_CONFIGURED' });

  const actionValue = request.query?.action;
  const action = Array.isArray(actionValue) ? actionValue[0] : actionValue;

  if (action === 'login') {
    const body = bodyObject(request);
    const email = typeof body?.email === 'string' ? body.email.trim() : '';
    const password = typeof body?.password === 'string' ? body.password : '';
    if (!email || email.length > 254 || !password || password.length > 4096) {
      return response.status(400).json({ error: 'INVALID_CREDENTIAL_INPUT' });
    }

    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error || !data.session?.access_token || !data.session?.refresh_token) {
      return response.status(401).json({ error: error?.message || 'LOGIN_FAILED' });
    }
    setRefreshCookie(response, data.session.refresh_token);
    return response.status(200).json(publicSession(data.session));
  }

  if (action === 'session') {
    const refreshToken = cookies(request.headers?.cookie)[COOKIE];
    if (!refreshToken) return response.status(401).json({ error: 'NO_SESSION' });

    const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
    if (error || !data.session?.access_token || !data.session?.refresh_token) {
      clearRefreshCookie(response);
      return response.status(401).json({ error: 'SESSION_EXPIRED' });
    }
    setRefreshCookie(response, data.session.refresh_token);
    return response.status(200).json(publicSession(data.session));
  }

  if (action === 'logout') {
    const refreshToken = cookies(request.headers?.cookie)[COOKIE];
    clearRefreshCookie(response);
    if (refreshToken) {
      const { data } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
      if (data.session?.access_token && data.session?.refresh_token) {
        await supabase.auth.signOut({ scope: 'local' });
      }
    }
    return response.status(200).json({ ok: true });
  }

  return response.status(404).json({ error: 'AUTH_ROUTE_NOT_FOUND' });
}
