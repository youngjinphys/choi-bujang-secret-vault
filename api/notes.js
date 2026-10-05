import { createClient } from '@supabase/supabase-js';

const noStore = (response) => {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('CDN-Cache-Control', 'no-store');
  response.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
};

export default async function handler(request, response) {
  noStore(response);
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !secretKey) {
    return response.status(503).json({ error: 'NOTES_BACKEND_NOT_CONFIGURED' });
  }

  const supabase = createClient(supabaseUrl, secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  const { data, error } = await supabase
    .from('learning_notes')
    .select('id,title,content')
    .order('id', { ascending: true });

  if (error) return response.status(502).json({ error: 'NOTES_BACKEND_ERROR' });
  return response.status(200).json({ notes: data ?? [] });
}
