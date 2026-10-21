// Google 캘린더 갱신용 열쇠(refresh token)를 서버(KV)에 보관하고, 1시간짜리 출입증(access token)을 대신 받아줌
// 브라우저는 무작위 key만 가짐. 나머지 요청은 정적 파일(index.html 등)
export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (req.method !== 'POST' || !u.pathname.startsWith('/gc/')) return env.ASSETS.fetch(req);
    if (req.headers.get('Origin') !== u.origin) return new Response('forbidden', { status: 403 });
    const b = await req.json().catch(() => ({}));
    const tok = p => fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: env.GCID, client_secret: env.GCSECRET, ...p })
    }).then(r => r.json());
    if (u.pathname === '/gc/code') {
      if (!b.code) return new Response('bad request', { status: 400 });
      const j = await tok({ code: b.code, grant_type: 'authorization_code', redirect_uri: 'postmessage' });
      // shortcut: diag는 invalid_client 원인 찾기용 임시값(비밀 자체는 안 보냄), 원인 찾으면 제거
      if (!j.refresh_token) return Response.json({ error: j.error || 'no_refresh_token', diag: { id: String(env.GCID).slice(0, 14), sp: String(env.GCSECRET || '').slice(0, 7), sl: String(env.GCSECRET || '').length } }, { status: 400 });
      const key = crypto.randomUUID() + crypto.randomUUID();
      await env.GK.put(key, j.refresh_token);
      return Response.json({ key, access_token: j.access_token });
    }
    if (u.pathname === '/gc/token') {
      const rt = typeof b.key === 'string' && await env.GK.get(b.key);
      if (!rt) return new Response('unknown key', { status: 401 });
      const j = await tok({ refresh_token: rt, grant_type: 'refresh_token' });
      if (j.access_token) return Response.json({ access_token: j.access_token });
      if (j.error === 'invalid_grant') await env.GK.delete(b.key); // 사용자가 권한을 끊음
      return new Response('refresh failed', { status: 401 });
    }
    return new Response('not found', { status: 404 });
  }
};
