import { bytesToHex, hexToBytes, b64urlEncode, b64urlDecode, ctEqual } from './utils';
import { sha256Bytes, hmacSha256B64url, verifyPBKDF2, base32Decode, verifyTotp, sealAesGcm, openAesGcm } from './crypto';

type Env = {
  DB: D1Database;
  ISSUER: string;
  SESSION_COOKIE_NAME: string;
  ADMIN_ALLOWED_ORIGINS: string;
  ADMIN_PASS_HASH: string;
  SIGNING_GATEWAY_HMAC_KEY: string;
  TOTP_MASTER_KEY: string;
  SIGNER_API_BASE: string;
};

const CSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'";
const HSTS = 'max-age=63072000; includeSubDomains; preload';

function json(data: unknown, init: number | ResponseInit = 200): Response {
  return new Response(JSON.stringify(data), { status: typeof init === 'number' ? init : init.status, headers: { 'content-type': 'application/json' } });
}

function html(s: string): Response {
  return new Response(s, { headers: { 'content-type': 'text/html; charset=utf-8', 'Content-Security-Policy': CSP, 'Strict-Transport-Security': HSTS } });
}

function allowOrigin(env: Env, req: Request): boolean {
  const o = req.headers.get('Origin') || '';
  const allowed = (env.ADMIN_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  return allowed.includes(o);
}

async function ipUAHashes(req: Request): Promise<{ ip: string; ua: string; ipHash: Uint8Array; uaHash: Uint8Array }> {
  const ip = req.headers.get('CF-Connecting-IP') || '';
  const ua = req.headers.get('User-Agent') || '';
  const ipHash = await sha256Bytes(ip);
  const uaHash = await sha256Bytes(ua);
  return { ip, ua, ipHash, uaHash };
}

function setCookie(name: string, value: string, maxAge: number = 86400): string {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function requireSession(env: Env, req: Request) {
  const cookieHeader = req.headers.get('Cookie') || '';
  const cookies = Object.fromEntries(cookieHeader.split(';').map(v => v.trim().split('=').map(decodeURIComponent)).filter(kv => kv[0]));
  const sid = cookies[env.SESSION_COOKIE_NAME];
  if (!sid) return null;
  const row = await env.DB.prepare('SELECT admin_id, csrf_token, exp, ip_hash, ua_hash FROM sessions WHERE id=?').bind(sid).first();
  if (!row) return null;
  const now = Math.floor(Date.now() / 1000);
  if (now > row.exp) return null;
  const { ipHash, uaHash } = await ipUAHashes(req);
  if (!ctEqual(new Uint8Array(row.ip_hash), ipHash)) return null;
  if (!ctEqual(new Uint8Array(row.ua_hash), uaHash)) return null;
  return { sid, adminId: row.admin_id as string, csrf: new Uint8Array(row.csrf_token) };
}

async function rateLimit(env: Env, bucket: string, limit: number, windowSec: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`
    INSERT INTO rate_limits(bucket, window_s, count, updated_at) VALUES(?,?,1,?)
    ON CONFLICT(bucket) DO UPDATE SET
      count = CASE WHEN updated_at <= ? - window_s THEN 1 ELSE count + 1 END,
      updated_at = ?
    RETURNING count
  `).bind(bucket, windowSec, now, now, now).first();
  return (row?.count || 0) <= limit;
}

function adminLoginPage(): string {
  return `<!doctype html><meta charset=utf-8>
<title>dmj.one – Admin login</title>
<h1>dmj.one signer – Admin</h1>
<form method="POST" action="/admin/login">
  <label>Password <input name="p" type="password" required></label>
  <button>Log in</button>
</form>`;
}

function adminDashboardPage(rows: any[], csrfB64: string, issuer: string): string {
  return `<!doctype html><meta charset=utf-8>
<title>dmj.one – Admin</title>
<h1>Issued documents</h1>
<p>Issuer: <strong>${issuer}</strong></p>
<input type="hidden" id="csrf" value="${csrfB64}">
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>SHA256</th><th>File</th><th>Size</th><th>Issued</th><th>Status</th><th>Actions</th></tr>
${rows.map((r: any) => `<tr>
<td><code>${r.sha}</code></td>
<td>${r.filename || ''}</td>
<td>${r.size_bytes}</td>
<td>${new Date((r.issued_at as number) * 1000).toISOString()}</td>
<td>${r.status === 1 ? 'issued' : 'revoked'}</td>
<td>${r.status === 1 ? `<button class="revoke" data-sha="${r.sha}">Revoke</button>` : ''}</td>
</tr>`).join('')}
</table>
<h2>Sign a PDF</h2>
<form id="sign" enctype="multipart/form-data" method="POST" action="/admin/sign">
  <input type="file" name="pdf" accept="application/pdf" required>
  <button>Sign PDF</button>
</form>
<h2>Step-up (TOTP)</h2>
<p>If not set up, open <a href="/admin/totp/setup">TOTP setup</a>.</p>
<p>Enter 6-digit code to confirm revocation:</p>
<input id="totp" maxlength="6" inputmode="numeric" pattern="[0-9]{6}">
<script>
document.querySelectorAll('.revoke').forEach(btn=>{
  btn.addEventListener('click', async ()=>{
    const sha = btn.getAttribute('data-sha');
    const totp = document.getElementById('totp').value;
    const csrf = document.getElementById('csrf').value;
    const res = await fetch('/admin/revoke', {
      method:'POST',
      headers: {'Content-Type':'application/json','X-CSRF-Token': csrf},
      body: JSON.stringify({ sha256: sha, totp })
    });
    const j = await res.json();
    alert(JSON.stringify(j));
    if (j.ok) location.reload();
  });
});
</script>`;
}

function verifyPage(): string {
  return `<!doctype html><meta charset=utf-8>
<title>Verify • dmj.one</title>
<h1>Verify a document</h1>
<form enctype="multipart/form-data" method="POST" action="/verify/upload">
  <input type="file" name="pdf" accept="application/pdf" required>
  <button>Verify</button>
</form>
<p>Or paste a SHA-256 (hex) to check issuance status only:</p>
<form method="GET" action="/verify/sha">
  <input name="sha256" pattern="[0-9a-fA-F]{64}" required>
  <button>Check</button>
</form>`;
}

function toBase32(u8: Uint8Array): string {
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let out = '', bits = 0, value = 0;
  for (const b of u8) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  while (out.length % 8) out += '=';
  return out;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === 'GET' && (path === '/' || path === '/verify' || path === '/verify/')) {
      return html(verifyPage());
    }

    if (req.method === 'POST' && path === '/verify/upload') {
      const form = await req.formData();
      const f = form.get('pdf');
      if (!(f instanceof File)) return json({ error:'no_file' }, 400);
      if (f.size > 20*1024*1024) return json({ error:'too_large' }, 413);
      const buf = new Uint8Array(await f.arrayBuffer());
      const magic = new TextDecoder().decode(buf.slice(0,5));
      if (magic !== '%PDF-') return json({ error:'not_pdf' }, 415);
      const sha = await sha256Bytes(buf);
      const shaHex = bytesToHex(sha);
      const rec = await env.DB.prepare('SELECT status FROM documents WHERE sha256=?').bind(sha).first();
      const fdata = new FormData();
      fdata.append('pdf', new Blob([buf], { type:'application/pdf' }), 'uploaded.pdf');
      const vr = await fetch(`${env.SIGNER_API_BASE}/verify`, { method:'POST', body:fdata });
      if (!vr.ok) return json({ error:'verify_backend' }, 502);
      const v = await vr.json();
      const pinned = await env.DB.prepare("SELECT value FROM config WHERE key='signer_spki_sha256'").first();
      const spkiOK = v.spkiSha256 && pinned?.value && v.spkiSha256 === pinned.value;
      let verdict: 'GENUINE' | 'REVOKED' | 'TAMPERED' | 'UNKNOWN';
      if (rec?.status === 2) verdict = 'REVOKED';
      else if (v.valid && spkiOK && rec) verdict = 'GENUINE';
      else if (!v.valid || !spkiOK) verdict = 'TAMPERED';
      else verdict = 'UNKNOWN';
      const { ipHash, uaHash } = await ipUAHashes(req);
      await env.DB.prepare("INSERT INTO audit_log(id, who, action, doc_sha, ts, ip_hash, ua_hash) VALUES(?,?,?,?,?,?,?)")
        .bind(crypto.randomUUID(), null, 'verify', sha, Math.floor(Date.now()/1000), ipHash, uaHash).run();
      return json({ verdict, sha256: shaHex, issuer: env.ISSUER, signedAt: v.signedAt || '', reason: v.reason || '' });
    }

    if (req.method === 'GET' && path === '/verify/sha') {
      const shaHex = url.searchParams.get('sha256') || url.searchParams.get('sha') || '';
      if (!/^[0-9a-fA-F]{64}$/.test(shaHex)) return json({ error:'bad_sha' }, 400);
      const row = await env.DB.prepare('SELECT status FROM documents WHERE sha256=?').bind(hexToBytes(shaHex)).first();
      if (!row) return json({ verdict:'UNKNOWN', sha256: shaHex, issuer: env.ISSUER });
      return json({ verdict: row.status === 2 ? 'REVOKED' : 'ISSUED', sha256: shaHex, issuer: env.ISSUER });
    }

    if (req.method === 'GET' && (path === '/admin' || path === '/login' || path === '/admin/')) {
      const session = await requireSession(env, req);
      if (!session) return html(adminLoginPage());
      const rows = await env.DB.prepare("SELECT hex(sha256) AS sha, filename, size_bytes, issued_at, status FROM documents ORDER BY issued_at DESC LIMIT 300").all();
      const csrfB64 = b64urlEncode(session.csrf);
      return html(adminDashboardPage(rows.results || [], csrfB64, env.ISSUER));
    }

    if (req.method === 'POST' && path === '/admin/login') {
      const okRate = await rateLimit(env, `login:${(await ipUAHashes(req)).ip}`, 5, 60);
      if (!okRate) return json({ error:'rate' }, 429);
      const form = await req.formData();
      const pass = (form.get('p') as string) || '';
      const ok = await verifyPBKDF2(env.ADMIN_PASS_HASH, pass);
      if (!ok) return json({ ok:false }, 401);
      const now = Math.floor(Date.now()/1000);
      let admin = await env.DB.prepare("SELECT id FROM admins WHERE username='admin'").first();
      if (!admin) {
        const aid = crypto.randomUUID();
        await env.DB.prepare("INSERT INTO admins(id, username, created_at) VALUES(?,?,?)").bind(aid, 'admin', now).run();
        admin = { id: aid };
      }
      const { ip, ua, ipHash, uaHash } = await ipUAHashes(req);
      const sid = crypto.randomUUID();
      const csrf = crypto.getRandomValues(new Uint8Array(32));
      await env.DB.prepare("INSERT INTO sessions(id, admin_id, csrf_token, iat, exp, ip_hash, ua_hash) VALUES(?,?,?,?,?,?,?)")
        .bind(sid, admin.id, csrf, now, now + 86400, ipHash, uaHash).run();
      const headers = new Headers({ 'Set-Cookie': setCookie(env.SESSION_COOKIE_NAME, sid), 'content-type':'application/json' });
      return new Response(JSON.stringify({ ok:true }), { headers });
    }

    if (req.method === 'POST' && path === '/admin/sign') {
      const s = await requireSession(env, req);
      if (!s) return json({ error:'auth' }, 401);
      const csrf = req.headers.get('X-CSRF-Token') || '';
      if (csrf !== b64urlEncode(s.csrf)) return json({ error:'csrf' }, 403);
      if (!allowOrigin(env, req)) return json({ error:'origin' }, 403);
      const form = await req.formData();
      const f = form.get('pdf');
      if (!(f instanceof File)) return json({ error:'no_file' }, 400);
      if (f.size > 20*1024*1024) return json({ error:'too_large' }, 413);
      const buf = new Uint8Array(await f.arrayBuffer());
      const magic = new TextDecoder().decode(buf.slice(0,5));
      if (magic !== '%PDF-') return json({ error:'not_pdf' }, 415);
      const fileShaHex = bytesToHex(await sha256Bytes(buf));
      const nonce = crypto.randomUUID();
      const ts = Math.floor(Date.now()/1000).toString();
      await env.DB.prepare("INSERT INTO gateway_nonces(nonce, ts) VALUES(?,?)").bind(nonce, parseInt(ts)).run();
      const auth = await hmacSha256B64url(env.SIGNING_GATEWAY_HMAC_KEY, `${ts}|${nonce}|${fileShaHex}`);
      const outForm = new FormData();
      outForm.append('pdf', new Blob([buf], { type:'application/pdf' }), (f as any).name || 'input.pdf');
      outForm.append('displayName', env.ISSUER);
      outForm.append('reason', `Digitally signed by ${env.ISSUER}`);
      const res = await fetch(`${env.SIGNER_API_BASE}/sign`, {
        method:'POST',
        headers: {
          'X-DMJ-Timestamp': ts,
          'X-DMJ-Nonce': nonce,
          'X-DMJ-FileSHA256': fileShaHex,
          'Authorization': `DMJ-HMAC ${auth}`
        },
        body: outForm
      });
      if (!res.ok) return json({ error:'signer_failed' }, 502);
      const signed = new Uint8Array(await res.arrayBuffer());
      const signedSha = await sha256Bytes(signed);
      const signedShaHex = bytesToHex(signedSha);
      const metaB64 = res.headers.get('X-DMJ-Meta') || 'e30=';
      const meta = JSON.parse(atob(metaB64)) || {};
      const now = Math.floor(Date.now()/1000);
      const pinned = await env.DB.prepare("SELECT value FROM config WHERE key='signer_spki_sha256'").first();
      if (!pinned && meta.spkiSha256) {
        await env.DB.prepare("INSERT INTO config(key, value) VALUES('signer_spki_sha256', ?)").bind(meta.spkiSha256).run();
        await env.DB.prepare("INSERT INTO audit_log(id, who, action, ts) VALUES(?,?,?,?)")
          .bind(crypto.randomUUID(), s.adminId, 'pin_spki', now).run();
      }
      const sigId = crypto.randomUUID();
      await env.DB.batch([
        env.DB.prepare("INSERT INTO signatures(id, cert_serial, cert_spki_sha256, name, reason, subfilter, alg, created_at) VALUES(?,?,?,?,?,?,?,?)")
          .bind(sigId, meta.certSerial || 'unknown', b64urlDecode(meta.spkiSha256 || ''), env.ISSUER, `Digitally signed by ${env.ISSUER}`, meta.subfilter || 'adbe.pkcs7.detached', meta.sigAlg || 'RSA-SHA256', now),
        env.DB.prepare("INSERT INTO documents(id, sha256, size_bytes, filename, status, issued_at, signature_id) VALUES(?,?,?,?,?,?,?)")
          .bind(crypto.randomUUID(), signedSha, signed.length, (f as any).name || 'document.pdf', 1, now, sigId),
        env.DB.prepare("INSERT INTO audit_log(id, who, action, doc_sha, ts) VALUES(?,?,?,?,?)")
          .bind(crypto.randomUUID(), s.adminId, 'sign', signedSha, now)
      ]);
      return new Response(signed, {
        headers: {
          'Content-Type':'application/pdf',
          'Content-Disposition': `attachment; filename="signed-${(f as any).name || 'document'}.pdf"`,
          'Strict-Transport-Security': HSTS,
          'Content-Security-Policy': CSP
        }
      });
    }

    if (req.method === 'GET' && path === '/admin/totp/setup') {
      const s = await requireSession(env, req);
      if (!s) return new Response('Unauthorized', { status: 401 });
      const admin = await env.DB.prepare('SELECT totp_enc FROM admins WHERE id=?').bind(s.adminId).first();
      if (admin?.totp_enc) return html(`<!doctype html><h1>TOTP already configured</h1><p>Return to <a href="/admin">Admin</a>.</p>`);
      const secret = crypto.getRandomValues(new Uint8Array(20));
      const b32 = toBase32(secret);
      const issuer = encodeURIComponent(env.ISSUER);
      const label = encodeURIComponent('admin@dmj.one');
      const otpauth = `otpauth://totp/${label}?secret=${b32}&issuer=${issuer}&digits=6&period=30`;
      const tokenB64 = b64urlEncode(secret);
      return html(`<!doctype html><meta charset=utf-8>
<h1>Set up TOTP</h1>
<p>Secret (Base32): <code>${b32}</code></p>
<p>otpauth URL: <code>${otpauth}</code></p>
<form method="POST" action="/admin/totp/confirm">
  <input type="hidden" name="tmp" value="${tokenB64}">
  <label>Enter a 6-digit code from your authenticator: <input name="code" maxlength="6" required></label>
  <button>Confirm</button>
</form>`);
    }

    if (req.method === 'POST' && path === '/admin/totp/confirm') {
      const s = await requireSession(env, req);
      if (!s) return json({ error:'auth' }, 401);
      const form = await req.formData();
      const tmp = form.get('tmp') as string;
      const code = ((form.get('code') as string) || '').trim();
      if (!tmp || !/^[0-9]{6}$/.test(code)) return json({ error:'bad' }, 400);
      const secret = b64urlDecode(tmp);
      const ok = await verifyTotp(secret, code, 1);
      if (!ok) return json({ error:'totp' }, 403);
      const sealed = await sealAesGcm(env.TOTP_MASTER_KEY, secret);
      await env.DB.prepare("UPDATE admins SET totp_enc=? WHERE id=?").bind(sealed, s.adminId).run();
      return new Response(`<p>TOTP configured. <a href="/admin">Back</a></p>`, { headers: { 'content-type':'text/html' } });
    }

    if (req.method === 'POST' && path === '/admin/revoke') {
      const s = await requireSession(env, req);
      if (!s) return json({ error:'auth' }, 401);
      const csrf = req.headers.get('X-CSRF-Token') || '';
      if (csrf !== b64urlEncode(s.csrf)) return json({ error:'csrf' }, 403);
      if (!allowOrigin(env, req)) return json({ error:'origin' }, 403);
      const body = await req.json().catch(() => null) as any;
      const shaHex = (body?.sha256 as string) || '';
      const totpCode = (body?.totp as string || '').trim();
      if (!/^[0-9a-fA-F]{64}$/.test(shaHex)) return json({ error:'bad_sha' }, 400);
      if (!/^[0-9]{6}$/.test(totpCode)) return json({ error:'bad_totp' }, 400);
      const a = await env.DB.prepare('SELECT totp_enc FROM admins WHERE id=?').bind(s.adminId).first();
      if (!a?.totp_enc) return json({ error:'totp_not_configured' }, 403);
      const secret = await openAesGcm(env.TOTP_MASTER_KEY, new Uint8Array(a.totp_enc));
      const ok = await verifyTotp(secret, totpCode, 1);
      if (!ok) return json({ error:'totp' }, 403);
      const doc = await env.DB.prepare('SELECT id, status FROM documents WHERE sha256=?').bind(hexToBytes(shaHex)).first();
      if (!doc) return json({ error:'not_found' }, 404);
      if (doc.status === 2) return json({ ok:true, already:true });
      const now = Math.floor(Date.now()/1000);
      await env.DB.batch([
        env.DB.prepare('UPDATE documents SET status=2 WHERE id=?').bind(doc.id),
        env.DB.prepare('INSERT INTO revocations(id, document_id, revoked_by, reason, revoked_at) VALUES(?,?,?,?,?)')
          .bind(crypto.randomUUID(), doc.id, s.adminId, body?.reason || null, now),
        env.DB.prepare('INSERT INTO audit_log(id, who, action, doc_sha, ts) VALUES(?,?,?,?,?)')
          .bind(crypto.randomUUID(), s.adminId, 'revoke', hexToBytes(shaHex), now)
      ]);
      return json({ ok:true });
    }

    if (req.method === 'GET' && path.startsWith('/proof/')) {
      const shaHex = path.split('/').pop() || '';
      if (!/^[0-9a-fA-F]{64}$/.test(shaHex)) return json({ error:'bad_sha' }, 400);
      const row = await env.DB.prepare(`
        SELECT d.size_bytes, d.filename, d.status, d.issued_at, s.cert_serial, hex(s.cert_spki_sha256) AS spki
        FROM documents d JOIN signatures s ON d.signature_id=s.id WHERE d.sha256=?
      `).bind(hexToBytes(shaHex)).first();
      if (!row) return json({ error:'not_found' }, 404);
      return json({
        sha256: shaHex,
        size_bytes: row.size_bytes,
        filename: row.filename,
        status: row.status === 2 ? 'REVOKED' : 'ISSUED',
        issued_at: new Date((row.issued_at as number) * 1000).toISOString(),
        cert_serial: row.cert_serial,
        signer_spki_sha256_hex: (row.spki as string).toLowerCase(),
        issuer: env.ISSUER
      });
    }

    if (req.method === 'GET' && (path === '/admin/login' || path === '/admin')) {
      return html(adminLoginPage());
    }

    return new Response('Not found', { status: 404 });
  },

  async scheduled(event: ScheduledEvent, env: Env) {
    const now = Math.floor(Date.now()/1000);
    await env.DB.prepare('DELETE FROM sessions WHERE exp < ?').bind(now).run();
    await env.DB.prepare('DELETE FROM gateway_nonces WHERE ts < ?').bind(now - 86400).run();
    await env.DB.prepare('DELETE FROM rate_limits WHERE updated_at < ?').bind(now - 3600).run();
  }
};
