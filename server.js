require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const axios = require('axios');
const cron = require('node-cron');
const db = require('./db');
const { generatePO } = require('./lib/pdf');
const { sendPOEmail } = require('./lib/email');
// Session store: SQLite (synchronous, persistent file)
const SqliteStore = require('better-sqlite3-session-store')(session);
const SESSION_DB_PATH = process.env.SESSION_DB_PATH || path.join(__dirname, 'stockyshift_sessions.db');
const SessionStore = new SqliteStore({
  client: require('better-sqlite3')(SESSION_DB_PATH),
  expired: { clear: true, intervalMs: 900000 },
});

const app = express();
const PORT = process.env.PORT || 3000;

// ─── TEMPORARY DEBUG: catch-all request log (REMOVE BEFORE LAUNCH) ────────
// Mounted as the VERY FIRST middleware — before security headers, body
// parsing, sessions, auth, billing, and every route. Logs EVERY incoming
// request on ANY path (/, /dashboard.html, /api/..., webhooks, static) with
// the full URL, method, Host, Referer, User-Agent, sec-fetch-dest and the
// response status. Purpose: prove, from the server side, whether the hidden
// download iframe ever navigates to /api/.../export?dl=... (a real iframe
// navigation carries sec-fetch-dest: iframe; a fetch carries sec-fetch-dest:
// empty — the two are distinguishable in this log).
const __reqLog = [];
const __clientTrace = [];
const __reqLogMax = 2000;
// Unique per-process identity. The suffix is Date.now().toString(36) captured
// at process start — it NEVER changes during the process lifetime, so the ID
// proves browser and log-reader are on the SAME Render instance. (The "boot"
// field in /api/debug/instance is NOT boot time — it is new Date() at request
// time; do not use it to detect restarts.)
const __INSTANCE = [
  process.env.RENDER_INSTANCE_ID || require('os').hostname() || 'unknown',
  Date.now().toString(36),
].join('-');
app.use((req, res, next) => {
  res.on('finish', () => {
    const entry = {
      t: new Date().toISOString().slice(11, 23),
      m: req.method,
      url: String(req.originalUrl || req.url || '').slice(0, 300),
      host: String(req.headers.host || '').slice(0, 80) || null,
      ref: String(req.headers.referer || '').slice(0, 200) || null,
      ua: String(req.headers['user-agent'] || '').slice(0, 120) || null,
      dest: String(req.headers['sec-fetch-dest'] || ''),
      site: String(req.headers['sec-fetch-site'] || ''),
      status: res.statusCode,
      ct: String(res.getHeader('content-type') || '').slice(0, 80) || null,
      inst: __INSTANCE,
    };
    __reqLog.push(entry);
    if (__reqLog.length > __reqLogMax) __reqLog.shift();
  });
  next();
});

// ─── Rate limiting (simple in-memory fixed-window) ────────────────────────
// Protects /auth and /auth/callback from oauth_states table flooding (an
// attacker hitting /auth?shop=x repeatedly grows the oauth_states table faster
// than the 15-min sweep can delete). Single-process Render (WEB_CONCURRENCY=1)
// makes in-memory limiting safe. If scaled to multiple workers later, move this
// to a shared store (Redis / SQLite).
const rateBuckets = new Map();
function rateLimit({ windowMs = 60 * 1000, max = 20 } = {}) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    const now = Date.now();
    const bucket = rateBuckets.get(ip);
    if (!bucket || bucket.resetAt <= now) {
      // Fresh bucket (this IP may legitimately hit /auth several times across
      // retries/reloads — 20/min is generous while blocking floods)
      rateBuckets.set(ip, { count: 1, resetAt: now + windowMs });
      if (rateBuckets.size > 10000) { // prune old buckets occasionally
        for (const [k, b] of rateBuckets) if (b.resetAt <= now) rateBuckets.delete(k);
      }
      return next();
    }
    bucket.count += 1;
    if (bucket.count > max) {
      res.set('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
      return res.status(429).json({ error: 'Too many requests — please try again shortly.' });
    }
    next();
  };
}

// ─── Async error safety net (Express 4) ───────────────────────────────────
// Express 4 does NOT catch rejected promises from async route handlers —
// a DB error in a route without try/catch becomes an unhandledRejection,
// which crashes the WHOLE process (every store, not just the failing one).
// Shim every app.get/post/put/delete registration so each handler's
// rejection is forwarded to the global error middleware at the bottom of
// this file instead of killing the app. Sync handlers pass through unchanged.
const _routeMethods = ['get', 'post', 'put', 'delete'];
for (const _m of _routeMethods) {
  const _orig = app[_m].bind(app);
  app[_m] = (path, ...handlers) => {
    const wrapped = handlers.map(h =>
      h.length >= 4 ? h : (req, res, next) => Promise.resolve(h(req, res, next)).catch(next)
    );
    return _orig(path, ...wrapped);
  };
}

// Strip control characters and cap length on merchant-entered text before it
// reaches the DB — control chars can corrupt PDFKit rendering and HTML output.
const sanitizeText = (s, max = 255) => String(s ?? '').replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, max);

// Behind Cloudflare → Render proxy. Without this, req.secure is false,
// so express-session silently refuses to set secure:true cookies —
// sessions never get created in production and all API auth fails.
app.set('trust proxy', 1);

// Shopify API version — update when Shopify deprecates the current version
const API_VERSION = '2026-07';

// ─── Middleware ───────────────────────────────────────────────────────────

// ─── Security Headers (App Store requirement, embedded-app compatible) ─────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // HSTS: production only — on localhost over http it would brick the browser
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  // Embedded apps MUST be frameable by Shopify admin
  // Use CSP frame-ancestors (modern) instead of X-Frame-Options (deprecated for this use case)
  const shop = (req.query.shop || '').trim();
  // Only allow valid myshopify.com domains to prevent header injection
  if (shop && /^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/.test(shop)) {
    res.setHeader('Content-Security-Policy', `frame-ancestors https://${shop} https://admin.shopify.com;`);
  } else if (req.path.startsWith('/api/') || req.path.startsWith('/webhooks/') || req.path === '/privacy' || req.path === '/terms' || req.path === '/') {
    // Public/non-embedded routes: deny framing entirely
    res.setHeader('X-Frame-Options', 'DENY');
  } else {
    // App routes with missing/invalid shop: still allow Shopify admin framing,
    // otherwise the app renders as a blank white screen inside the admin iframe
    // (a common App Store rejection reason). Restrict to admin.shopify.com only.
    res.setHeader('Content-Security-Policy', 'frame-ancestors https://admin.shopify.com;');
  }
  next();
});

// Capture raw body for webhook HMAC verification
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ extended: true }));

// API responses must never be cached. Safari aggressively caches GET
// fetch() responses without Cache-Control and serves STALE JSON (e.g. an
// old billing status, pre-heal) after a redeploy or billing heal — which
// looks like the app is broken when the server already fixed itself.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// Instance identity + build stamp, served with no-store so a CDN can never
// answer it from cache. The tracer reads this on boot and reports it back.
app.get('/api/debug/instance', (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  res.set('Pragma', 'no-cache');
  res.json({
    instance: __INSTANCE,
    build: '0ccbd88',
    boot: new Date().toISOString(),
  });
});

// Client trace upload + readback are defined BELOW, after the CSRF/billing
// middleware (the /debug path is billing-exempt; readback is key-gated).

app.use(session({
  store: SessionStore,
  secret: process.env.SESSION_SECRET || (() => {
    console.error('FATAL: SESSION_SECRET not set — refusing to start. Set SESSION_SECRET in .env');
    process.exit(1);
  })(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 86400000, // 24 hours
    // Secure + SameSite=None required on HTTPS (production).
    // Local dev over http://localhost would refuse the cookie otherwise.
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    secure: process.env.NODE_ENV === 'production',
  },
}));

// Malformed JSON bodies → 400, not 500. body-parser's parse errors (SyntaxError
// with entity.parse.failed) would otherwise fall through to the global error
// handler and return "Internal server error" for a client-side mistake.
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON in request body' });
  }
  next(err);
});

// ─── Shopify HMAC / Session Token Verification ────────────────────────────

function verifyWebhook(body, hmacHeader) {
  if (!hmacHeader || !SHOPIFY_API_SECRET) return false;
  const calculatedHmac = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(body, 'utf8')
    .digest('base64');
  // Compare using Buffer in case of different string lengths
  const expected = Buffer.from(calculatedHmac);
  const actual = Buffer.from(hmacHeader);
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

// Verify a Shopify App Bridge session token (JWT) — no npm deps needed
function verifySessionToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;

  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  } catch {
    return null;
  }

  // Must be HS256
  if (header.alg !== 'HS256') return null;
  // Must not be expired. Symmetric 300s tolerance with the nbf check: Shopify
  // token issuer clocks can run ahead of this server, and a strict exp check
  // then 401s perfectly valid tokens ("Session expired") for no reason.
  if (payload.exp < Date.now() / 1000 - 300) return null;
  // Must not be used before its nbf (not-before) timestamp, with 5min clock skew
  // tolerance — Shopify's token issuer clock can be ahead of this server's, and
  // a strict nbf check then rejects perfectly valid tokens (=> "Session expired").
  if (payload.nbf && payload.nbf > (Date.now() / 1000) + 300) return null;
  // Must be issued for our API key
  if (payload.aud !== SHOPIFY_API_KEY) return null;

  // Verify HMAC signature with timing-safe comparison
  const expectedSig = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(parts[0] + '.' + parts[1])
    .digest('base64url')
    .replace(/=+$/, ''); // base64url has no padding

  const sigBuf = Buffer.from(expectedSig);
  const partsBuf = Buffer.from(parts[2]);
  if (sigBuf.length !== partsBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, partsBuf)) return null;

  // Extract shop from dest field: "https://{shop}.myshopify.com"
  const dest = payload.dest || '';
  const match = dest.match(/https:\/\/([^/]+)/);
  if (!match) return null;

  // Validate issuer (App Bridge spec): iss is "https://{shop}.myshopify.com/admin"
  // — must be the SAME shop as dest. Prevents a leaked token for shop B from
  // being replayed against shop A (the aud/signature checks alone can't catch
  // this if the secret is shared across shops).
  const issMatch = (payload.iss || '').match(/https:\/\/([^/]+)/);
  if (!issMatch || issMatch[1] !== match[1]) return null;

  return { shop: match[1], payload };
}

// Middleware: authenticate via session token (Bearer) or session cookie.
// Sets req.shop for use by getShop(). All API routes require authentication
// via Bearer token (embedded) or session cookie (standalone).
app.use((req, res, next) => {
  let authedShop = null;
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    const result = verifySessionToken(authHeader.slice(7));
    if (result) authedShop = result.shop;
  }
  if (!authedShop && req.session?.shop) authedShop = req.session.shop;
  req.shop = authedShop;
  next();
});

// Redirect direct .html requests to extensionless versions so the route
// handlers (which do contact email substitution) always serve them.
app.get('/privacy.html', (_req, res) => res.redirect(301, '/privacy'));
app.get('/terms.html', (_req, res) => res.redirect(301, '/terms'));

// Serve static assets (favicon, robots, sitemap, etc.)
// privacy.html and terms.html are above this middleware, so the redirect fires first.
app.use(express.static('views'));

// HTML pages must never be cached either. Safari heuristically caches pages
// served without explicit headers — a cached dashboard shell can run stale
// JS (e.g. an old billing check) for days even after the server is fixed.
// Pages are tiny; freshness always wins.
app.use((req, res, next) => {
  if (req.path === '/' || req.path.endsWith('.html') || req.path === '/privacy' || req.path === '/terms' || req.path === '/apps/stockyshift') {
    res.set('Cache-Control', 'no-store');
  }
  next();
});

// ─── Billing enforcement middleware ───────────────────────────────────────
// Enforces paywall server-side — an expired/cancelled merchant cannot use
// the API even if they bypass the client-side billing overlay.
// NOTE: this middleware is mounted at '/api', so req.path here is RELATIVE
// (e.g. '/billing/status', not '/api/billing/status').
const BILLING_EXEMPT_PATHS = [
  '/config',
  '/billing/status',
  '/billing/create',
  '/billing/cancel',
  '/billing/cancel-pending',
  '/db-health',
  '/debug',
];
if (process.env.NODE_ENV !== 'production') BILLING_EXEMPT_PATHS.push('/test-email');

app.use('/api', async (req, res, next) => {
  // CSRF defense: the session cookie is SameSite=None (required so the
  // embedded iframe on admin.shopify.com can carry it), which means a
  // malicious third-party site could trigger state-changing /api calls with
  // the victim's cookie in standalone mode. Browsers send Origin on every
  // cross-site POST — reject anything that didn't come from our own origin
  // or the Shopify admin. (Missing Origin = same-origin navigation/curl,
  // which cannot carry a CSRF victim's cookies anyway.)
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.headers.origin;
    if (origin) {
      let host = '';
      try { host = new URL(origin).host; } catch { return res.status(403).json({ error: 'Forbidden' }); }
      const allowed = ['stockyshift.com', 'admin.shopify.com', 'localhost'];
      const ok = allowed.some(a => host === a || host.endsWith('.' + a) || host.startsWith('localhost:') || host.startsWith('127.0.0.1:'));
      if (!ok) return res.status(403).json({ error: 'Forbidden' });
    }
  }

  // Allow preflight and exempt paths
  if (req.method === 'OPTIONS') return next();
  if (BILLING_EXEMPT_PATHS.some(p => req.path === p || req.path.startsWith(p + '/'))) return next();

  const shop = req.shop || req.session?.shop;
  if (!shop) return next(); // auth middleware handles 401 for these

  try {
    const merchant = await db.get('SELECT billing_status, trial_ends_at FROM merchants WHERE shop = $1', [shop]);
    if (!isBillingActive(merchant)) {
      return res.status(402).json({ error: 'Billing required', code: 'BILLING_REQUIRED' });
    }
    next();
  } catch (e) {
    console.error('[Billing] Enforcement check failed:', e.message);
    next(); // fail open on DB error, auth still applies
  }
});

// ─── TEMPORARY DEBUG: client trace upload + key-gated readback (REMOVE BEFORE LAUNCH)
// Upload does NOT require session auth: the embedded iframe authenticates via
// App Bridge Bearer tokens, and the session cookie is not guaranteed present
// in that context (which caused 401s). The CSRF middleware above still
// origin-checks this POST (stockyshift.com / admin.shopify.com only).
// The readback is gated by DEBUG_KEY so the ring is never exposed publicly.
app.post('/api/debug/trace', async (req, res) => {
  const lines = Array.isArray(req.body?.lines) ? req.body.lines : [];
  const shop = (req.query.shop || '').toString().slice(0, 100);
  __clientTrace.push({ t: new Date().toISOString().slice(11, 23), shop, n: lines.length, inst: __INSTANCE, lines: lines.slice(-500) });
  if (__clientTrace.length > 50) __clientTrace.shift();
  res.json({ ok: true, instance: __INSTANCE });
});

app.get('/api/debug/trace', (req, res) => {
  if (!process.env.DEBUG_KEY || req.query.key !== process.env.DEBUG_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  res.json({
    reader: { instance: __INSTANCE },
    requests: __reqLog.slice(-500),
    clientTrace: __clientTrace.slice(-10),
  });
});

// ─── Static Pages ─────────────────────────────────────────────────────────

app.get('/privacy', (req, res) => {
  const CONTACT_PRIVACY = process.env.CONTACT_PRIVACY || 'privacy@stockyshift.com';
  let html = require('fs').readFileSync(path.join(__dirname, 'views', 'privacy.html'), 'utf8');
  html = html.replace(/privacy@stockyshift\.com/g, CONTACT_PRIVACY);
  res.send(html);
});

app.get('/terms', (req, res) => {
  const CONTACT_LEGAL = process.env.CONTACT_LEGAL || 'legal@stockyshift.com';
  let html = require('fs').readFileSync(path.join(__dirname, 'views', 'terms.html'), 'utf8');
  html = html.replace(/legal@stockyshift\.com/g, CONTACT_LEGAL);
  res.send(html);
});

// ─── Shopify OAuth ────────────────────────────────────────────────────────

const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const SCOPES = process.env.SCOPES || 'write_inventory,read_inventory,read_products,read_locations';
const APP_URL = process.env.SHOPIFY_APP_URL || process.env.APP_URL;

// Iframe-safe auth redirect. Shopify's embedded admin renders the app inside a
// cross-origin iframe; a plain 302 from the server is followed INSIDE that
// iframe, and Shopify's own auth pages (admin.shopify.com) refuse to render in
// a frame — the result is the blank "admin.shopify.com refused to connect."
// page. This serves a tiny HTML page that navigates the TOP window instead.
// Browsers block cross-origin top navigation without user activation, so the
// page also renders a button (a click grants the permission) and a fallback
// link — the iframe can never silently dead-end on a white page.
function sendAuthRedirect(res, targetUrl) {
  const safeUrl = String(targetUrl).replace(/</g, '\\u003c').replace(/>/g, '\\u003e');
  res.type('html').send(`<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#1a1a2e;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .card{background:#23233c;border:1px solid #34345a;border-radius:16px;padding:40px 44px;max-width:400px;text-align:center}
    h1{font-size:22px;margin:0 0 8px;color:#fff;font-weight:700}
    p{color:#a0a0b8;font-size:14px;margin:0 0 24px;line-height:1.5}
    button{background:#4a6cf7;color:#fff;border:none;border-radius:10px;padding:13px 32px;font-size:15px;font-weight:600;cursor:pointer}
    button:hover{background:#3b5de7}
    .small{color:#6b6b88;font-size:12px;margin-top:20px}
    .small a{color:#8a8aaa}
  </style></head><body><div class="card">
    <h1>StockyShift</h1>
    <p>Connect your store to open StockyShift.</p>
    <button id="go">Open StockyShift</button>
    <p class="small"><a id="lnk" href="#">Open in a new tab</a></p>
  </div><script>
  (function () {
    var url = ${JSON.stringify(safeUrl)};
    var navigate = function () {
      try { window.top.location.href = url; }
      catch (e) { window.open(url, '_blank'); }
    };
    document.getElementById('go').addEventListener('click', navigate);
    document.getElementById('lnk').href = url;
    // Auto-attempt on load — allowed at top level and when the browser
    // permits cross-origin top navigation; otherwise the button above is
    // the user-activation path (a click always grants the permission).
    navigate();
  })();
  <\/script></body></html>`);
}

// Step 1: Redirect merchant to Shopify authorization
app.get('/auth', rateLimit({ windowMs: 60 * 1000, max: 20 }), async (req, res) => {
  let { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop parameter');
  shop = String(shop).toLowerCase(); // Shopify normalizes to lowercase — store canonical form
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop domain. Must be a valid .myshopify.com domain.');
  }

  // Stateless state: random, single-use, stored in DB (HMAC is not needed — this is true CSRF)
  const state = crypto.randomBytes(20).toString('hex');
  await db.run('DELETE FROM oauth_states WHERE created_at < $1', [Date.now() - 15 * 60 * 1000]);
  await db.run('INSERT INTO oauth_states (state, shop, created_at) VALUES ($1, $2, $3)',
    [state, shop, Date.now()]);

  const redirectUri = `${APP_URL}/auth/callback`;
  const installUrl = `https://${shop}/admin/oauth/authorize?` +
    `client_id=${SHOPIFY_API_KEY}` +
    `&scope=${SCOPES}` +
    `&redirect_uri=${redirectUri}` +
    `&state=${state}`;

  // Iframe-safe: never 302 straight to Shopify's authorize page — if this
  // route is hit from inside the embedded iframe, a 302 would leave the
  // iframe on admin.shopify.com's OAuth page, which refuses to render in a
  // frame ("refused to connect"). The HTML page escapes to the top window.
  sendAuthRedirect(res, installUrl);
});

// Step 2: Handle OAuth callback
app.get('/auth/callback', rateLimit({ windowMs: 60 * 1000, max: 30 }), async (req, res) => {
  const { code, state } = req.query;
  const shop = String(req.query.shop || '').toLowerCase();

  // Verify single-use state and consume it (prevents replay).
  // NOTE: if this callback is delivered twice (Shopify retries, or the merchant
  // double-clicked approve), the first delivery consumes the state and the
  // second would see no row. Handle that gracefully below.
  const stateRow = await db.get('SELECT shop, created_at FROM oauth_states WHERE state = $1', [state || '']);
  const stateAge = stateRow ? Date.now() - stateRow.created_at : Infinity;
  if (!stateRow || stateRow.shop !== shop || stateAge > 15 * 60 * 1000) {
    // State failed to verify. If the merchant is ALREADY installed and active,
    // this is a duplicate delivery of a successful callback — just send them in.
    // Otherwise it's a genuine CSRF attempt or expired link.
    const existing = shop ? await db.get('SELECT is_active FROM merchants WHERE shop = $1', [shop]) : null;
    if (existing?.is_active) {
      console.log(`[OAuth] ${shop} callback re-delivered (state already consumed) — merchant active, redirecting in`);
      req.session.shop = shop;
      return res.redirect(`/?shop=${shop}`);
    }
    console.warn(`[OAuth] State mismatch for ${shop}: state=${state ? state.slice(0, 8) + '…' : '(missing)'} row=${stateRow ? 'found' : 'missing'} age=${Math.round(stateAge / 1000)}s`);
    return res.status(403).send('State mismatch. Possible CSRF attack or expired link — try installing again.');
  }

  // Consume the state IMMEDIATELY, as early as possible. The state is
  // single-use, so a failed token exchange already forces a fresh /auth flow
  // (the dashboard/install links always go through /auth first). Consuming
  // early shrinks the CSRF window: once deleted, a second delivery of this
  // callback cannot be accepted even if a leaked URL is replayed before the
  // merchant installs. (A duplicate delivery is still handled gracefully:
  // if the merchant is already active we let them in above.)
  await db.run('DELETE FROM oauth_states WHERE state = $1', [state || '']);

  // Verify shop domain (same validation as /auth endpoint)
  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.myshopify\.com$/.test(shop)) {
    return res.status(400).send('Invalid shop domain');
  }

  try {
    // Exchange code for access token (expiring=1 required for API 2026-07+)
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
        expiring: 1,
      },
      { timeout: 15000 } // don't hang the install screen on a slow network
    );

    const tokenData = tokenResponse.data;
    // SECURITY: never log tokenData — it contains access_token AND
    // refresh_token (live credentials for the store). Log metadata only.
    console.log(`[OAuth] Token exchange succeeded for ${shop} (expires_in: ${tokenData.expires_in || 'n/a'})`);
    const accessToken = tokenData.access_token;
    const refreshToken = tokenData.refresh_token || null;
    const expiresAt = tokenData.expires_in
      ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
      : null;

    // Store merchant in database — set to 'pending' initially, then heal if
    // Shopify App Pricing already created a subscription (modern install flow).
    await db.run(`
      INSERT INTO merchants (shop, access_token, refresh_token, expires_at, billing_status, trial_ends_at)
      VALUES ($1, $2, $3, $4, 'pending', NULL)
      ON CONFLICT(shop) DO UPDATE SET
        access_token = $2,
        refresh_token = $3,
        expires_at = $4,
        is_active = 1,
        uninstalled_at = NULL,
        billing_status = CASE
          WHEN ${DEV_SHOW_BILLING} THEN 'pending'
          WHEN trial_used = 0 AND billing_status NOT IN ('active') THEN 'pending'
          ELSE billing_status
        END,
        trial_ends_at = CASE
          WHEN ${DEV_SHOW_BILLING} THEN NULL
          WHEN trial_used = 0 AND billing_status NOT IN ('active') THEN NULL
          ELSE trial_ends_at
        END
    `, [shop, accessToken, refreshToken, expiresAt]);

    // Heal billing status for App Pricing installs: dev stores get auto-activated
    // (no charge), and production stores may have an App Pricing subscription
    // created automatically when they pick a plan on the install screen.
    const merchant = await db.get('SELECT trial_used, billing_status FROM merchants WHERE shop = $1', [shop]);
    // Reinstalls on dev stores: the reinstall unmark listenwebhook sets trial_used=0
    // but sometimes the merchant row keeps the old trial flag. If billing_status is
    // 'pending' (fresh install or reinstall on dev store), always run the heal check.
    //
    // DEV_SHOW_BILLING: testing-only. When active, DEV_STORES SHOULD NOT be
    // auto-healed because the whole point is to exercise the REAL App Pricing
    // flow. The store stays 'pending' (forced by the upsert above) so the
    // dashboard overlay shows and /api/billing/create returns Shopify's real
    // confirmation URL. Heal-skipping also protects against a stale test
    // subscription from an earlier test charge re-latching this store to
    // 'trial' without the user ever seeing the checkout.
    if (!DEV_SHOW_BILLING && merchant && (merchant.billing_status === 'pending' || merchant.billing_status === 'trial' || ['cancelled', 'declined', 'expired', 'frozen'].includes(merchant.billing_status))) {
      // First: check shop plan type. Dev/affiliate/staff stores bypass billing
      // entirely — set them as 'trial' with no Shopify charge ID. Production
      // stores get the App Pricing subscription lookup below.
      let isDevStore = false;
      try {
        isDevStore = await detectDevStore(shop, accessToken);
        console.log(`[OAuth] ${shop} dev-store detection: ${isDevStore}`);
      } catch (err) {
        console.warn(`[OAuth] ${shop} plan-type check failed: ${err.message} — assuming production`);
      }

      if (isDevStore && !DEV_SHOW_BILLING) {
        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);
        await db.run(`
          UPDATE merchants SET billing_status = 'trial', trial_ends_at = $1, trial_used = 1
          WHERE shop = $2
        `, [trialEnd.toISOString(), shop]);
        console.log(`[OAuth] ${shop} is a dev store — auto-activated with ${BILLING_PLAN.trial_days}-day trial, no Shopify charge`);
      } else {
        if (DEV_SHOW_BILLING) {
          console.log(`[OAuth] DEV_SHOW_BILLING active — ${shop} treated as production (dev-store auto-trial skipped)`);
        }
        try {
          const gqlRes = await axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
            query: `{
              currentAppInstallation {
                activeSubscriptions { id status trialDays remainingTrialDays }
              }
          }`,
        }, {
          headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' },
          timeout: 8000,
        });
        const subs = gqlRes.data?.data?.currentAppInstallation?.activeSubscriptions || [];
        const activeSub = subs.find(s =>
          String(s.status).toUpperCase() === 'ACTIVE' || String(s.status).toUpperCase() === 'TRIALING'
        );
        if (activeSub) {
          const trialEnd = activeSub.remainingTrialDays && activeSub.remainingTrialDays > 0
            ? new Date(Date.now() + activeSub.remainingTrialDays * 86400000).toISOString()
            : null;
          await db.run(`
            UPDATE merchants SET
              billing_status = 'trial',
              trial_ends_at = $1,
              shopify_charge_id = $2,
              trial_used = 1
            WHERE shop = $3
          `, [trialEnd, String(activeSub.id).replace(/^gid:\/\/shopify\/AppSubscription\//, ''), shop]);
          console.log(`[OAuth] ${shop} App Pricing sub detected — status: ${activeSub.status}, trial until: ${trialEnd || 'n/api'}`);
        }
      } catch (healErr) {
        // Non-fatal: if this GraphQL call fails, the merchant still gets the
        // trial overlay and can click "Start Trial" manually (but it's
        // the manual flow that can fail with "Session expired").
        console.warn(`[OAuth] Could not heal billing for ${shop}: ${healErr.message}`);
      }
      } // end else (production store)
    }

    // Notify founder of new install (async, non-blocking)
    const notifyEmail = process.env.NOTIFY_EMAIL || 'stockyshift@stockyshift.com';
    sendPOEmail({
      to: notifyEmail,
      subject: `🎉 New install: ${shop}`,
      text: `Someone just installed StockyShift on ${shop}!\n\nInstall time: ${new Date().toISOString()}\nBilling status: pending (trial)\n\nView in Partner Dashboard:\nhttps://partners.shopify.com`,
    }).catch(err => console.warn(`[Notify] Failed to send install notification: ${err.message}`));

    // Webhooks are declared app-level in shopify.app.toml (app/uninstalled,
    // app_subscriptions/update) — Shopify registers them for ALL shops that
    // install this app, so no per-shop registration is needed here. Declaring
    // them in both places creates duplicate subscriptions and double deliveries.

    // Fetch merchant email from Shopify API (async, non-blocking, GraphQL)
    axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      query: `{ shop { email } }`,
    }, {
      headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' },
      timeout: 5000,
    }).then(async gqlRes => {
      const email = gqlRes.data?.data?.shop?.email;
      if (email) {
        await db.run('UPDATE merchants SET email = $1 WHERE shop = $2', [email, shop]);
      }
    }).catch(err => {
      console.warn(`[OAuth] Could not fetch email for ${shop}: ${err.message}`);
    });

    // Store shop in session so embedded iframe reload works without ?shop= in URL
    req.session.shop = shop;
    // State was already consumed right after validation above (line ~324).
    // Redirect merchant into the EMBEDDED app inside the Shopify admin
    // (matches /billing/confirm behavior — landing on the standalone /?shop=
    // page after install is jarring and doesn't match App Store expectations)
    res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift`);
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.status(500).send('Installation failed. Please try again.');
  }
});

// ─── App Config (exposes API key for App Bridge) ─────────────────────────

app.get('/api/config', (req, res) => {
  if (!SHOPIFY_API_KEY) {
    return res.status(500).json({ error: 'Server misconfigured: missing SHOPIFY_API_KEY' });
  }
  res.json({
    api_key: SHOPIFY_API_KEY,
    billing_test_mode: process.env.BILLING_TEST_MODE === 'true',
    dev_show_billing: DEV_SHOW_BILLING,
  });
});

// ─── Embedded App Entry ──────────────────────────────────────────────────

// Serve the dashboard for any root request with a shop parameter
app.get('/', async (req, res, next) => {
  try {
    let { shop, reauth } = req.query;
    if (!shop) {
      // Only check session if visitor has a session cookie (avoids ~500ms DB read for every landing page visitor)
      if (req.headers.cookie?.includes('connect.sid') && req.session?.shop) {
        return res.redirect(`/?shop=${encodeURIComponent(req.session.shop)}`);
      }
      // Landing page is static and shared — let browsers cache it for 5 min
      // so repeat visits don't round-trip (helps hide Render free-tier cold starts)
      res.set('Cache-Control', 'public, max-age=300');
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Force re-auth if ?reauth=1 (soft-deactivate, triggers fresh OAuth; data survives).
    // Only honor it for the authenticated session owner — without this check,
    // anyone knowing a shop domain could GET /?shop=victim&reauth=1 and null
    // the victim's token (forced re-auth DoS).
    if (reauth === '1' && req.session?.shop === shop) {
      await db.run('UPDATE merchants SET is_active = 0, access_token = \'\' WHERE shop = $1', [shop]);
      return sendAuthRedirect(res, `${APP_URL}/auth?shop=${encodeURIComponent(shop)}`);
    }

    // Check if merchant exists
    const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1 AND is_active = 1', [shop]);
    if (!merchant) {
      // Iframe-safe: serve an escape page instead of a 302. The embedded
      // iframe must never navigate to Shopify's auth pages directly.
      return sendAuthRedirect(res, `${APP_URL}/auth?shop=${encodeURIComponent(shop)}`);
    }

    // Force re-auth if merchant has a non-expiring token (no refresh_token) — API 2026-07 rejects them.
    // Soft-deactivate instead of DELETE so FK-linked data (vendors, POs, products) survives re-install.
    if (!merchant.refresh_token) {
      console.log(`[Auth] ${shop} has non-expiring token, forcing re-auth for API 2026-07 compatibility`);
      await db.run('UPDATE merchants SET is_active = 0, access_token = \'\' WHERE shop = $1', [shop]);
      return sendAuthRedirect(res, `${APP_URL}/auth?shop=${encodeURIComponent(shop)}`);
    }

    // Refresh session shop so subsequent API calls (which use getShop()) don't fail
    // when the session cookie expired or was lost (e.g. after session DB migration).
    req.session.shop = shop;

    // If SKIP_BILLING is true, force billing status to active (DEV ONLY — never in production)
    if (process.env.NODE_ENV !== 'production' && process.env.SKIP_BILLING === 'true') {
      await db.run(`UPDATE merchants SET billing_status = 'active' WHERE shop = $1`, [shop]);
    }

    // Send the dashboard HTML directly (NOT a redirect) so Shopify can't intercept.
    // must-revalidate: the dashboard is a live app — always serve the current
    // version (bug fixes land constantly), never a stale cached copy. Safari's
    // back/forward and iframe caches will otherwise serve an old JS bundle.
    res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
  } catch (e) {
    next(e);
  }
});

// ─── App Proxy Route ─────────────────────────────────────────────────────

// Shopify Admin proxies requests to /apps/stockyshift when the app is embedded
// The landing page detects the iframe context and handles auth redirect
app.get('/apps/stockyshift', async (req, res, next) => {
  try {
    // Extract shop from Shopify's signed proxy request
    let { shop } = req.query;
    if (!shop) {
      // Only check session if visitor has a session cookie (avoids ~500ms DB read for every landing page visitor)
      if (req.headers.cookie?.includes('connect.sid') && req.session?.shop) {
        return res.redirect(`/?shop=${encodeURIComponent(req.session.shop)}`);
      }
      // Landing page is static and shared — let browsers cache it for 5 min
      // so repeat visits don't round-trip (helps hide Render free-tier cold starts)
      res.set('Cache-Control', 'public, max-age=300');
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Check if merchant is authenticated
    const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1 AND is_active = 1', [shop]);

    // If SKIP_BILLING is true, force billing status to active (DEV ONLY)
    if (process.env.NODE_ENV !== 'production' && process.env.SKIP_BILLING === 'true' && merchant) {
      await db.run(`UPDATE merchants SET billing_status = 'active' WHERE shop = $1`, [shop]);
    }

    if (!merchant) {
      // Not authenticated — serve landing page, JS will redirect to auth
      // Landing page is static and shared — let browsers cache it for 5 min
      // so repeat visits don't round-trip (helps hide Render free-tier cold starts)
      res.set('Cache-Control', 'public, max-age=300');
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Force re-auth if old token (no refresh_token)
    // Soft-deactivate instead of DELETE so FK-linked data (vendors, POs, products) survives re-install.
    if (!merchant.refresh_token) {
      console.log(`[Auth] ${shop} (via proxy) has non-expiring token, forcing re-auth`);
      await db.run('UPDATE merchants SET is_active = 0, access_token = \'\' WHERE shop = $1', [shop]);
      // Landing page is static and shared — let browsers cache it for 5 min
      // so repeat visits don't round-trip (helps hide Render free-tier cold starts)
      res.set('Cache-Control', 'public, max-age=300');
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Refresh session shop so API calls (via getShop()) work even if session was stale
    req.session.shop = shop;

    // Authenticated — serve the dashboard directly through the iframe.
    // Same no-cache as the root route: never serve a stale JS bundle.
    res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
  } catch (e) {
    next(e);
  }
});

// ─── API Routes ──────────────────────────────────────────────────────────

// Helper: resolve the authenticated shop for this request, or null.
// Priority: 1) Bearer token (JWT from App Bridge - embedded mode),
//           2) Session cookie shop (standalone mode).
// The query/body fallback has been REMOVED to prevent unauthenticated
// API access. Use a valid Bearer token or session cookie.
function getShop(req) {
  if (req.shop) return req.shop;
  if (req.session?.shop) return req.session.shop;
  return null;
}

// Helper: requires an authenticated shop. Returns null and sends 401 if not authenticated.
function requireShop(req, res) {
  const shop = getShop(req);
  if (!shop) { res.status(401).json({ error: 'Authentication required' }); return null; }
  return shop;
}

// Store slug for https://admin.shopify.com/store/{slug} redirects: Shopify
// admin URLs use dashes where the store name has dots ("my.store" becomes
// "my-store"). Previous code only stripped the .myshopify.com suffix, so
// stores with dots in their name got redirected to a URL that 404s.
function storeSlug(shop) {
  return String(shop).replace(/\.myshopify\.com$/i, '').replace(/\./g, '-');
}

// Shopify returns this exact message when the access token is invalid or
// revoked (store uninstalled the app, token rotated, etc.). Any route that
// talks to Shopify must treat this as "connection expired" and return 401
// so the dashboard can trigger the reconnect flow — NOT a generic 500.
function isShopifyAuthError(err) {
  const status = err?.response?.status;
  const msg = String(err?.response?.data?.errors || err?.message || '');
  return status === 401 || msg.includes('Invalid API key or access token');
}

// A dead Shopify connection: soft-deactivate + purge tokens (data preserved,
// reinstall via /auth restores everything). Mirrors the uninstall webhook —
// covers cases where that webhook never fired (not registered, or Shopify
// revoked the token without delivering it).
// MUST NEVER THROW: this runs inside a catch block that then returns a 401
// to the dashboard. If the cleanup itself threw, the route shim forwards it
// to the global error middleware → "Internal server error" → the reconnect
// flow never triggers and the user is stuck (exactly the bug this fixes).
async function expireShopifyConnection(shop) {
  try {
    await db.run(`
      UPDATE merchants
      SET is_active = 0, access_token = \'\', refresh_token = NULL, expires_at = NULL
      WHERE shop = $1
    `, [shop]);
    console.warn(`[Auth] ${shop}: Shopify rejected credentials — connection expired, merchant soft-deactivated (data preserved for reinstall)`);
  } catch (err) {
    // Log and continue: the 401 response must still reach the dashboard.
    console.error(`[Auth] expireShopifyConnection failed for ${shop}: ${err.message} — will retry on next request`);
  }
}

// Helper: load merchant's access token with auto-refresh for expiring tokens (API 2026-07+)
async function refreshShopifyToken(shop, oldRefreshToken) {
  const params = new URLSearchParams({
    client_id: SHOPIFY_API_KEY,
    client_secret: SHOPIFY_API_SECRET,
    grant_type: 'refresh_token',
    refresh_token: oldRefreshToken,
  });
  const response = await axios.post(
    `https://${shop}/admin/oauth/access_token`,
    params.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 15000 }
  );
  const { access_token, expires_in, refresh_token: newRefreshToken } = response.data;
  const expires_at = expires_in
    ? new Date(Date.now() + expires_in * 1000).toISOString()
    : null;
  try {
    await db.run(`
      UPDATE merchants SET access_token = $1, refresh_token = $2, expires_at = $3 WHERE shop = $4
    `, [access_token, newRefreshToken, expires_at, shop]);
  } catch (err) {
    // Shopify ALREADY rotated the refresh token — if the persist fails we now
    // hold a consumed token and the next refresh will 401. Retry once
    // (idempotent UPDATE), then let the error surface loudly so it's noticed
    // before the token becomes unusable.
    console.error(`[Token] Persist new token for ${shop} failed: ${err.message} — retrying once`);
    await db.run(`
      UPDATE merchants SET access_token = $1, refresh_token = $2, expires_at = $3 WHERE shop = $4
    `, [access_token, newRefreshToken, expires_at, shop]);
  }
  return access_token;
}

// Per-shop token refresh lock — prevents multiple concurrent requests from
// each calling refresh_token (the first refresh invalidates the old token,
// so the others would fail with an expired refresh_token).
const refreshLocks = new Map();

async function getToken(shop) {
  const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1 AND is_active = 1', [shop]);
  if (!merchant?.access_token) return null;

  // If the token has an expiry and is within 5 min of expiring (or already expired), refresh it
  if (merchant.expires_at && merchant.refresh_token) {
    const expiresAt = new Date(merchant.expires_at).getTime();
    const fiveMinutesFromNow = Date.now() + 5 * 60 * 1000;
    if (expiresAt < fiveMinutesFromNow) {
      // Serialize refresh per shop: if another request is already refreshing,
      // await the same promise instead of firing a duplicate refresh.
      if (!refreshLocks.has(shop)) {
        refreshLocks.set(shop, (async () => {
          console.log(`[Token] Refreshing token for ${shop} (expired or expiring soon)`);
          return refreshShopifyToken(shop, merchant.refresh_token);
        })().finally(() => refreshLocks.delete(shop)));
      }
      try {
        return await refreshLocks.get(shop);
      } catch (err) {
        console.error(`[Token] Refresh failed for ${shop}:`, err.response?.data || err.message);
        // Fall through — return the old token and let the API call fail naturally
      }
    }
  }

  return merchant.access_token;
}

// GraphQL query for syncing products with variants and inventory (no REST API)
//
// NOTE on inventoryLevels(first: 10): keep the page size at 10 per inventory
// item to stay under Shopify's GraphQL query cost budget. Bumping it to 250
// multiplied query cost across every product x variant and broke sync for many
// stores with query-cost errors. Multi-location completeness for 11+ locations
// remains a documented v1 limitation; the correct fix is a separate location
// pagination pass, not inflating this nested connection. (These notes are
// deliberately JS comments - not GraphQL # comments - because Shopify's
// parser rejects certain characters inside inline # comments.)
const SYNC_PRODUCTS_QUERY = `
  query($first: Int!, $after: String) {
    products(first: $first, after: $after) {
      pageInfo { hasNextPage endCursor }
      edges {
        node {
          id
          title
                  variants(first: 100) {
            edges {
              node {
                id
                sku
                inventoryItem {
                  id
                  unitCost {
                    amount
                  }
                  inventoryLevels(first: 10) {
                    edges {
                      node {
                        quantities(names: ["available"]) {
                          name
                          quantity
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;

// Helper: extract numeric ID from Shopify GraphQL global ID (e.g. "gid://shopify/Product/123")
function gidToId(gid) {
  const parts = (gid || '').split('/');
  return parseInt(parts[parts.length - 1]) || null;
}

// Helper: convert numeric ID to Shopify GraphQL global ID
function idToGid(type, id) {
  if (!id) return null;
  return `gid://shopify/${type}/${id}`;
}

// Core sync logic — shared by the manual sync route and the daily auto-sync
// cron, so the 8 AM low-stock alerts run on fresh stock. Without auto-sync,
// stock goes stale the moment a merchant sells after their last manual sync.
async function runProductSync(shop, token) {
  try {
    // Fetch all products + variants + inventory via GraphQL
    const allVariants = [];
    let hasNextPage = true;
    let after = null;
    let pageCount = 0;
    const MAX_PAGES = 200; // 80 per page × 200 = 16,000 variants max per sync (cost-safe)

    while (hasNextPage && pageCount < MAX_PAGES) {
      pageCount++;
      const gqlRes = await axios.post(
        `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
        { query: SYNC_PRODUCTS_QUERY, variables: { first: 80, after } },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 30000 }
      );

      const data = gqlRes.data?.data?.products;
      if (!data) {
        const errs = gqlRes.data?.errors;
        throw new Error(errs ? errs.map(e => e.message).join('; ') : 'GraphQL returned no data');
      }

      for (const edge of data.edges) {
        const product = edge.node;
        const productId = gidToId(product.id);
        for (const vEdge of product.variants.edges) {
          const variant = vEdge.node;
          // Sum available across all locations
          let available = 0;
          if (variant.inventoryItem?.inventoryLevels?.edges) {
            for (const level of variant.inventoryItem.inventoryLevels.edges) {
              const qty = level.node.quantities?.find(q => q.name === 'available');
              available += qty ? qty.quantity : 0;
            }
          }
          allVariants.push({
            product_id: productId,
            variant_id: gidToId(variant.id),
            inventory_item_id: gidToId(variant.inventoryItem?.id),
            shop,
            title: product.title,
            sku: variant.sku || '',
            current_stock: available,
            // Shopify's unitCost (in the shop's base currency). Null when the
            // merchant doesn't track costs in Shopify — leave 0 so the PO
            // modal falls back to a blank field instead of a wrong number.
            unit_cost: variant.inventoryItem?.unitCost?.amount
              ? parseFloat(variant.inventoryItem.unitCost.amount)
              : 0,
          });
        }
      }

      hasNextPage = data.pageInfo.hasNextPage;
      after = data.pageInfo.endCursor;
    }

    // Upsert into local DB (single transaction for the whole sync)
    let variantCount = 0;
    const seenVariantIds = [];
    const syncCompleted = !hasNextPage; // false if we hit MAX_PAGES (partial sync)
    await db.transaction((tx) => {
      for (const v of allVariants) {
        tx.run(`
          INSERT INTO products (shopify_product_id, shopify_variant_id, inventory_item_id, shop, title, sku, current_stock, unit_cost)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          ON CONFLICT(shop, shopify_variant_id) DO UPDATE SET
            title = excluded.title,
            sku = excluded.sku,
            current_stock = excluded.current_stock,
            inventory_item_id = excluded.inventory_item_id,
            unit_cost = excluded.unit_cost,
            is_active = 1
        `, [v.product_id, v.variant_id, v.inventory_item_id, shop, v.title, v.sku, v.current_stock, v.unit_cost || 0]);
        seenVariantIds.push(v.variant_id);
        variantCount++;
      }

      // Deactivate variants that no longer exist in Shopify (deleted products/variants).
      // Only run when the sync completed fully — a partial sync (hit MAX_PAGES) means
      // unseen variants may still exist, so deactivating them would be wrong.
      if (syncCompleted && seenVariantIds.length > 0) {
        const CHUNK = 500;
        for (let i = 0; i < seenVariantIds.length; i += CHUNK) {
          const chunk = seenVariantIds.slice(i, i + CHUNK);
          const placeholders = chunk.map(() => '?').join(',');
          const sql = `UPDATE products SET is_active = 0 WHERE shop = ? AND is_active = 1 AND shopify_variant_id NOT IN (${placeholders})`;
          tx.run(sql, [shop, ...chunk]);
        }
      } else if (syncCompleted && seenVariantIds.length === 0) {
        // Store genuinely has zero variants in Shopify — deactivate everything
        tx.run('UPDATE products SET is_active = 0 WHERE shop = $1', [shop]);
      }
    });

    // partial: true when MAX_PAGES was hit — the merchant only saw part of
    // their catalog and must know, or they'll set reorder points on half
    // their SKUs and miss low-stock alerts on the rest.
    return { synced: variantCount, partial: !syncCompleted };
  } catch (err) {
    throw err; // caller (route or cron) decides how to surface the error
  }
}

// Sync products from Shopify (manual trigger)
// In-memory per-shop throttle: max one sync per shop per minute. Repeated
// bursts burn Shopify GraphQL API credits and can throttle the WHOLE app
// (Shopify's rate limits apply app-wide, not per store).
const syncThrottle = new Map();
app.post('/api/sync-products', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Shop not installed' });

  const now = Date.now();
  const lastSync = syncThrottle.get(shop) || 0;
  if (now - lastSync < 60000) {
    const waitSec = Math.ceil((60000 - (now - lastSync)) / 1000);
    return res.status(429).json({ error: `Please wait ${waitSec}s — syncs are limited to once per minute per store.` });
  }
  syncThrottle.set(shop, now);
  // Sweep stale entries so the map can't grow unbounded
  if (syncThrottle.size > 1000) {
    for (const [s, t] of syncThrottle) {
      if (now - t > 300000) syncThrottle.delete(s);
    }
  }

  try {
    const result = await runProductSync(shop, token);
    res.json(result);
  } catch (err) {
    // Dead token (store uninstalled or revoked access): tell the dashboard to
    // reconnect instead of showing a cryptic 500. Without this, the user sees
    // "Sync failed: Invalid API key or access token" and is stuck.
    if (isShopifyAuthError(err)) {
      await expireShopifyConnection(shop);
      return res.status(401).json({ error: 'Shopify connection expired — reconnect to continue.', reauth: true });
    }
    const detail = err.response?.data || err.message;
    const raw = typeof detail === 'object' ? JSON.stringify(detail) : String(detail);
    console.error('Sync error:', raw, err.stack);
    res.status(500).json({
      error: 'Sync failed',
      detail: raw.substring(0, 500),
      // Only include stack trace in non-production to avoid leaking internals
      ...(process.env.NODE_ENV !== 'production' ? { stack: err.stack?.substring(0, 300) } : {}),
    });
  }
});

// Get low stock products (below reorder point)
app.get('/api/low-stock', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  // Join products with vendors to show vendor info alongside low stock items
  const lowStock = await db.all(`
    SELECT p.*, v.name as vendor_name, v.email as vendor_email
    FROM products p
    LEFT JOIN vendors v ON p.preferred_vendor_id = v.id
    WHERE p.shop = $1
      AND p.is_active = 1
      AND p.reorder_point > 0
      AND p.current_stock <= p.reorder_point
    ORDER BY (p.reorder_point - p.current_stock) DESC
  `, [shop]);

  res.json(lowStock);
});

// Get all products
app.get('/api/products', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const products = await db.all(`
    SELECT p.*, v.name as vendor_name
    FROM products p
    LEFT JOIN vendors v ON p.preferred_vendor_id = v.id
    WHERE p.shop = $1 AND p.is_active = 1
    ORDER BY p.title
  `, [shop]);

  res.json(products);
});

// Export products as CSV (for migration/manual backup workflows)
// ─── CSV export (direct download with short-lived signed token) ────────
// The old fetch+blob+programmatic-click download trips Safari's download
// prompts and can leave the app in a weird state. Direct navigation to an
// attachment URL is reliable in EVERY browser — but the export routes need
// auth, and a bare <a href> has no Bearer header. So the client first asks
// for a 60-second HMAC-signed token (still authenticated via the normal
// session), then navigates to the export URL with ?dl=token. No blob, no
// iframe gymnastics, no popups.
app.get('/api/export/token', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const exp = Math.floor(Date.now() / 1000) + 60;
  const payload = `${shop}:${exp}`;
  const sig = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(payload).digest('hex');
  res.json({ token: `${Buffer.from(payload).toString('base64url')}.${sig}` });
});

// Verify a download token: returns the shop if valid and unexpired, else null.
function verifyDownloadToken(token) {
  if (!token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  let payloadStr;
  try { payloadStr = Buffer.from(payloadB64, 'base64url').toString(); } catch (_) { return null; }
  const expected = crypto.createHmac('sha256', process.env.SESSION_SECRET).update(payloadStr).digest('hex');
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const [shop, exp] = payloadStr.split(':');
  if (!shop || !exp || Number(exp) < Math.floor(Date.now() / 1000)) return null;
  if (!/^[a-z0-9-]+\.myshopify\.com$/i.test(shop)) return null;
  return shop;
}

app.get('/api/products/export', async (req, res) => {
  let shop = verifyDownloadToken(req.query.dl);
  if (!shop) shop = requireShop(req, res);
  if (!shop) return;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const products = await db.all(`
    SELECT p.title, p.sku, p.current_stock, p.reorder_point, COALESCE(p.unit_cost, 0) AS unit_cost,
           COALESCE(v.name, '') AS vendor_name
    FROM products p
    LEFT JOIN vendors v ON p.preferred_vendor_id = v.id
    WHERE p.shop = $1 AND p.is_active = 1
    ORDER BY p.title
  `, [shop]);

  // Escape CSV fields: quote if they contain comma, quote, or newline
  const esc = (v) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = ['title', 'sku', 'current_stock', 'reorder_point', 'unit_cost', 'vendor_name'];
  const lines = [header.map(esc).join(',')];
  for (const p of products) {
    lines.push([p.title, p.sku, p.current_stock, p.reorder_point, p.unit_cost, p.vendor_name].map(esc).join(','));
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="stockyshift-products-${shop.replace(/[^a-z0-9]/gi, '')}.csv"`);
  res.send('\uFEFF' + lines.join('\r\n')); // BOM so Excel opens UTF-8 correctly
});

// Update reorder point for a product
app.post('/api/products/reorder-point', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const { id, reorder_point, preferred_vendor_id } = req.body;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const productId = parseInt(id);
  if (!Number.isInteger(productId) || productId < 1) {
    return res.status(400).json({ error: 'Invalid product ID' });
  }

  // Validate reorder_point: must be a non-negative integer (defaults to 0)
  let reorderPoint = 0;
  if (reorder_point !== undefined && reorder_point !== null && reorder_point !== '') {
    reorderPoint = parseInt(reorder_point);
    if (!Number.isInteger(reorderPoint) || reorderPoint < 0) {
      return res.status(400).json({ error: 'Reorder point must be a non-negative integer' });
    }
  }

  // The vendor must belong to THIS shop — otherwise shop A could attach shop
  // B's vendor, and /api/products + /api/low-stock would then leak shop B's
  // vendor name/email to shop A through their JOIN.
  if (preferred_vendor_id !== undefined && preferred_vendor_id !== null && preferred_vendor_id !== '') {
    const vendorId = parseInt(preferred_vendor_id);
    if (!Number.isInteger(vendorId) || vendorId < 1) {
      return res.status(400).json({ error: 'Invalid vendor ID' });
    }
    const vendorCheck = await db.get('SELECT id FROM vendors WHERE id = $1 AND shop = $2', [vendorId, shop]);
    if (!vendorCheck) return res.status(400).json({ error: 'Vendor not found' });
  }

  if (preferred_vendor_id === undefined) {
    // Field not sent — preserve the existing vendor. Previous code wrote
    // NULL whenever the client omitted the field, silently detaching every
    // vendor whenever a merchant edited just the reorder point.
    await db.run(`
      UPDATE products SET reorder_point = $1 WHERE id = $2 AND shop = $3
    `, [reorderPoint, productId, shop]);
  } else {
    // Explicitly sent ('' clears the vendor, an id attaches it)
    await db.run(`
      UPDATE products SET reorder_point = $1, preferred_vendor_id = $2 WHERE id = $3 AND shop = $4
    `, [reorderPoint, preferred_vendor_id || null, productId, shop]);
  }

  res.json({ success: true });
});

// ─── Vendor Routes ───────────────────────────────────────────────────────

app.get('/api/vendors', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const vendors = await db.all('SELECT * FROM vendors WHERE shop = $1 ORDER BY name', [shop]);
  res.json(vendors);
});

app.post('/api/vendors', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const { email, min_order_amount } = req.body;
  const name = sanitizeText(req.body.name, 100);
  const notes = sanitizeText(req.body.notes, 255);
  if (!name || !email) return res.status(400).json({ error: 'Missing required fields' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  // Must be numeric — otherwise "abc" stores as text in the REAL column
  // and renders as "$NaN" in the dashboard
  let minOrderAmount = 0;
  if (min_order_amount !== undefined && min_order_amount !== '') {
    minOrderAmount = Number(min_order_amount);
    if (Number.isNaN(minOrderAmount)) return res.status(400).json({ error: 'Minimum order amount must be a number' });
  }

  const result = await db.get(
    'INSERT INTO vendors (shop, name, email, min_order_amount, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [shop, name, email, minOrderAmount, notes || '']
  );
  res.json({ id: result.id });
});

// Update vendor
app.put('/api/vendors/:id', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  const { email, min_order_amount } = req.body;
  const name = sanitizeText(req.body.name, 100);
  const notes = sanitizeText(req.body.notes, 255);
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid vendor ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });

  // Must be numeric — otherwise "abc" stores as text in the REAL column
  // and renders as "$NaN" in the dashboard
  let minOrderAmount = 0;
  if (min_order_amount !== undefined && min_order_amount !== '') {
    minOrderAmount = Number(min_order_amount);
    if (Number.isNaN(minOrderAmount)) return res.status(400).json({ error: 'Minimum order amount must be a number' });
  }

  await db.run(`
    UPDATE vendors SET name = $1, email = $2, min_order_amount = $3, notes = $4
    WHERE id = $5 AND shop = $6
  `, [name, email, minOrderAmount, notes || '', id, shop]);

  res.json({ success: true });
});

// Delete vendor
app.delete('/api/vendors/:id', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid vendor ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  // Check if vendor has POs — count + delete in ONE synchronous transaction
  // so a PO created in another tab between the check and the delete cannot
  // leave a dangling vendor reference (TOCTOU). Native better-sqlite3
  // transaction: no awaits inside, nothing can interleave.
  // NOTE: db.transaction returns a Promise (db.js wraps the synchronous
  // better-sqlite3 transaction in Promise.resolve). We MUST await it — the
  // previous code read `del.blocked` from the un-awaited Promise, which is
  // always undefined, so the blocked check was bypassed and the server
  // returned {success:true} even when 0 rows were deleted (because the
  // transaction had short-circuited on the blocked path).
  const del = await db.transaction((tx) => {
    const poCount = tx.get('SELECT COUNT(*) AS count FROM purchase_orders WHERE vendor_id = $1 AND shop = $2', [id, shop]);
    if (poCount.count > 0) return { blocked: true, count: poCount.count };

    // Unset as preferred vendor on products (scoped to shop)
    tx.run('UPDATE products SET preferred_vendor_id = NULL WHERE preferred_vendor_id = $1 AND shop = $2', [id, shop]);
    // Delete vendor — capture changes so we can detect "0 rows deleted"
    // (e.g., vendor id belongs to another shop — shouldn't happen because
    // shop is from req.shop, but defensive)
    const delInfo = tx.run('DELETE FROM vendors WHERE id = $1 AND shop = $2', [id, shop]);
    return { blocked: false, deleted: delInfo.changes };
  });
  if (del.blocked) {
    return res.status(400).json({
      error: `Cannot delete: vendor has ${del.count} existing purchase order(s). Delete the POs first.`
    });
  }
  if (!del.deleted) {
    // Transaction ran but no row matched (id+shop combo not in vendors table)
    return res.status(404).json({ error: 'Vendor not found for this shop' });
  }

  res.json({ success: true });
});

// ─── PO Routes ───────────────────────────────────────────────────────────



app.post('/api/purchase-orders', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const { vendor_id, items } = req.body;
  const notes = sanitizeText(req.body.notes, 500);
  if (!vendor_id || !items?.length) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!/^\d+$/.test(vendor_id)) return res.status(400).json({ error: 'Invalid vendor ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });
  // Verify vendor belongs to this shop
  const vendorCheck = await db.get('SELECT id FROM vendors WHERE id = $1 AND shop = $2', [vendor_id, shop]);
  if (!vendorCheck) return res.status(400).json({ error: 'Vendor not found' });

  // Verify every product belongs to THIS shop BEFORE writing anything —
  // otherwise a PO could reference another shop's product, and receiving
  // would push the wrong inventory item (or corrupt the local DB).
  for (const item of items) {
    const productId = parseInt(item.product_id);
    if (!Number.isInteger(productId) || productId < 1) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }
    const productCheck = await db.get('SELECT id FROM products WHERE id = $1 AND shop = $2', [productId, shop]);
    if (!productCheck) return res.status(400).json({ error: `Product ${item.product_id} not found` });
    item.product_id = productId;
  }

  // Generate PO number with random suffix to prevent collision on rapid double-click
  // 4-byte random suffix: 2^32 possibilities per millisecond — collision
  // effectively impossible (2-byte suffix was 1/65536 per same-ms pair)
  const poNumber = `PO-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  let total = 0;

  // Calculate total with input validation
  for (const item of items) {
    const qty = parseInt(item.ordered_qty);
    const cost = parseFloat(item.unit_cost) || 0;
    if (!Number.isFinite(qty) || qty < 1) {
      return res.status(400).json({ error: 'ordered_qty must be a positive number' });
    }
    if (cost < 0) {
      return res.status(400).json({ error: 'unit_cost cannot be negative' });
    }
    total += qty * cost;
    item.ordered_qty = qty;
    item.unit_cost = cost;
  }

  const poId = await db.transaction((tx) => {
    const poResult = tx.get(`
      INSERT INTO purchase_orders (shop, vendor_id, po_number, total, notes)
      VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, [shop, vendor_id, poNumber, total, notes || '']);

    const newPoId = poResult.id;

    for (const item of items) {
      // Fetch product title/sku at creation time (denormalized — survives product deletion)
      const product = tx.get('SELECT title, sku FROM products WHERE id = $1', [item.product_id]);
      tx.run(`
        INSERT INTO po_line_items (po_id, product_id, product_title, product_sku, ordered_qty, unit_cost)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [newPoId, item.product_id, product?.title || '', product?.sku || '', item.ordered_qty, item.unit_cost || 0]);
    }

    return newPoId;
  });
  res.json({ po_id: poId, po_number: poNumber, total });
});

// Send PO email
// Per-shop throttle for PO emails: a scripted merchant (or a double-click
// storm) could otherwise blast the SMTP provider — burning Resend quota,
// spamming vendor inboxes, and damaging the sending domain's reputation.
// One send per 6s per shop (10/min) is generous for real usage.
const sendThrottle = new Map();

app.post('/api/purchase-orders/:id/send', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid PO ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const sendNow = Date.now();
  const lastSend = sendThrottle.get(shop) || 0;
  if (sendNow - lastSend < 6000) {
    const waitSec = Math.ceil((6000 - (sendNow - lastSend)) / 1000);
    return res.status(429).json({ error: `Please wait ${waitSec}s between sends.` });
  }
  sendThrottle.set(shop, sendNow);
  // Sweep stale entries so the map can't grow unbounded
  if (sendThrottle.size > 1000) {
    for (const [s, t] of sendThrottle) {
      if (sendNow - t > 600000) sendThrottle.delete(s);
    }
  }

  const po = await db.get(`
    SELECT po.*, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.id = $1 AND po.shop = $2
  `, [id, shop]);

  if (!po) return res.status(404).json({ error: 'PO not found' });

  // UI only shows Send for drafts, but the API must enforce it too —
  // re-sending a fully received PO would email the vendor a stale order.
  if (po.status === 'received') {
    return res.status(400).json({ error: 'This purchase order has already been received and cannot be re-sent.' });
  }

  // Use denormalized product_title/product_sku (stored at PO creation time)
  // so POs are not broken if the product is later deleted. Fall back to JOIN
  // for POs created before the denormalization migration.
  const lineItems = await db.all(`
    SELECT pli.*,
           COALESCE(pli.product_title, p.title) AS title,
           COALESCE(pli.product_sku, p.sku) AS sku
    FROM po_line_items pli
    LEFT JOIN products p ON pli.product_id = p.id
    WHERE pli.po_id = $1
  `, [id]);

  try {
    // Generate PDF
    const pdfBuffer = await generatePO(po, lineItems);

    // Send email
    await sendPOEmail({
      to: po.vendor_email,
      subject: `Purchase Order ${po.po_number}`,
      text: `Please find attached Purchase Order ${po.po_number}.`,
      attachment: {
        filename: `${po.po_number}.pdf`,
        content: pdfBuffer,
      },
    });

    // Mark as sent
    await db.run(`
      UPDATE purchase_orders SET status = 'sent', emailed_at = CURRENT_TIMESTAMP WHERE id = $1
    `, [id]);

    res.json({ success: true });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// Receive against PO (also updates inventory in Shopify)
// Serialize receives per PO. The local DB math is atomic (sync transaction),
// but the Shopify inventory push happens AFTER commit — two concurrent
// receives on the same PO would both push their deltas (double-apply) while
// the UI shows only the first. A per-PO in-flight lock rejects the second
// with 409 until the first finishes.
const receiveLocks = new Map();

app.post('/api/purchase-orders/:id/receive', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  const { items } = req.body; // [{line_item_id, received_qty}]
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid PO ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const lockKey = `${shop}:${id}`; // per-shop: PO ids collide across shops
  if (receiveLocks.has(lockKey)) {
    return res.status(409).json({ error: 'This PO is already being received — wait a moment and try again.' });
  }
  receiveLocks.set(lockKey, true);
  try {

  // Validate items shape and quantities (deltas, not absolute totals).
  // Empty arrays are a client bug — receiving nothing would flip the PO to
  // 'partial' purely from the status recompute, with zero actual receipt.
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'items must be a non-empty array' });
  }
  for (const item of items) {
    const delta = parseInt(item.received_delta ?? item.received_qty ?? 0);
    if (!Number.isFinite(delta) || delta <= 0) {
      return res.status(400).json({ error: 'received_delta must be a positive integer' });
    }
    item.received_delta = delta;
    const lineId = parseInt(item.line_item_id);
    if (!Number.isFinite(lineId) || lineId < 1) {
      return res.status(400).json({ error: 'line_item_id must be a positive integer' });
    }
    item.line_item_id = lineId;
  }

  // Verify PO belongs to this shop
  const po = await db.get('SELECT id, status FROM purchase_orders WHERE id = $1 AND shop = $2', [id, shop]);
  if (!po) return res.status(404).json({ error: 'PO not found' });
  // Only sent/partial POs can receive — draft POs were never shipped to the
  // vendor, so receiving against one would record inventory for stock the
  // merchant never ordered. (Fully received POs fail per-line anyway, since
  // every positive delta would exceed ordered_qty.)
  if (po.status !== 'sent' && po.status !== 'partial') {
    return res.status(400).json({ error: 'This PO cannot be received — only sent or partially received POs can receive stock' });
  }

  // Verify all line items belong to this PO and compute new totals
  // (validation happens again INSIDE the transaction — see below —
  //  so a concurrent request can't slip past with stale data)

  // Collect inventory adjustments needed (computed during transaction below)
  const adjustments = [];

  try {
    await db.transaction((tx) => {
    for (const item of items) {
      // Atomic re-check INSIDE the transaction (better-sqlite3 is synchronous,
      // so no other request can interleave here — closes the TOCTOU race)
      const current = tx.get(`
        SELECT ordered_qty, received_qty FROM po_line_items WHERE id = $1 AND po_id = $2
      `, [item.line_item_id, id]);
      if (!current) throw new Error(`Line item ${item.line_item_id} not found on this PO`);

      const oldQty = current.received_qty || 0;
      const delta = item.received_delta;
      const newQty = oldQty + delta;

      if (newQty > current.ordered_qty) {
        throw new Error(`Cannot receive more than ${current.ordered_qty} for this item (ordered: ${current.ordered_qty}, already received: ${oldQty})`);
      }

      tx.run(`
        UPDATE po_line_items SET received_qty = $1 WHERE id = $2 AND po_id = $3
      `, [newQty, item.line_item_id, id]);

      // Record adjustment for Shopify push (delta only)
      const lineItem = tx.get(`
        SELECT p.inventory_item_id, p.id AS product_id
        FROM po_line_items pli
        JOIN products p ON pli.product_id = p.id
        WHERE pli.id = $1
      `, [item.line_item_id]);

      if (lineItem?.inventory_item_id) {
        adjustments.push({
          inventory_item_id: lineItem.inventory_item_id,
          product_id: lineItem.product_id,
          line_item_id: item.line_item_id,
          delta,
        });
      }
    }

    // Check if all items are fully received
    const allItems = tx.all(`
      SELECT ordered_qty, received_qty FROM po_line_items WHERE po_id = $1
    `, [id]);

    const allReceived = allItems.every(i => i.received_qty >= i.ordered_qty);

    if (allReceived) {
      tx.run(`
        UPDATE purchase_orders SET status = 'received', received_at = CURRENT_TIMESTAMP WHERE id = $1
      `, [id]);
    } else {
      tx.run(`
        UPDATE purchase_orders SET status = 'partial' WHERE id = $1
      `, [id]);
    }
    });
  } catch (err) {
    // Validation errors thrown inside the transaction (over-receipt, line
    // item mismatch) are USER errors → 400 with the readable message.
    // Anything else (SQLITE_BUSY, etc.) rethrows → 500 via the global handler.
    const msg = String(err?.message || '');
    if (msg.startsWith('Cannot receive more than') || msg.startsWith('Line item')) {
      return res.status(400).json({ error: msg });
    }
    throw err;
  }

  // After transaction: push inventory adjustments to Shopify. If a push fails,
  // roll back the affected line item's received_qty to its old value so the UI
  // stays consistent with actual inventory.
  if (adjustments.length > 0) {
    let locationId = null;
    const failedLineItemIds = new Set();
    // Dead Shopify connection flag: when set, roll back everything Shopify
    // never confirmed and ONLY THEN return 401. The previous code returned
    // 401 from inside the push loop/catch, skipping the rollback — leaving
    // received_qty committed locally for adjustments Shopify never applied.
    let deadConnection = false;
    try {
      const token = await getToken(shop);
      // Get first location via GraphQL (most merchants have only one)
      const locRes = await axios.post(
        `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
        { query: `{ locations(first: 1) { edges { node { id } } } }` },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
      );
      locationId = locRes.data?.data?.locations?.edges?.[0]?.node?.id || null;

      if (locationId) {
        for (let i = 0; i < adjustments.length; i++) {
          const adj = adjustments[i];
          const mutation = `
            mutation($input: InventoryAdjustQuantitiesInput!) {
              inventoryAdjustQuantities(input: $input) {
                userErrors { field message }
              }
            }
          `;
          try {
            const adjRes = await axios.post(
              `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
              {
                query: mutation,
                variables: {
                  input: {
                    reason: "received",
                    referenceDocumentUri: `stockyshift://purchase-order/${id}`,
                    changes: [{
                      inventoryItemId: idToGid('InventoryItem', adj.inventory_item_id),
                      locationId: locationId,
                      delta: adj.delta,
                    }],
                  },
                },
              },
              {
                headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
                timeout: 10000,
              }
            );
            const userErrors = adjRes.data?.data?.inventoryAdjustQuantities?.userErrors || [];
            if (userErrors.length > 0) {
              throw new Error(userErrors.map(e => e.message).join('; '));
            }
            // Only mark local stock after Shopify accepted the adjustment
            await db.run('UPDATE products SET current_stock = current_stock + $1 WHERE id = $2 AND shop = $3',
              [adj.delta, adj.product_id, shop]);
          } catch (itemErr) {
            // Dead connection (store uninstalled / token revoked): mark this
            // item AND everything after it for rollback (only Shopify-confirmed
            // pushes keep their local received_qty), stop pushing, then fall
            // through to the rollback block below — the 401 is sent AFTER the
            // rollback so local state matches what Shopify actually saw.
            if (isShopifyAuthError(itemErr)) {
              await expireShopifyConnection(shop);
              deadConnection = true;
              for (let j = i; j < adjustments.length; j++) {
                failedLineItemIds.add(adjustments[j].line_item_id);
              }
              break;
            }
            failedLineItemIds.add(adj.line_item_id);
            console.error(`[Receive] Failed to push inventory for item ${adj.inventory_item_id} (${shop}):`, itemErr.message);
          }
        }
        if (!deadConnection) console.log(`[Receive] Shopify inventory updated for ${shop} at location ${locationId}`);
      } else {
        // No location found — all adjustments failed
        for (const adj of adjustments) {
          failedLineItemIds.add(adj.line_item_id);
        }
        console.warn(`[Receive] No locations found for ${shop} — Shopify inventory not updated`);
      }
    } catch (err) {
      // Dead connection on the locations query (the first Shopify call): no
      // adjustment was pushed, so EVERY local received_qty commit (done in the
      // sync transaction above) needs rollback before the 401 goes out.
      if (isShopifyAuthError(err)) {
        await expireShopifyConnection(shop);
        deadConnection = true;
        for (const adj of adjustments) {
          failedLineItemIds.add(adj.line_item_id);
        }
      } else {
        // Entire Shopify push failed — all adjustments need rollback
        for (const adj of adjustments) {
          failedLineItemIds.add(adj.line_item_id);
        }
        console.error(`[Receive] Shopify inventory update failed for ${shop}:`, err.response?.data || err.message);
      }
    }

    // Roll back received_qty for any items whose Shopify push failed.
    // All rollback writes + the status recompute happen in ONE transaction:
    // previously each UPDATE auto-committed separately, so a crash mid-rollback
    // left received_qty diverging from Shopify inventory.
    if (failedLineItemIds.size > 0) {
      await db.transaction((tx) => {
        for (const lineItemId of failedLineItemIds) {
          // Subtract the delta (not a snapshot — current value is authoritative)
          tx.run(`
            UPDATE po_line_items SET received_qty = MAX(received_qty - $1, 0)
            WHERE id = $2 AND po_id = $3
          `, [adjustments.find(a => a.line_item_id === lineItemId)?.delta || 0, lineItemId, id]);
          console.log(`[Receive] Rolled back received_qty for line item ${lineItemId} (Shopify push failed)`);
        }
        console.warn(`[Receive] ${failedLineItemIds.size} item(s) rolled back. Total pushed: ${adjustments.length - failedLineItemIds.size} of ${adjustments.length}.`);

        // Recompute PO status from actual received quantities — otherwise the PO
        // stays 'received'/'partial' even though some (or all) items were rolled back.
        const afterRollback = tx.all(`
          SELECT ordered_qty, received_qty FROM po_line_items WHERE po_id = $1
        `, [id]);

        if (afterRollback.length === 0) throw new Error('PO not found');

        const totalOrdered = afterRollback.reduce((s, i) => s + (i.ordered_qty || 0), 0);
        const totalReceived = afterRollback.reduce((s, i) => s + (i.received_qty || 0), 0);

        let newStatus = 'sent';
        if (totalReceived >= totalOrdered && totalOrdered > 0) newStatus = 'received';
        else if (totalReceived > 0) newStatus = 'partial';

        // Clear received_at if the rollback drops the PO out of 'received' —
        // otherwise the timestamp records a receipt that was rolled back.
        tx.run(`
          UPDATE purchase_orders
          SET status = $1,
              received_at = CASE WHEN $1 = 'received' THEN received_at ELSE NULL END
          WHERE id = $2
        `, [newStatus, id]);
        console.warn(`[Receive] PO ${id} status recomputed to '${newStatus}' after rollback`);
      });
    }

    // Rollback has run (if anything failed) — only now is local state
    // consistent with what Shopify actually saw, so it's safe to surface the
    // reconnect prompt.
    if (deadConnection) {
      return res.status(401).json({ error: 'Shopify connection expired — reconnect to continue.', reauth: true });
    }
  }

  res.json({ success: true, adjustments: adjustments.length });
  } finally {
    receiveLocks.delete(lockKey);
  }
});

app.get('/api/purchase-orders', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const pos = await db.all(`
    SELECT po.*, v.name as vendor_name
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.shop = $1
    ORDER BY po.created_at DESC
  `, [shop]);

  res.json(pos);
});

// Export purchase orders as CSV
app.get('/api/purchase-orders/export', async (req, res) => {
  let shop = verifyDownloadToken(req.query.dl);
  if (!shop) shop = requireShop(req, res);
  if (!shop) return;
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const pos = await db.all(`
    SELECT po.po_number, po.status, po.total, po.created_at, po.emailed_at, po.received_at,
           po.notes, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.shop = $1
    ORDER BY po.created_at DESC
  `, [shop]);

  const esc = (v) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = ['po_number', 'vendor_name', 'vendor_email', 'status', 'total', 'created_at', 'emailed_at', 'received_at', 'notes'];
  const lines = [header.map(esc).join(',')];
  for (const p of pos) {
    lines.push([p.po_number, p.vendor_name, p.vendor_email, p.status, p.total, p.created_at, p.emailed_at, p.received_at, p.notes].map(esc).join(','));
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="stockyshift-pos-${shop.replace(/[^a-z0-9]/gi, '')}.csv"`);
  res.send('\uFEFF' + lines.join('\r\n')); // BOM for Excel
});
app.get('/api/purchase-orders/:id', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid PO ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const po = await db.get(`
    SELECT po.*, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.id = $1 AND po.shop = $2
  `, [id, shop]);

  if (!po) return res.status(404).json({ error: 'PO not found' });

  // Use denormalized product_title/product_sku (survives product deletion).
  // Fall back to JOIN for POs created before the migration.
  const lineItems = await db.all(`
    SELECT pli.*,
           COALESCE(pli.product_title, p.title) AS title,
           COALESCE(pli.product_sku, p.sku) AS sku,
           p.current_stock
    FROM po_line_items pli
    LEFT JOIN products p ON pli.product_id = p.id
    WHERE pli.po_id = $1
  `, [id]);

  res.json({ ...po, line_items: lineItems });
});

// Delete a purchase order (only draft POs can be deleted)
app.delete('/api/purchase-orders/:id', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid PO ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const po = await db.get('SELECT status FROM purchase_orders WHERE id = $1 AND shop = $2', [id, shop]);
  if (!po) return res.status(404).json({ error: 'PO not found' });
  if (po.status !== 'draft') return res.status(400).json({ error: 'Only draft POs can be deleted' });

  await db.transaction((tx) => {
    tx.run('DELETE FROM po_line_items WHERE po_id = $1', [id]);
    tx.run('DELETE FROM purchase_orders WHERE id = $1', [id]);
  });

  res.json({ success: true });
});

// ─── Test Email (dev only) ────────────────────────────────────────────────

if (process.env.NODE_ENV !== 'production') {
  app.get('/api/test-email', async (req, res) => {
    const { to } = req.query;
    if (!to) return res.status(400).json({ error: 'Missing ?to=email' });

    try {
      await sendPOEmail({
        to,
        subject: 'StockyShift — Test Email',
        text: 'This is a test email from StockyShift.\n\nIf you received this, SMTP is working correctly.',
      });
      res.json({ success: true, message: `Test email sent to ${to}` });
    } catch (err) {
      console.error('[TestEmail]', err.message);
      res.status(500).json({ error: err.message });
    }
  });
}

// ─── Billing (Shopify Billing API) ──────────────────────────────────────

const BILLING_PLAN = {
  // MUST match the plan configured in the Partner Dashboard (App Pricing).
  // Dashboard plan: "starter" — $29/month, 7-day trial. If you rename the
  // plan in the dashboard, update this to match, or Shopify's manual
  // appSubscriptionCreate fallback can create mismatched charges.
  name: 'starter',
  price: 29.00,
  trial_days: 7,
  return_url: `${APP_URL}/billing/confirm`,
};

// App handle — the slug used in admin URLs (…/apps/stockyshift) and the
// Shopify App Pricing plan-selection page (…/charges/<appHandle>/pricing_plans).
// Must match the handle in shopify.app.toml / the Partner Dashboard listing.
const APP_HANDLE = 'stockyshift';

// DEV_SHOW_BILLING=true — testing-only escape hatch. On a dev store the
// normal OAuth heal auto-activates the 7-day trial (no Shopify charge), so
// the real App Pricing page is never exercised. When this flag is set, dev
// stores are treated like production stores: they stay 'pending', the
// dashboard shows the upgrade overlay, and /api/billing/create returns the
// REAL Shopify confirmation_url so the merchant can approve the actual
// App Pricing page. Must be explicitly enabled in env — off by default —
// so production (where this flag is not set) is unaffected.
const DEV_SHOW_BILLING = process.env.DEV_SHOW_BILLING === 'true';

// Check if billing is active (or in trial) for a shop
function isBillingActive(merchant) {
  if (process.env.NODE_ENV !== 'production' && process.env.SKIP_BILLING === 'true') return true;
  if (!merchant) return false;
  if (merchant.billing_status === 'active') return true;
  if (merchant.billing_status === 'trial') {
    // Check if trial hasn't expired
    if (merchant.trial_ends_at) {
      const trialEnd = new Date(merchant.trial_ends_at);
      if (trialEnd > new Date()) return true;
    }
  }
  return false;
}

// NOTE: The legacy Billing API (appSubscriptionCreate / createCharge) was
// removed. Shopify App Pricing (managed pricing) BLOCKS that mutation with
// "Managed Pricing Apps cannot use the Billing API (to create charges)".
// The only supported upgrade path is redirecting the merchant to the
// Shopify-hosted plan-selection page (see /api/billing/create).

// Get billing status for the dashboard
// Dev-store plan-type cache for the billing status self-heal (10 min TTL).
const __devStoreCache = new Map(); // shop -> { isDev: bool, at: ms }

// Detect whether a shop is a development store, with a REST fallback.
// The GraphQL partnerType query can fail transiently (timeout, hiccup);
// a false negative leaves a dev store stuck behind a paywall. Retry via
// the REST shop.json plan_name when GraphQL fails or returns nothing.
const DEV_PLAN_TYPES = ['affiliate', 'staff', 'shopify_plus_partner', 'partner_test'];
async function detectDevStore(shop, token) {
  try {
    const gql = await axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      query: `{ shop { plan { partnerType } } }`,
    }, {
      headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
      timeout: 8000,
    });
    const pt = gql.data?.data?.shop?.plan?.partnerType;
    if (pt) return DEV_PLAN_TYPES.includes(pt);
  } catch (err) {
    console.warn(`[DevDetect] GraphQL plan check failed for ${shop}: ${err.message} — trying REST fallback`);
  }
  try {
    const rest = await axios.get(`https://${shop}/admin/api/${API_VERSION}/shop.json`, {
      headers: { 'X-Shopify-Access-Token': token },
      timeout: 8000,
    });
    const planName = String(rest.data?.shop?.plan_name || '').toLowerCase();
    return ['affiliate', 'staff', 'partner_test', 'development'].some(p => planName.includes(p));
  } catch (err) {
    console.warn(`[DevDetect] REST plan check failed for ${shop}: ${err.message}`);
    return false;
  }
}

// TEMPORARY debug endpoint (REMOVE before launch): read-only merchant row
// inspector + live Shopify probe. Only responds when DEBUG_KEY env matches.
app.get('/api/debug/merchant', async (req, res) => {
  if (!process.env.DEBUG_KEY || req.query.key !== process.env.DEBUG_KEY) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const shop = String(req.query.shop || '').toLowerCase();
  if (!shop || !/^[a-z0-9-]+\.myshopify\.com$/.test(shop)) {
    return res.status(400).json({ error: 'shop required' });
  }
  const m = await db.get(
    'SELECT shop, billing_status, trial_used, is_active, uninstalled_at, trial_ends_at, shopify_charge_id, LENGTH(access_token) AS token_len, expires_at, installed_at FROM merchants WHERE shop = $1',
    [shop]
  );
  if (!m) return res.json({ not_found: true });
  let probe = null;
  try {
    const token = await getToken(shop);
    if (!token) {
      probe = { token: 'none' };
    } else {
      const r = await axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
        query: `{ shop { plan { partnerType } } currentAppInstallation { activeSubscriptions { id status } } }`,
      }, {
        headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
        timeout: 8000,
      });
      probe = {
        token: 'ok',
        partnerType: r.data?.data?.shop?.plan?.partnerType ?? null,
        subs: (r.data?.data?.currentAppInstallation?.activeSubscriptions || []).map(s => ({ id: s.id, status: s.status })),
        errors: r.data?.errors || null,
      };
      // REST fallback probe: what does plan_name report for this shop?
      try {
        const rest = await axios.get(`https://${shop}/admin/api/${API_VERSION}/shop.json`, {
          headers: { 'X-Shopify-Access-Token': token },
          timeout: 8000,
        });
        probe.rest_plan_name = rest.data?.shop?.plan_name ?? null;
      } catch (restErr) {
        probe.rest_error = restErr.message;
      }
    }
  } catch (e) {
    probe = { error: e.message };
  }
  return res.json({ merchant: m, probe });
});

app.get('/api/billing/status', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;

  const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1', [shop]);
  if (!merchant) return res.json({ status: 'not_installed' });

  if (process.env.NODE_ENV !== 'production' && process.env.SKIP_BILLING === 'true') {
    return res.json({ status: 'active', plan: BILLING_PLAN.name, skip_billing: true });
  }

  // Dev-store self-heal: with DEV_SHOW_BILLING off, dev stores must never
  // see a paywall. A reinstall (or a declined plan page) can leave a stale
  // non-active status (cancelled/declined/expired/frozen/pending) that the
  // /auth heal never touched — heal it here on every status read so a stuck
  // row can't block the dashboard. Production stores without an active
  // subscription stay in their state (correct paywall behavior).
  if (!DEV_SHOW_BILLING && merchant && ['pending', 'trial', 'cancelled', 'declined', 'expired', 'frozen'].includes(merchant.billing_status)) {
    try {
      const cached = __devStoreCache.get(shop);
      let isDevStore = cached ? cached.isDev : null;
      if (cached && Date.now() - cached.at > 10 * 60 * 1000) __devStoreCache.delete(shop);
      if (isDevStore === null) {
        const token = await getToken(shop);
        if (token) {
          isDevStore = await detectDevStore(shop, token);
          __devStoreCache.set(shop, { isDev: isDevStore, at: Date.now() });
        }
      }
      if (isDevStore) {
        const prev = merchant.billing_status;
        const trialEnd = new Date();
        trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);
        await db.run(`UPDATE merchants SET billing_status = 'trial', trial_ends_at = $1, trial_used = 1, trial_heal_note = $2 WHERE shop = $3`, [trialEnd.toISOString(), `dev-store self-heal (was '${prev}')`, shop]);
        merchant.billing_status = 'trial';
        merchant.trial_ends_at = trialEnd.toISOString();
        console.log(`[Billing] ${shop} dev store healed to trial (was stuck at '${prev}')`);
      }
    } catch (err) {
      console.warn(`[Billing] Dev-store heal check failed for ${shop}: ${err.message}`);
    }
  }

  // Calculate trial days remaining
  let trialDaysLeft = 0;
  if (merchant.trial_ends_at) {
    trialDaysLeft = Math.max(0, Math.ceil((new Date(merchant.trial_ends_at) - new Date()) / 86400000));
  }

  // Trial expired locally. With a Shopify-managed trial (trialDays in the
  // charge), Shopify starts billing after the trial WITHOUT changing the
  // subscription status — so no subscriptions_update webhook fires and the
  // local 'trial' status would never flip to 'active', locking out a paying
  // customer on day 8. Query Shopify live once and heal the local status.
  if (merchant.billing_status === 'trial' && merchant.trial_ends_at && new Date(merchant.trial_ends_at) <= new Date()) {
    try {
      const token = await getToken(shop);
      if (token) {
        const verifyRes = await axios.post(
          `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
          {
            query: `
              query {
                currentAppInstallation {
                  activeSubscriptions { id status }
                }
              }
            `,
          },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
        );
        const subs = verifyRes.data?.data?.currentAppInstallation?.activeSubscriptions || [];
        // Heal only when the ACTIVE subscription matches OUR charge_id (or its
        // GID form). Trial charges carry gid://shopify/AppSubscription/101...,
        // while webhook payloads historically used the bare numeric id — match
        // either. Without this, an unrelated ACTIVE subscription (e.g. a
        // second app's charge, or a stale leftover) could flip this merchant
        // to 'active' when they have no paid plan with us.
        const healed = subs.some(s =>
          String(s.status).toUpperCase() === 'ACTIVE' &&
          (!merchant.shopify_charge_id ||
            String(s.id) === String(merchant.shopify_charge_id) ||
            String(s.id).replace(/^gid:\/\/shopify\/AppSubscription\//, '') ===
              String(merchant.shopify_charge_id).replace(/^gid:\/\/shopify\/AppSubscription\//, ''))
        );
        if (healed) {
          await db.run(`UPDATE merchants SET billing_status = 'active', trial_ends_at = NULL WHERE shop = $1`, [shop]);
          merchant.billing_status = 'active';
          console.log(`[Billing] ${shop} trial expired but Shopify subscription ACTIVE — healed to 'active'`);
        }
      }
    } catch (err) {
      console.warn(`[Billing] Live status check failed for ${shop}: ${err.message} — keeping trial-expired status`);
    }
  }

  res.json({
    status: merchant.billing_status,
    charge_id: merchant.shopify_charge_id,
    trial_days_left: trialDaysLeft,
    plan: BILLING_PLAN.name,
    price: BILLING_PLAN.price,
    dev_show_billing: DEV_SHOW_BILLING,
    oauth_trial_heal: merchant.trial_heal_note || null,
  });
});

// Initiate billing (create charge, redirect to Shopify)
app.post('/api/billing/create', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;

  const token = await getToken(shop);
  if (!token) {
    console.error(`[Billing Debug] ${shop} getToken returned null — checking DB`);
    const rawMerchant = await db.get('SELECT access_token, is_active, expires_at FROM merchants WHERE shop = $1', [shop]);
    console.error(`[Billing Debug] merchant row:`, { has_token: !!rawMerchant?.access_token, is_active: rawMerchant?.is_active, expires_at: rawMerchant?.expires_at });
    return res.status(401).json({ error: 'Not installed' });
  }

  console.log(`[Billing Debug] ${shop} token present, length=${token.length}, trying App Pricing lookup`);

// Remove the disabled dev store block entirely — replace with a simple if-check
  // inside the App Pricing healing block below. The healing block runs for 'pending'
  // OR 'trial' merchants (dev stores that were reinstalled).

  // Shopify App Pricing: if the merchant already picked a plan on the App
  // Pricing screen, Shopify auto-creates the subscription. Query it live
  // and heal the local status instead of trying to create a duplicate
  // charge (which Shopify rejects, causing the "Session expired" error).
  const merchant = await db.get('SELECT billing_status, trial_used FROM merchants WHERE shop = $1', [shop]);
  if (merchant && (merchant.billing_status === 'pending' || merchant.billing_status === 'trial')) {
    try {
      const gqlRes = await axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
        query: `{
          currentAppInstallation {
            activeSubscriptions { id status trialDays remainingTrialDays }
          }
        }`,
      }, {
        headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' },
        timeout: 8000,
      });
      console.log(`[Billing Debug] ${shop} activeSubs response:`, JSON.stringify(gqlRes.data).slice(0, 500));
      const subs = gqlRes.data?.data?.currentAppInstallation?.activeSubscriptions || [];
      const activeSub = subs.find(s =>
        String(s.status).toUpperCase() === 'ACTIVE' || String(s.status).toUpperCase() === 'TRIALING'
      );
      if (activeSub) {
        const trialEnd = activeSub.remainingTrialDays && activeSub.remainingTrialDays > 0
          ? new Date(Date.now() + activeSub.remainingTrialDays * 86400000).toISOString()
          : new Date(Date.now() + BILLING_PLAN.trial_days * 86400000).toISOString();
        await db.run(`
          UPDATE merchants SET
            billing_status = 'trial',
            trial_ends_at = $1,
            shopify_charge_id = $2,
            trial_used = 1
          WHERE shop = $3
        `, [trialEnd, String(activeSub.id).replace(/^gid:\/\/shopify\/AppSubscription\//, ''), shop]);
        console.log(`[Billing] ${shop} App Pricing sub detected — redirecting to dashboard`);
        return res.json({ confirmation_url: `https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift` });
      }
    } catch (err) {
      console.warn(`[Billing] App Pricing lookup failed for ${shop}: ${err.message} — proceeding to plan-selection redirect`);
      console.warn(`[Billing Debug] Failure detail:`, JSON.stringify(err.response?.data || err.message).slice(0, 800));
    }
  }

  // BILLING_TEST_MODE: skip Shopify's billing API, activate locally
  if (process.env.BILLING_TEST_MODE === 'true') {
    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);
    await db.run(`
      UPDATE merchants SET billing_status = 'trial', trial_ends_at = $1, shopify_charge_id = NULL, trial_used = 1
      WHERE shop = $2
    `, [trialEnd.toISOString(), shop]);
    console.log(`[Billing] TEST MODE: ${shop} activated with ${BILLING_PLAN.trial_days}d trial`);
    // Return a URL that immediately redirects back to the dashboard
    return res.json({ confirmation_url: `${APP_URL}/billing/test-confirm?shop=${shop}` });
  }

  try {
    // Shopify App Pricing (managed pricing): the legacy Billing API
    // (appSubscriptionCreate) is BLOCKED for managed-pricing apps — Shopify
    // rejects it with "Managed Pricing Apps cannot use the Billing API (to
    // create charges)". The supported flow is to redirect the merchant to
    // Shopify's hosted plan-selection page. Shopify creates the subscription
    // on approval and returns to BILLING_PLAN.return_url with plan_handle +
    // shop params, which /billing/confirm verifies and heals.
    const pricingUrl = `https://admin.shopify.com/store/${storeSlug(shop)}/charges/${APP_HANDLE}/pricing_plans`;
    console.log(`[Billing] ${shop} redirecting to App Pricing plan selection: ${pricingUrl}`);
    return res.json({ confirmation_url: pricingUrl, app_pricing: true });
  } catch (err) {
    const detail = err.response?.data || err.message;
    const raw = JSON.stringify(detail);
    console.error('[Billing] Create charge error:', raw);
    // Always return a string for the error — never let [object Object] leak
    let errorMsg = '';
    if (typeof detail === 'string') {
      errorMsg = detail;
    } else if (detail?.errors) {
      const e = detail.errors;
      if (typeof e === 'string') errorMsg = e;
      else if (Array.isArray(e)) errorMsg = e.join('; ');
      else errorMsg = JSON.stringify(e);
    } else {
      errorMsg = raw || 'Unknown billing error';
    }
    res.status(500).json({ error: errorMsg });
  }
});

// Billing test confirm (simulated approval for BILLING_TEST_MODE)
app.get('/billing/test-confirm', async (req, res) => {
  // Guarded ONLY by BILLING_TEST_MODE, not NODE_ENV: running BILLING_TEST_MODE=true
  // in production is a legitimate pre-launch configuration (test charges), and
  // this route does nothing dangerous — activation happens in /api/billing/create,
  // which is already gated by the same flag. Blocking on NODE_ENV just made the
  // test-mode flow 404 in prod ("Not found" after clicking the trial button).
  if (process.env.BILLING_TEST_MODE !== 'true') {
    return res.status(404).send('Not found');
  }
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop');
  // Already activated by /api/billing/create, just redirect to dashboard
  res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift`);
});

// Callback from Shopify after merchant approves (or declines) billing
app.get('/billing/confirm', async (req, res) => {
  const { charge_id, subscription_id } = req.query;
  // Shopify's GraphQL billing redirect includes shop, but never trust the
  // query alone — fall back to the session cookie (same browser) so a
  // missing query param can't silently kill the approval flow.
  const shop = String(req.query.shop || req.session?.shop || '').toLowerCase();
  if (!shop) return res.status(400).send('Missing shop parameter — this URL should only be accessed via Shopify billing redirect');

  // No subscription identifiers: "merchant declined" — OR, with Shopify App
  // Pricing, the return from the plan-selection page (Shopify appends only
  // plan_handle + shop, no charge_id). Handle both:
  // SECURITY: this GET is unauthenticated (browser redirect from Shopify
  // billing), so it must not be usable as a downgrade vector: only touch shops
  // that actually have the app installed, and never flip an actively paying
  // merchant to 'declined' on query params alone — verify with Shopify first.
  if (!charge_id && !subscription_id) {
    // SECURITY (audit finding #1): this GET bears no subscription identifiers,
    // which means "merchant declined." It must only be honored for a merchant
    // who actually walked through the app's billing flow (their browser holds
    // the app session cookie for this shop). An attacker who crafts
    // /billing/confirm?shop=victim.myshopify.com with no valid session must
    // NOT be able to flip a pending/trial merchant to 'declined' (which would
    // lock the merchant out). Requiring req.session.shop === shop keeps the
    // legitimate decline redirect working (same browser) while blocking the
    // query-param-only downgrade vector.
    if (!req.session?.shop || req.session.shop !== shop) {
      console.warn(`[Billing] Blocked unauthenticated decline attempt for ${shop}`);
      // No-op, NOT an error page: the session lock must never brick a legitimate
      // decline when the 24h session cookie expired (e.g. merchant kept an iframe
      // open past expiry). The merchant just lands back on the billing overlay,
      // and an attacker's crafted downgrade URL is safely ignored either way.
      return res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift`);
    }
    const token = await getToken(shop);
    if (!token) return res.status(401).send('Not installed');
    // Never downgrade a merchant who still has active OR trialing subs in
    // Shopify, regardless of what the local billing_status says. This covers
    // both 'active' (paying a sub) and 'trial' (mid trial) merchants — an
    // attacker with a forged decline URL must not be able to shut down a
    // paying or trialing merchant. Fail closed: if the verification call fails,
    // assume the subscription is still active and do NOT downgrade.
    let liveSub = null;
    let verified = false; // whether the Shopify check completed successfully
    try {
      const verifyRes = await axios.post(
        `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
        { query: `{ currentAppInstallation { activeSubscriptions { id status remainingTrialDays } } }` },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
      );
      const subs = verifyRes.data?.data?.currentAppInstallation?.activeSubscriptions || [];
      const st = s => String(s.status).toUpperCase();
      liveSub = subs.find(s => st(s) === 'ACTIVE' || st(s) === 'TRIALING') || null;
      verified = true;
    } catch { /* verification failed — fail closed: never downgrade */ }
    if (!verified) {
      // Fail closed: can't confirm the merchant has NO subscription, so don't
      // mark them declined — just send them back to the dashboard.
      console.warn(`[Billing] ${shop} confirm verification failed — leaving status unchanged`);
      return res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift`);
    }
    if (liveSub) {
      // App Pricing approval (plan_handle return) or an existing sub — heal the
      // local row so the dashboard stops showing the paywall: set the charge id,
      // a trial window from Shopify's remainingTrialDays (fall back to our plan
      // config), and trial_used. Same normalization as the /api/billing/create
      // heal block.
      const trialEnd = liveSub.remainingTrialDays && liveSub.remainingTrialDays > 0
        ? new Date(Date.now() + liveSub.remainingTrialDays * 86400000).toISOString()
        : new Date(Date.now() + BILLING_PLAN.trial_days * 86400000).toISOString();
      await db.run(`
        UPDATE merchants SET
          billing_status = 'trial',
          trial_ends_at = $1,
          shopify_charge_id = $2,
          trial_used = 1
        WHERE shop = $3
      `, [trialEnd, String(liveSub.id).replace(/^gid:\/\/shopify\/AppSubscription\//, ''), shop]);
      console.log(`[Billing] ${shop} App Pricing approval detected — healed to trial until ${trialEnd}`);
      return res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift`);
    }
    await db.run(`UPDATE merchants SET billing_status = 'declined' WHERE shop = $1`, [shop]);
    return res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift?billing=declined`);
  }

  const token = await getToken(shop);
  if (!token) return res.status(401).send('Not installed');

  try {
    // With GraphQL, the subscription is already active when they return
    const subId = subscription_id || charge_id;

    // SECURITY: Verify with Shopify that this subscription actually exists and is ACTIVE.
    // Never trust query params alone — anyone could otherwise activate billing without paying.
    const verifyRes = await axios.post(
      `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
      {
        query: `
          query {
            currentAppInstallation {
              activeSubscriptions {
                id
                status
              }
            }
          }
        `,
      },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
    );

    const activeSubs = verifyRes.data?.data?.currentAppInstallation?.activeSubscriptions || [];
    const normalizedSubId = String(subId).replace(/^gid:\/\/shopify\/AppSubscription\//, '');
    const verified = activeSubs.some(sub =>
      sub.status === 'ACTIVE' &&
      (String(sub.id) === String(subId) || String(sub.id).replace(/^gid:\/\/shopify\/AppSubscription\//, '') === normalizedSubId)
    );

    if (!verified) {
      console.warn(`[Billing] ${shop} confirm rejected — no ACTIVE subscription matching ${subId}`);
      return res.status(402).send('Subscription not found or not active. Please complete billing to continue.');
    }

    // Calculate trial end date (7 days from now)
    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);

    const billingStatus = BILLING_PLAN.trial_days > 0 ? 'trial' : 'active';

    await db.run(`
      UPDATE merchants
      SET shopify_charge_id = $1, billing_status = $2, trial_ends_at = $3, trial_used = 1
      WHERE shop = $4
    `, [String(subId), billingStatus, trialEnd.toISOString(), shop]);

    console.log(`[Billing] ${shop} subscribed — ${billingStatus} until ${trialEnd.toISOString()}`);

    // Redirect back into the Shopify admin where the app is embedded.
    // (Landing on the bare app URL would drop the merchant out of the admin
    // chrome — the embedded route is admin.shopify.com/store/<slug>/apps/stockyshift.)
    res.redirect(`https://admin.shopify.com/store/${storeSlug(shop)}/apps/stockyshift`);
  } catch (err) {
    console.error('[Billing] Confirm error:', err.message);
    res.status(500).send('Failed to activate billing. Please try again.');
  }
});

// ─── Cancel pending subscriptions (for stuck billing) ─────────────────────
app.post('/api/billing/cancel-pending', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Not installed' });

  try {
    // First, try to cancel the charge we know about from the DB
    const merchant = await db.get('SELECT shopify_charge_id FROM merchants WHERE shop = $1', [shop]);
    const dbChargeId = merchant?.shopify_charge_id;

    const canceled = [];
    const allSubs = [];

    // If we have a stored charge_id, try to cancel it directly
    if (dbChargeId) {
      try {
        const cancelResult = await axios.post(
          `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
          {
            query: `mutation appSubscriptionCancel($id: ID!) { appSubscriptionCancel(id: $id) { userErrors { field message } } }`,
            variables: { id: dbChargeId },
          },
          { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
        );
        const errors = cancelResult.data?.data?.appSubscriptionCancel?.userErrors || [];
        if (errors.length > 0) {
          console.log(`Could not cancel ${dbChargeId}:`, errors.map(e => e.message).join('; '));
        } else {
          canceled.push(dbChargeId.split('/').pop());
        }
      } catch (e) {
        console.log(`Could not cancel subscription ${dbChargeId}:`, e.message);
      }
    }

    // Also query existing subscriptions via GraphQL for diagnostics
    const query = `{ appSubscriptions(first:10) { edges { node { id status } } } }`;
    const result = await axios.post(
      `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
      { query },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
    );

    const subscriptions = result.data?.data?.appSubscriptions?.edges || [];
    const foundSubs = subscriptions.map(e => ({ id: e.node.id, status: e.node.status }));

    // Cancel any additional pending subs found via the query
    for (const sub of subscriptions) {
      if (sub.node.status === 'PENDING' || sub.node.status === 'ACCEPTED') {
        const id = sub.node.id;
        if (!dbChargeId || id !== dbChargeId) { // skip if already tried above
          try {
            const cancelResult = await axios.post(
              `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
              {
                query: `mutation appSubscriptionCancel($subId: ID!) { appSubscriptionCancel(id: $subId) { userErrors { field message } } }`,
                variables: { subId: id },
              },
              { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
            );
            const errors = cancelResult.data?.data?.appSubscriptionCancel?.userErrors || [];
            if (errors.length > 0) {
              console.log(`Could not cancel ${id}:`, errors.map(e => e.message).join('; '));
            } else {
              canceled.push(id.split('/').pop());
            }
          } catch (e) {
            console.log(`Could not cancel subscription ${id}:`, e.message);
          }
        }
      }
    }

    // Clear charge_id from DB if we canceled successfully.
    // billing_status -> 'pending' (NOT NULL): NULL would permanently lock the
    // merchant out of billing — the dashboard's billing overlay only renders
    // for 'pending'/'trial'/expired states, so a NULL status with no charge_id
    // leaves them with a non-functional app and no way back to the trial page.
    await db.run("UPDATE merchants SET shopify_charge_id = NULL, billing_status = 'pending' WHERE shop = $1", [shop]);

    res.json({ canceled, message: `Canceled ${canceled.length} pending subscriptions`, db_charge_id: dbChargeId, found_subs: foundSubs });
  } catch (err) {
    console.error('[Billing] Cancel error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to cancel subscriptions' });
  }
});

// Cancel an ACTIVE subscription (full cancellation) from the Settings tab.
// Also used to let a merchant cancel directly instead of waiting for Shopify's
// subscriptions_update webhook (which fires asynchronously). Exempt from the
// billing middleware (BILLING_EXEMPT_PATHS) so a 'pending'/'trial' merchant can
// always reach it to clean up a stale subscription they no longer want.
app.post('/api/billing/cancel', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Not installed' });

  try {
    // Find the merchant's current subscription(s).
    const query = `{ currentAppInstallation { activeSubscriptions { id status } } }`;
    const result = await axios.post(
      `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
      { query },
      { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
    );
    const subs = result.data?.data?.currentAppInstallation?.activeSubscriptions || [];

    const canceled = [];
    const notCanceled = [];
    for (const sub of subs) {
      const st = String(sub.status).toUpperCase();
      // Only cancel subscriptions that are actually billable/live. A 'PAUSED'
      // / 'DECLINED' sub is already inactive and canceling it returns a
      // userError tastefully handled below.
      if (st === 'ACTIVE' || st === 'TRIALING' || st === 'ACCEPTED' || st === 'PENDING') {
        try {
          const cancelRes = await axios.post(
            `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
            {
              query: `mutation appSubscriptionCancel($id: ID!) { appSubscriptionCancel(id: $id) { appSubscription { id status } userErrors { field message } } }`,
              variables: { id: sub.id },
            },
            { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
          );
          const errs = cancelRes.data?.data?.appSubscriptionCancel?.userErrors || [];
          if (errs.length > 0) {
            notCanceled.push({ id: sub.id, error: errs.map(e => e.message).join('; ') });
          } else {
            canceled.push(sub.id.split('/').pop());
          }
        } catch (e) {
          notCanceled.push({ id: sub.id, error: e.message });
        }
      }
    }

    if (notCanceled.length > 0) {
      // Shopify still holds at least one subscription we could not cancel.
      // Do NOT flip local status to 'cancelled' while the merchant is still
      // being billed — that would let them cancel the app while Shopify
      // keeps charging. Return the error so the toast tells them to retry
      // (or cancel through Shopify's billing page directly).
      return res.status(500).json({ error: notCanceled[0].error, canceled, notCanceled });
    }

    // Reflect locally only now that all attempts succeeded. Keep the same
    // status vocabulary the subscriptions_update webhook uses ('cancelled')
    // so the dashboard's status handling stays consistent. shopify_charge_id
    // is preserved so the webhook's WHERE shopify_charge_id = $4 still
    // matches if it fires later.
    await db.run("UPDATE merchants SET billing_status = 'cancelled' WHERE shop = $1", [shop]);

    res.json({ canceled, message: `Canceled ${canceled.length} subscription${canceled.length === 1 ? '' : 's'}` });
  } catch (err) {
    console.error('[Billing] Cancel active error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to cancel subscription' });
  }
});

// ─── Debug: check which API key is active (dev only) ─────────────────────
if (process.env.NODE_ENV !== 'production') {
app.get('/api/debug', (req, res) => {
  // Debug-only: hide in production (same guard as /api/db-health)
  if (process.env.NODE_ENV === 'production') return res.status(403).json({ error: 'Forbidden' });
  const key = process.env.SHOPIFY_API_KEY || 'NOT SET';
  res.json({
    api_key_prefix: key.substring(0, 8) + '...',
    api_key_length: key.length,
    app_url: APP_URL,
    skip_billing: process.env.SKIP_BILLING,
    billing_test_mode: process.env.BILLING_TEST_MODE,
    scopes: process.env.SCOPES,
    node_env: process.env.NODE_ENV,
  });
});
}

// Render healthcheck path — 200 only when the DB is actually reachable.
// Deliberately unauthenticated (Render pings it without headers); reveals
// nothing beyond whether the app can serve. If the mounted disk fails, this
// 503s and Render restarts the service instead of serving a dead dashboard.
app.get('/healthz', async (req, res) => {
  try {
    await db.get('SELECT 1 AS ok');
    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[Health] /healthz DB check failed:', err.message);
    res.status(503).json({ ok: false });
  }
});

// Database health check (with 5s timeout). Blocked in production (no public health data).
app.get('/api/db-health', async (req, res) => {
  if (process.env.NODE_ENV === 'production') return res.status(403).json({ error: 'Forbidden' });
  const failTimer = setTimeout(() => {
    if (!res.headersSent) res.status(500).json({ error: 'Database connection timed out after 5s' });
  }, 5000);
  try {
    const result = await db.get('SELECT 1 AS ok');
    clearTimeout(failTimer);
    if (!res.headersSent) res.json({ connected: true, result });
  } catch (err) {
    clearTimeout(failTimer);
    if (!res.headersSent) res.status(500).json({ connected: false, error: err.message });
  }
});

// ─── Cron: Daily Auto-Sync (07:45) + Low Stock Check (08:00) ─────────────
// NOTE: cron runs in UTC (Render containers default to UTC). 07:45/08:00 UTC
// is 3:45/4:00 AM Eastern — intentional: sync + alerts land before the US
// workday. There is no per-merchant timezone support yet; if a merchant in
// another timezone complains about alert timing, this is the place to add
// per-shop TZ offsets (merchants.tz column or similar).

// Auto-sync every active merchant's products BEFORE the low-stock check so
// alerts fire on fresh stock levels. Manual-only sync meant a merchant who
// sold 50 units after syncing got 8 AM alerts with stale numbers.
cron.schedule('45 7 * * *', async () => {
  console.log('[Cron] Auto-syncing products for all active merchants...');
  try {
    const merchants = await db.all('SELECT shop FROM merchants WHERE is_active = 1');
    for (const m of merchants) {
      try {
        const token = await getToken(m.shop);
        if (!token) continue;
        const result = await runProductSync(m.shop, token);
        console.log(`[Cron] Auto-sync ${m.shop}: ${result.synced} variants${result.partial ? ' (partial — catalog exceeds 4,000 variants)' : ''}`);
      } catch (err) {
        // One shop's failure must not stop the rest of the daily run
        console.error(`[Cron] Auto-sync failed for ${m.shop}: ${err.message}`);
        // Dead connection: stop retrying every day — expire it (data preserved)
        if (isShopifyAuthError(err)) {
          await expireShopifyConnection(m.shop);
        }
      }
    }
  } catch (err) {
    console.error('[Cron] Auto-sync error:', err.message);
  }
});

// ─── Cron Job: GDPR 48h Purge Sweep ──────────────────────────────────────

// Belt-and-braces on top of Shopify's shop/redact webhook (which fires ~48h
// after uninstall): hard-delete any merchant soft-deactivated more than 48h
// ago whose data survived — e.g. if a redact webhook delivery permanently
// failed. Matches the privacy policy's "48 hours" retention promise.
// Mirrors the shop/redact deletion order (FK children first).
cron.schedule('30 4 * * *', async () => {
  console.log('[Cron] Running GDPR 48h purge sweep...');
  try {
    const stale = await db.all(`
      SELECT shop FROM merchants
      WHERE is_active = 0 AND uninstalled_at IS NOT NULL
        AND uninstalled_at < datetime('now', '-48 hours')
    `);
    for (const { shop } of stale) {
      await db.run('DELETE FROM po_line_items WHERE po_id IN (SELECT id FROM purchase_orders WHERE shop = $1)', [shop]);
      await db.run('DELETE FROM purchase_orders WHERE shop = $1', [shop]);
      await db.run('DELETE FROM products WHERE shop = $1', [shop]);
      await db.run('DELETE FROM vendors WHERE shop = $1', [shop]);
      await db.run('DELETE FROM oauth_states WHERE shop = $1', [shop]);
      await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
      console.log(`[GDPR] Sweep: purged ${shop} (uninstalled > 48h)`);
    }
  } catch (err) {
    console.error('[GDPR] Sweep error:', err.message);
  }
});

// ─── Cron Job: Daily Low Stock Check ─────────────────────────────────────

// Run at 08:00 UTC every day (3:45/4:00 AM Eastern; see the timezone note
// above the auto-sync cron — no per-shop timezone support yet).
cron.schedule('0 8 * * *', async () => {
  console.log('[Cron] Running daily low stock check...');
  try {
    // Only alert paying/trial-active merchants — skip expired, cancelled, declined
    const merchants = await db.all(`
      SELECT shop, email, billing_status, trial_ends_at FROM merchants
      WHERE is_active = 1
        AND email IS NOT NULL
        AND (
          billing_status = 'active'
          OR (billing_status = 'trial' AND trial_ends_at IS NOT NULL)
        )
    `);

    const now = new Date();
    for (const merchant of merchants) {
      // JS Date comparison (handles ISO 8601 correctly, unlike SQLite datetime())
      if (merchant.billing_status === 'trial' && merchant.trial_ends_at && new Date(merchant.trial_ends_at) <= now) {
        continue; // trial expired, skip
      }
      const lowStock = await db.all(`
        SELECT p.*, v.name as vendor_name
        FROM products p
        LEFT JOIN vendors v ON p.preferred_vendor_id = v.id
        WHERE p.shop = $1
          AND p.is_active = 1
          AND p.reorder_point > 0
          AND p.current_stock <= p.reorder_point
      `, [merchant.shop]);

        if (lowStock.length > 0) {
        console.log(`[Cron] ${merchant.shop}: ${lowStock.length} products below reorder point`);
        try {
          const lowStockList = lowStock.map(p =>
            `- ${p.title} (SKU: ${p.sku}) — Stock: ${p.current_stock}, Reorder at: ${p.reorder_point}`
          ).join('\n');

          // Link directly to the embedded app in Shopify admin (not standalone landing page)
          // Strip .myshopify.com suffix, then replace dots with dashes —
          // Shopify admin URL uses dashes for store names with dots
          // (e.g. 'my.store.myshopify.com' → admin URL is 'my-store')
          const storeName = merchant.shop
            .replace('.myshopify.com', '')
            .replace(/\./g, '-');
          const adminUrl = `https://admin.shopify.com/store/${storeName}/apps/stockyshift`;

          const emailText = `StockyShift — Low Stock Alert for ${merchant.shop}\n\n` +
            `The following products are below their reorder point:\n\n${lowStockList}\n\n` +
            `Open StockyShift in your Shopify admin to create purchase orders:\n${adminUrl}\n`;

          if (merchant.email) {
            await sendPOEmail({
              to: merchant.email,
              subject: `Low Stock Alert — ${lowStock.length} products need reordering`,
              text: emailText,
            });
          }
        } catch (err) {
          console.error(`[Cron] Failed to send alert for ${merchant.shop}: ${err.message}`);
        }
      }
    }
  } catch (err) {
    console.error('[Cron] Error:', err.message);
  }
});

// ─── Webhook: Handle app uninstall ───────────────────────────────────────

app.post('/webhooks/app/uninstalled', async (req, res) => {
  const shop = req.headers['x-shopify-shop-domain'];
  const hmac = req.headers['x-shopify-hmac-sha256'];
  if (!shop) return res.status(400).send('Missing shop');

  // Verify HMAC to ensure this is a real Shopify webhook
  if (!verifyWebhook(req.rawBody, hmac)) {
    console.warn(`[Webhook] Invalid HMAC for uninstall from ${shop}`);
    return res.status(401).send('Invalid HMAC');
  }

  // Defense in depth: verify topic header matches (prevents confusion attacks
  // where a valid webhook for a different topic is replayed to this endpoint)
  const topic = req.headers['x-shopify-topic'];
  if (topic && topic !== 'app/uninstalled') {
    console.warn(`[Webhook] Topic mismatch on /webhooks/app/uninstalled: got '${topic}'`);
    return res.status(400).send('Topic mismatch');
  }

  // Mark shop inactive but KEEP data — if merchant reinstalls within 48 hours,
  // their vendors, POs, and settings are restored. shop/redact (48h later) deletes everything.
  // Purge credentials: a store that revoked access must not keep a live token.
  // (Reinstall re-fetches fresh tokens, so the 48h restore window is unaffected.)
  await db.run(`
    UPDATE merchants
    SET is_active = 0,
        uninstalled_at = CURRENT_TIMESTAMP,
        access_token = \'\',
        refresh_token = NULL,
        expires_at = NULL
    WHERE shop = $1
  `, [shop]);

  console.log(`[Webhook] ${shop} uninstalled StockyShift — marked inactive, data preserved (48h grace)`);
  res.status(200).send('OK');
});

// ─── Webhook: Subscription status changes (keeps billing in sync) ─────────
// Without this, a merchant who cancels their subscription keeps billing_status='active'
// in our DB → they retain full access indefinitely without paying.
app.post('/webhooks/app/subscriptions_update', async (req, res) => {
  const shop = req.headers['x-shopify-shop-domain'];
  const hmac = req.headers['x-shopify-hmac-sha256'];
  if (!shop) return res.status(400).send('Missing shop');
  if (!verifyWebhook(req.rawBody, hmac)) {
    console.warn(`[Webhook] Invalid HMAC for subscriptions_update from ${shop}`);
    return res.status(401).send('Invalid HMAC');
  }

  try {
    const payload = req.body;
    const sub = payload?.app_subscription;
    if (!sub) {
      console.warn(`[Webhook] subscriptions_update from ${shop}: no app_subscription in payload`);
      return res.status(200).send('OK');
    }

    const subStatus = (sub.status || '').toUpperCase();
    const subId = String(sub.id || '');

    // Map Shopify subscription status to our billing_status
    // ACTIVE → 'active' (paid, in force)
    // CANCELLED/DECLINED/EXPIRED/FROZEN → mark as such
    const statusMap = {
      'ACTIVE': 'active',
      'CANCELLED': 'cancelled',
      'DECLINED': 'declined',
      'EXPIRED': 'expired',
      'FROZEN': 'frozen',
    };
    const newStatus = statusMap[subStatus] || null;

    if (newStatus) {
      const upd = await db.run(
        `UPDATE merchants
         SET billing_status = $1,
             shopify_charge_id = COALESCE($2, shopify_charge_id)
         WHERE shop = $3 AND shopify_charge_id = $4`,
        [newStatus, subId, shop, subId]
      );
      if (upd.changes === 0) {
        // Subscription changed but no merchant row has this charge_id. This
        // catches GID-format drift: we store gid://shopify/AppSubscription/101...,
        // while webhook payloads sometimes carry the bare numeric id. Log it
        // loudly — silent 0-row updates hide billing desync.
        console.warn(`[Webhook] ${shop} subscription ${subId} → '${newStatus}' but NO merchant row matched exact charge_id — retrying with normalized GID`);
        const norm = (id) => String(id || '').replace(/^gid:\/\/shopify\/AppSubscription\//, '');
        const merchantRow = await db.get('SELECT shopify_charge_id FROM merchants WHERE shop = $1', [shop]);
        if (merchantRow && norm(merchantRow.shopify_charge_id) === norm(subId)) {
          const upd2 = await db.run('UPDATE merchants SET billing_status = $1 WHERE shop = $2', [newStatus, shop]);
          console.log(`[Webhook] ${shop} charge_id normalized match (${subId}) → '${newStatus}' (${upd2.changes} row)`);
        } else {
          console.warn(`[Webhook] ${shop} no charge_id match for ${subId} — webhook ignored (stored: ${merchantRow?.shopify_charge_id || '(none)'})`);
        }
      } else {
        console.log(`[Webhook] ${shop} subscription ${subId} → '${newStatus}'`);
      }
    } else {
      console.log(`[Webhook] ${shop} subscriptions_update: unknown status '${subStatus}' — no update`);
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error(`[Webhook] subscriptions_update error for ${shop}:`, err.message);
    res.status(200).send('OK'); // always 200 so Shopify doesn't retry
  }
});

// ─── GDPR Webhooks (required for App Store review) ──────────────────────
// We store zero customer PII (no email, name, address for customers), so
// data_request and customers/redact are no-ops. shop/redact deletes everything.

// Unified GDPR endpoint — receives all compliance topics,
// dispatches based on X-Shopify-Topic header
app.post('/webhooks/gdpr', async (req, res) => {
  const topic = req.headers['x-shopify-topic'];
  const hmac = req.headers['x-shopify-hmac-sha256'];
  const shop = req.headers['x-shopify-shop-domain'];
  if (!verifyWebhook(req.rawBody, hmac)) return res.status(401).send('Invalid HMAC');

  switch (topic) {
    case 'customers/data_request':
      console.log(`[GDPR] customers/data_request received (no-op)`);
      return res.status(200).send('OK');
    case 'customers/redact':
      console.log(`[GDPR] customers/redact received (no-op)`);
      return res.status(200).send('OK');
    case 'shop/redact':
      if (!shop) return res.status(400).send('Missing shop');
      await db.run('DELETE FROM po_line_items WHERE po_id IN (SELECT id FROM purchase_orders WHERE shop = $1)', [shop]);
      await db.run('DELETE FROM purchase_orders WHERE shop = $1', [shop]);
      await db.run('DELETE FROM products WHERE shop = $1', [shop]);
      await db.run('DELETE FROM vendors WHERE shop = $1', [shop]);
      await db.run('DELETE FROM oauth_states WHERE shop = $1', [shop]);
      await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
      console.log(`[GDPR] shop/redact — all data deleted for ${shop}`);
      return res.status(200).send('OK');
    default:
      console.warn(`[GDPR] Unknown topic: ${topic}`);
      return res.status(200).send('OK');
  }
});

// Per-endpoint GDPR routes (kept for backward compatibility)

app.post('/webhooks/gdpr/customers/data_request', (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];
  if (!verifyWebhook(req.rawBody, hmac)) return res.status(401).send('Invalid HMAC');
  // No customer data stored — nothing to return
  console.log(`[GDPR] customers/data_request received (no-op)`);
  res.status(200).send('OK');
});

app.post('/webhooks/gdpr/customers/redact', (req, res) => {
  const hmac = req.headers['x-shopify-hmac-sha256'];
  if (!verifyWebhook(req.rawBody, hmac)) return res.status(401).send('Invalid HMAC');
  // No customer data stored — nothing to redact
  console.log(`[GDPR] customers/redact received (no-op)`);
  res.status(200).send('OK');
});

app.post('/webhooks/gdpr/shop/redact', async (req, res) => {
  const shop = req.headers['x-shopify-shop-domain'];
  const hmac = req.headers['x-shopify-hmac-sha256'];
  if (!shop) return res.status(400).send('Missing shop');
  if (!verifyWebhook(req.rawBody, hmac)) {
    console.warn(`[GDPR] Invalid HMAC for shop/redact from ${shop}`);
    return res.status(401).send('Invalid HMAC');
  }
  // Delete all data for this shop (same as uninstall but complete delete, not just deactivate)
  await db.run('DELETE FROM po_line_items WHERE po_id IN (SELECT id FROM purchase_orders WHERE shop = $1)', [shop]);
  await db.run('DELETE FROM purchase_orders WHERE shop = $1', [shop]);
  await db.run('DELETE FROM products WHERE shop = $1', [shop]);
  await db.run('DELETE FROM vendors WHERE shop = $1', [shop]);
  await db.run('DELETE FROM oauth_states WHERE shop = $1', [shop]);
  await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
  console.log(`[GDPR] shop/redact — all data deleted for ${shop}`);
  res.status(200).send('OK');
});

// ─── Error handling (must be registered AFTER all routes) ────────────────

// Global error handler — catches sync throws and next(err) from the route
// shim above. Returns JSON (never HTML) so the embedded dashboard can show
// a readable error instead of a blank iframe.
app.use((err, req, res, next) => {
  console.error('[Unhandled Error]', err.stack);
  if (res.headersSent) return next(err);
  res.status(500).json({
    error: 'Internal server error',
    detail: process.env.NODE_ENV === 'production' ? undefined : err.message,
  });
});

// Clean 404s for unmatched routes
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Belt-and-suspenders: keep the process alive if a rejection escapes the
// shim. A single failed request must never take down every store.
process.on('unhandledRejection', (e) => {
  console.error('[Unhandled Rejection]', e);
});

// Uncaught synchronous exceptions leave the process in an unknown state —
// log and exit so Render restarts a clean instance.
process.on('uncaughtException', (e) => {
  console.error('[Uncaught Exception]', e);
  process.exit(1);
});

// ─── Start ───────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`StockyShift running on port ${PORT}`);
  console.log(`OAuth callback URL: ${APP_URL}/auth/callback`);
  if (!APP_URL) console.error('FATAL: APP_URL not set — billing, OAuth, and webhooks will fail');
});
