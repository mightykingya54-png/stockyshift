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
  // Must not be expired
  if (payload.exp < Date.now() / 1000) return null;
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

// ─── Billing enforcement middleware ───────────────────────────────────────
// Enforces paywall server-side — an expired/cancelled merchant cannot use
// the API even if they bypass the client-side billing overlay.
// NOTE: this middleware is mounted at '/api', so req.path here is RELATIVE
// (e.g. '/billing/status', not '/api/billing/status').
const BILLING_EXEMPT_PATHS = [
  '/config',
  '/billing/status',
  '/billing/create',
  '/db-health',
  '/debug',
];
if (process.env.NODE_ENV !== 'production') BILLING_EXEMPT_PATHS.push('/test-email');

app.use('/api', async (req, res, next) => {
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
const SCOPES = process.env.SCOPES || 'read_products,write_products,read_inventory,write_inventory';
const APP_URL = process.env.SHOPIFY_APP_URL || process.env.APP_URL;

// Step 1: Redirect merchant to Shopify authorization
app.get('/auth', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop parameter');
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

  res.redirect(installUrl);
});

// Step 2: Handle OAuth callback
app.get('/auth/callback', async (req, res) => {
  const { shop, code, state } = req.query;

  // Verify single-use state and consume it (prevents replay)
  const stateRow = await db.get('SELECT shop, created_at FROM oauth_states WHERE state = $1', [state]);
  await db.run('DELETE FROM oauth_states WHERE state = $1', [state || '']);
  const stateAge = stateRow ? Date.now() - stateRow.created_at : Infinity;
  if (!stateRow || stateRow.shop !== shop || stateAge > 15 * 60 * 1000) {
    return res.status(403).send('State mismatch. Possible CSRF attack or expired link — try installing again.');
  }

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
      }
    );

    const tokenData = tokenResponse.data;
    console.log(`[OAuth] Token response for ${shop}:`, JSON.stringify(tokenData));
    const accessToken = tokenData.access_token;
    const refreshToken = tokenData.refresh_token || null;
    const expiresAt = tokenData.expires_in
      ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
      : null;

    // Store merchant in database — set billing to 'pending' so they see the trial offer page first
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
          WHEN trial_used = 0 AND billing_status NOT IN ('active') THEN 'pending'
          ELSE billing_status
        END,
        trial_ends_at = CASE
          WHEN trial_used = 0 AND billing_status NOT IN ('active') THEN NULL
          ELSE trial_ends_at
        END
    `, [shop, accessToken, refreshToken, expiresAt]);

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
    // Redirect merchant to the embedded app or dashboard
    res.redirect(`/?shop=${shop}`);
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
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Force re-auth if ?reauth=1 (soft-deactivate, triggers fresh OAuth; data survives)
    if (reauth === '1') {
      await db.run('UPDATE merchants SET is_active = 0, access_token = NULL WHERE shop = $1', [shop]);
      return res.redirect(`/auth?shop=${shop}`);
    }

    // Check if merchant exists
    const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1 AND is_active = 1', [shop]);
    if (!merchant) {
      return res.redirect(`/auth?shop=${shop}`);
    }

    // Force re-auth if merchant has a non-expiring token (no refresh_token) — API 2026-07 rejects them.
    // Soft-deactivate instead of DELETE so FK-linked data (vendors, POs, products) survives re-install.
    if (!merchant.refresh_token) {
      console.log(`[Auth] ${shop} has non-expiring token, forcing re-auth for API 2026-07 compatibility`);
      await db.run('UPDATE merchants SET is_active = 0, access_token = NULL WHERE shop = $1', [shop]);
      return res.redirect(`/auth?shop=${shop}`);
    }

    // Refresh session shop so subsequent API calls (which use getShop()) don't fail
    // when the session cookie expired or was lost (e.g. after session DB migration).
    req.session.shop = shop;

    // If SKIP_BILLING is true, force billing status to active (DEV ONLY — never in production)
    if (process.env.NODE_ENV !== 'production' && process.env.SKIP_BILLING === 'true') {
      await db.run(`UPDATE merchants SET billing_status = 'active' WHERE shop = $1`, [shop]);
    }

    // Send the dashboard HTML directly (NOT a redirect) so Shopify can't intercept
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
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Force re-auth if old token (no refresh_token)
    // Soft-deactivate instead of DELETE so FK-linked data (vendors, POs, products) survives re-install.
    if (!merchant.refresh_token) {
      console.log(`[Auth] ${shop} (via proxy) has non-expiring token, forcing re-auth`);
      await db.run('UPDATE merchants SET is_active = 0, access_token = NULL WHERE shop = $1', [shop]);
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Refresh session shop so API calls (via getShop()) work even if session was stale
    req.session.shop = shop;

    // Authenticated — serve the dashboard directly through the iframe
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
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  const { access_token, expires_in, refresh_token: newRefreshToken } = response.data;
  const expires_at = expires_in
    ? new Date(Date.now() + expires_in * 1000).toISOString()
    : null;
  await db.run(`
    UPDATE merchants SET access_token = $1, refresh_token = $2, expires_at = $3 WHERE shop = $4
  `, [access_token, newRefreshToken, expires_at, shop]);
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
                  # NOTE: Limited to first 10 locations. Merchants with 11+ locations
                  # will get incomplete inventory counts. Future fix: paginate all locations.
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

// Sync products from Shopify
app.post('/api/sync-products', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Shop not installed' });

  try {
    // Fetch all products + variants + inventory via GraphQL
    const allVariants = [];
    let hasNextPage = true;
    let after = null;
    let pageCount = 0;
    const MAX_PAGES = 50; // 80 per page × 50 = 4,000 variants max per sync

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
    await db.transaction(async (tx) => {
      for (const v of allVariants) {
        await tx.run(`
          INSERT INTO products (shopify_product_id, shopify_variant_id, inventory_item_id, shop, title, sku, current_stock)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT(shop, shopify_variant_id) DO UPDATE SET
            title = excluded.title,
            sku = excluded.sku,
            current_stock = excluded.current_stock,
            inventory_item_id = excluded.inventory_item_id,
            is_active = 1
        `, [v.product_id, v.variant_id, v.inventory_item_id, shop, v.title, v.sku, v.current_stock]);
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

    res.json({ synced: variantCount });
  } catch (err) {
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

  await db.run(`
    UPDATE products SET reorder_point = $1, preferred_vendor_id = $2 WHERE id = $3 AND shop = $4
  `, [reorderPoint, preferred_vendor_id || null, productId, shop]);

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
  const { name, email, min_order_amount, notes } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Missing required fields' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const result = await db.get(
    'INSERT INTO vendors (shop, name, email, min_order_amount, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [shop, name, email, min_order_amount || 0, notes || '']
  );
  res.json({ id: result.id });
});

// Update vendor
app.put('/api/vendors/:id', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  const { name, email, min_order_amount, notes } = req.body;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid vendor ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email format' });

  await db.run(`
    UPDATE vendors SET name = $1, email = $2, min_order_amount = $3, notes = $4
    WHERE id = $5 AND shop = $6
  `, [name, email, min_order_amount || 0, notes || '', id, shop]);

  res.json({ success: true });
});

// Delete vendor
app.delete('/api/vendors/:id', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid vendor ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  // Check if vendor has POs
  const poCount = await db.get('SELECT COUNT(*) AS count FROM purchase_orders WHERE vendor_id = $1 AND shop = $2', [id, shop]);
  if (poCount.count > 0) {
    return res.status(400).json({
      error: `Cannot delete: vendor has ${poCount.count} existing purchase order(s). Delete the POs first.`
    });
  }

  // Unset as preferred vendor on products (scoped to shop)
  await db.run('UPDATE products SET preferred_vendor_id = NULL WHERE preferred_vendor_id = $1 AND shop = $2', [id, shop]);
  // Delete vendor
  await db.run('DELETE FROM vendors WHERE id = $1 AND shop = $2', [id, shop]);

  res.json({ success: true });
});

// ─── PO Routes ───────────────────────────────────────────────────────────



app.post('/api/purchase-orders', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;
  const { vendor_id, items, notes } = req.body;
  if (!vendor_id || !items?.length) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!/^\d+$/.test(vendor_id)) return res.status(400).json({ error: 'Invalid vendor ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });
  // Verify vendor belongs to this shop
  const vendorCheck = await db.get('SELECT id FROM vendors WHERE id = $1 AND shop = $2', [vendor_id, shop]);
  if (!vendorCheck) return res.status(400).json({ error: 'Vendor not found' });

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

  const poId = await db.transaction(async (tx) => {
    const poResult = await tx.get(`
      INSERT INTO purchase_orders (shop, vendor_id, po_number, total, notes)
      VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, [shop, vendor_id, poNumber, total, notes || '']);

    const newPoId = poResult.id;

    for (const item of items) {
      // Fetch product title/sku at creation time (denormalized — survives product deletion)
      const product = await tx.get('SELECT title, sku FROM products WHERE id = $1', [item.product_id]);
      await tx.run(`
        INSERT INTO po_line_items (po_id, product_id, product_title, product_sku, ordered_qty, unit_cost)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [newPoId, item.product_id, product?.title || '', product?.sku || '', item.ordered_qty, item.unit_cost || 0]);
    }

    return newPoId;
  });
  res.json({ po_id: poId, po_number: poNumber, total });
});

// Send PO email
app.post('/api/purchase-orders/:id/send', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid PO ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const po = await db.get(`
    SELECT po.*, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.id = $1 AND po.shop = $2
  `, [id, shop]);

  if (!po) return res.status(404).json({ error: 'PO not found' });

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
app.post('/api/purchase-orders/:id/receive', async (req, res) => {
  const { id } = req.params;
  const shop = requireShop(req, res);
  if (!shop) return;
  const { items } = req.body; // [{line_item_id, received_qty}]
  if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'Invalid PO ID' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  // Validate items shape and quantities (deltas, not absolute totals)
  if (!Array.isArray(items)) {
    return res.status(400).json({ error: 'items must be an array' });
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
  const po = await db.get('SELECT id FROM purchase_orders WHERE id = $1 AND shop = $2', [id, shop]);
  if (!po) return res.status(404).json({ error: 'PO not found' });

  // Verify all line items belong to this PO and compute new totals
  // (validation happens again INSIDE the transaction — see below —
  //  so a concurrent request can't slip past with stale data)

  // Collect inventory adjustments needed (computed during transaction below)
  const adjustments = [];

  await db.transaction(async (tx) => {
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

      await tx.run(`
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

  // After transaction: push inventory adjustments to Shopify. If a push fails,
  // roll back the affected line item's received_qty to its old value so the UI
  // stays consistent with actual inventory.
  if (adjustments.length > 0) {
    let locationId = null;
    const failedLineItemIds = new Set();
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
        for (const adj of adjustments) {
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
            failedLineItemIds.add(adj.line_item_id);
            console.error(`[Receive] Failed to push inventory for item ${adj.inventory_item_id} (${shop}):`, itemErr.message);
          }
        }
        console.log(`[Receive] Shopify inventory updated for ${shop} at location ${locationId}`);
      } else {
        // No location found — all adjustments failed
        for (const adj of adjustments) {
          failedLineItemIds.add(adj.line_item_id);
        }
        console.warn(`[Receive] No locations found for ${shop} — Shopify inventory not updated`);
      }
    } catch (err) {
      // Entire Shopify push failed — all adjustments need rollback
      for (const adj of adjustments) {
        failedLineItemIds.add(adj.line_item_id);
      }
      console.error(`[Receive] Shopify inventory update failed for ${shop}:`, err.response?.data || err.message);
    }

    // Roll back received_qty for any items whose Shopify push failed
    if (failedLineItemIds.size > 0) {
      for (const lineItemId of failedLineItemIds) {
        // Subtract the delta (not a snapshot — current value is authoritative)
        await db.run(`
          UPDATE po_line_items SET received_qty = MAX(received_qty - $1, 0)
          WHERE id = $2 AND po_id = $3
        `, [adjustments.find(a => a.line_item_id === lineItemId)?.delta || 0, lineItemId, id]);
        console.log(`[Receive] Rolled back received_qty for line item ${lineItemId} (Shopify push failed)`);
      }
      console.warn(`[Receive] ${failedLineItemIds.size} item(s) rolled back. Total pushed: ${adjustments.length - failedLineItemIds.size} of ${adjustments.length}.`);

      // Recompute PO status from actual received quantities — otherwise the PO
      // stays 'received'/'partial' even though some (or all) items were rolled back.
      const afterRollback = await db.all(`
        SELECT ordered_qty, received_qty FROM po_line_items WHERE po_id = $1
      `, [id]);

      if (afterRollback.length === 0) return res.status(404).json({ error: 'PO not found' });

      const totalOrdered = afterRollback.reduce((s, i) => s + (i.ordered_qty || 0), 0);
      const totalReceived = afterRollback.reduce((s, i) => s + (i.received_qty || 0), 0);

      let newStatus = 'sent';
      if (totalReceived >= totalOrdered && totalOrdered > 0) newStatus = 'received';
      else if (totalReceived > 0) newStatus = 'partial';

      await db.run(`UPDATE purchase_orders SET status = $1 WHERE id = $2`, [newStatus, id]);
      console.warn(`[Receive] PO ${id} status recomputed to '${newStatus}' after rollback`);
    }
  }

  res.json({ success: true, adjustments: adjustments.length });
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

// Get single PO with line items
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

  await db.transaction(async (tx) => {
    await tx.run('DELETE FROM po_line_items WHERE po_id = $1', [id]);
    await tx.run('DELETE FROM purchase_orders WHERE id = $1', [id]);
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
  name: 'StockyShift Monthly',
  price: 29.00,
  trial_days: 7,
  return_url: `${APP_URL}/billing/confirm`,
};

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

// GraphQL mutation to create a subscription
const CREATE_SUBSCRIPTION_MUTATION = `
  mutation AppSubscriptionCreate($name: String!, $returnUrl: URL!, $trialDays: Int!, $price: Decimal!, $test: Boolean!) {
    appSubscriptionCreate(
      name: $name
      returnUrl: $returnUrl
      trialDays: $trialDays
      test: $test
      lineItems: [{
        plan: {
          appRecurringPricingDetails: {
            price: { amount: $price, currencyCode: USD }
          }
        }
      }]
    ) {
      confirmationUrl
      appSubscription {
        id
        status
      }
      userErrors {
        field
        message
      }
    }
  }
`;

// Create a Shopify billing subscription (GraphQL) and return confirmation URL
async function createCharge(shop, token) {
  const response = await axios.post(
    `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
    {
      query: CREATE_SUBSCRIPTION_MUTATION,
      variables: {
        name: BILLING_PLAN.name,
        returnUrl: BILLING_PLAN.return_url,
        trialDays: BILLING_PLAN.trial_days,
        price: BILLING_PLAN.price,
        test: process.env.BILLING_TEST_MODE === 'true',
      },
    },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );

  const data = response.data.data?.appSubscriptionCreate;
  if (data?.userErrors?.length > 0) {
    const err = data.userErrors.map(e => e.message).join('; ');
    throw new Error(err);
  }
  if (!data?.confirmationUrl) {
    throw new Error('No confirmation URL returned from Shopify');
  }

  return {
    id: data.appSubscription.id,
    confirmation_url: data.confirmationUrl,
    status: data.appSubscription.status,
  };
}

// Activate is not needed for GraphQL — subscription auto-activates on approval

// Get billing status for the dashboard
app.get('/api/billing/status', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;

  const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1', [shop]);
  if (!merchant) return res.json({ status: 'not_installed' });

  if (process.env.SKIP_BILLING === 'true') {
    return res.json({ status: 'active', plan: BILLING_PLAN.name, skip_billing: true });
  }

  // Calculate trial days remaining
  let trialDaysLeft = 0;
  if (merchant.trial_ends_at) {
    trialDaysLeft = Math.max(0, Math.ceil((new Date(merchant.trial_ends_at) - new Date()) / 86400000));
  }

  res.json({
    status: merchant.billing_status,
    charge_id: merchant.shopify_charge_id,
    trial_days_left: trialDaysLeft,
    plan: BILLING_PLAN.name,
    price: BILLING_PLAN.price,
  });
});

// Initiate billing (create charge, redirect to Shopify)
app.post('/api/billing/create', async (req, res) => {
  const shop = requireShop(req, res);
  if (!shop) return;

  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Not installed' });

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
    const charge = await createCharge(shop, token);
    // Store charge ID
    await db.run('UPDATE merchants SET shopify_charge_id = $1 WHERE shop = $2', [String(charge.id), shop]);
    res.json({ confirmation_url: charge.confirmation_url });
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

// Billing test confirm (simulated approval for BILLING_TEST_MODE — dev only)
app.get('/billing/test-confirm', async (req, res) => {
  // Defense in depth: never reachable in production even if BILLING_TEST_MODE leaks
  if (process.env.NODE_ENV === 'production' || process.env.BILLING_TEST_MODE !== 'true') {
    return res.status(404).send('Not found');
  }
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop');
  // Already activated by /api/billing/create, just redirect to dashboard
  res.redirect(`/?shop=${shop}`);
});

// Callback from Shopify after merchant approves (or declines) billing
app.get('/billing/confirm', async (req, res) => {
  const { charge_id, shop, subscription_id } = req.query;
  if (!shop) return res.status(400).send('Missing shop parameter — this URL should only be accessed via Shopify billing redirect');

  // Merchant declined billing — mark it explicitly and redirect back into the
  // admin with the declined flag (dashboard shows the message on the overlay)
  if (!charge_id && !subscription_id) {
    await db.run(`UPDATE merchants SET billing_status = 'declined' WHERE shop = $1`, [shop]);
    const storeSlug = shop.replace(/\.myshopify\.com$/i, '');
    return res.redirect(`https://admin.shopify.com/store/${storeSlug}/apps/stockyshift?billing=declined`);
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
    const storeSlug = shop.replace(/\.myshopify\.com$/i, '');
    res.redirect(`https://admin.shopify.com/store/${storeSlug}/apps/stockyshift`);
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

    // Clear charge_id from DB if we canceled successfully
    if (canceled.length > 0) {
      await db.run('UPDATE merchants SET shopify_charge_id = NULL, billing_status = NULL WHERE shop = $1', [shop]);
    }

    res.json({ canceled, message: `Canceled ${canceled.length} pending subscriptions`, db_charge_id: dbChargeId, found_subs: foundSubs });
  } catch (err) {
    console.error('[Billing] Cancel error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to cancel subscriptions' });
  }
});

// ─── Debug: check which API key is active (dev only) ─────────────────────
if (process.env.NODE_ENV !== 'production') {
app.get('/api/debug', (req, res) => {
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

// ─── Cron Job: Daily Low Stock Check ─────────────────────────────────────

// Run at 8:00 AM every day
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
  await db.run('UPDATE merchants SET is_active = 0, uninstalled_at = CURRENT_TIMESTAMP WHERE shop = $1', [shop]);

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
      await db.run(
        `UPDATE merchants
         SET billing_status = $1,
             shopify_charge_id = COALESCE($2, shopify_charge_id)
         WHERE shop = $3 AND shopify_charge_id = $4`,
        [newStatus, subId, shop, subId]
      );
      console.log(`[Webhook] ${shop} subscription ${subId} → '${newStatus}'`);
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
  await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
  console.log(`[GDPR] shop/redact — all data deleted for ${shop}`);
  res.status(200).send('OK');
});

// ─── Start ───────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`StockyShift running on port ${PORT}`);
  console.log(`OAuth callback URL: ${APP_URL}/auth/callback`);
  if (!APP_URL) console.error('FATAL: APP_URL not set — billing, OAuth, and webhooks will fail');
});
