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
const SessionStore = new SqliteStore({
  client: require('better-sqlite3')(path.join(__dirname, 'stockyshift_sessions.db')),
  expired: { clear: true, intervalMs: 900000 },
});

const app = express();
const PORT = process.env.PORT || 3000;

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
  } else {
    res.setHeader('X-Frame-Options', 'DENY');
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
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 86400000, // 24 hours
    sameSite: 'none',
    secure: true,
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
  // Must be issued for our API key
  if (payload.aud !== SHOPIFY_API_KEY) return null;

  // Verify HMAC signature
  const expectedSig = crypto
    .createHmac('sha256', SHOPIFY_API_SECRET)
    .update(parts[0] + '.' + parts[1])
    .digest('base64url')
    .replace(/=+$/, ''); // base64url has no padding

  if (parts[2] !== expectedSig) return null;

  // Extract shop from dest field: "https://{shop}.myshopify.com"
  const dest = payload.dest || '';
  const match = dest.match(/https:\/\/([^/]+)/);
  if (!match) return null;

  return { shop: match[1], payload };
}

// Middleware: authenticate via session token (Bearer) or fall back to session/params
app.use((req, res, next) => {
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    const result = verifySessionToken(authHeader.slice(7));
    if (result) {
      req.shop = result.shop;
    }
  }
  next();
});

// Serve static dashboard
app.use(express.static('views'));

// ─── Static Pages ─────────────────────────────────────────────────────────

app.get('/privacy', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'privacy.html'));
});

app.get('/terms', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'terms.html'));
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

  // Escape shop for safe HTML rendering
  const escShop = String(shop)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

    // Validate shop exists before redirecting to Shopify
  try {
    // Use GraphQL endpoint — real stores return 200 (auth error), fake stores return 404
    const shopCheck = await axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`,
      { query: '{ shop { name } }' },
      {
        timeout: 5000,
        validateStatus: () => true,
        headers: { 'Content-Type': 'application/json' },
      }
    );
    if (shopCheck.status === 404) {
      return res.send(`
      <!DOCTYPE html><html><head><meta charset="UTF-8">
      <title>Store not found</title>
      <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
        .card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 12px rgba(0,0,0,0.08);max-width:420px;width:100%;text-align:center}
        h1{font-size:24px;color:#1a1a2e;margin:0 0 12px 0}
        p{color:#666;margin:0 0 8px 0;font-size:15px;line-height:1.5}
        .btn{display:inline-block;padding:12px 24px;background:#1a1a2e;color:white;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;margin-top:16px}
        .btn:hover{background:#2a2a4e}
      </style>
      </head><body>
      <div class="card">
        <h1>Store not found</h1>
        <p>We couldn't find a Shopify store at <strong>${escShop}</strong>.</p>
        <p>Check the spelling and try again.</p>
        <a class="btn" href="/">Try again</a>
      </div>
      </body></html>
    `);
    }
  } catch {
    // Network error — store domain likely doesn't exist
    return res.send(`
      <!DOCTYPE html><html><head><meta charset="UTF-8">
      <title>Store not found</title>
      <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
        .card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 12px rgba(0,0,0,0.08);max-width:420px;width:100%;text-align:center}
        h1{font-size:24px;color:#1a1a2e;margin:0 0 12px 0}
        p{color:#666;margin:0 0 8px 0;font-size:15px;line-height:1.5}
        .btn{display:inline-block;padding:12px 24px;background:#1a1a2e;color:white;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;text-decoration:none;margin-top:16px}
        .btn:hover{background:#2a2a4e}
      </style>
      </head><body>
      <div class="card">
        <h1>Store not found</h1>
        <p>We couldn't find a Shopify store at <strong>${escShop}</strong>.</p>
        <p>Check the spelling and try again.</p>
        <a class="btn" href="/">Try again</a>
      </div>
      </body></html>
    `);
  }

  // Stateless state: HMAC-based, no session storage needed
  const state = crypto.createHmac('sha256', SHOPIFY_API_SECRET)
    .update(shop)
    .digest('hex');

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

  // Stateless state verification (HMAC-based, no session dependency)
  const expectedState = crypto.createHmac('sha256', SHOPIFY_API_SECRET)
    .update(shop)
    .digest('hex');
  if (state !== expectedState) {
    return res.status(403).send('State mismatch. Possible CSRF attack.');
  }

  // Verify shop domain (must end in .myshopify.com)
  if (!shop?.endsWith('.myshopify.com')) {
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
          WHEN billing_status NOT IN ('active') THEN 'pending'
          ELSE billing_status
        END,
        trial_ends_at = CASE
          WHEN billing_status NOT IN ('active') THEN NULL
          ELSE trial_ends_at
        END
    `, [shop, accessToken, refreshToken, expiresAt]);

    // Register uninstall webhook (async, non-blocking)
    axios.post(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      query: `mutation {
        webhookSubscriptionCreate(topic: APP_UNINSTALLED, webhookSubscription: {
          callbackUrl: "${APP_URL}/webhooks/app/uninstalled"
          format: JSON
        }) { userErrors { field message } }
      }`
    }, {
      headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' }
    }).catch(err => {
      console.warn(`[Webhook] Could not register APP_UNINSTALLED for ${shop}: ${err.message}`);
    });

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
  res.json({ api_key: SHOPIFY_API_KEY });
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

    // Force re-auth if ?reauth=1 (deletes shop from DB, triggers fresh OAuth)
    if (reauth === '1') {
      await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
      return res.redirect(`/auth?shop=${shop}`);
    }

    // Check if merchant exists
    const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1 AND is_active = 1', [shop]);
    if (!merchant) {
      return res.redirect(`/auth?shop=${shop}`);
    }

    // Force re-auth if merchant has a non-expiring token (no refresh_token) — API 2026-07 rejects them
    if (!merchant.refresh_token) {
      console.log(`[Auth] ${shop} has non-expiring token, forcing re-auth for API 2026-07 compatibility`);
      await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
      return res.redirect(`/auth?shop=${shop}`);
    }

    // If SKIP_BILLING is true, force billing status to active
    if (process.env.SKIP_BILLING === 'true') {
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

    // If SKIP_BILLING is true, force billing status to active
    if (process.env.SKIP_BILLING === 'true' && merchant) {
      await db.run(`UPDATE merchants SET billing_status = 'active' WHERE shop = $1`, [shop]);
    }

    if (!merchant) {
      // Not authenticated — serve landing page, JS will redirect to auth
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Force re-auth if old token (no refresh_token)
    if (!merchant.refresh_token) {
      console.log(`[Auth] ${shop} (via proxy) has non-expiring token, forcing re-auth`);
      await db.run('DELETE FROM merchants WHERE shop = $1', [shop]);
      return res.sendFile(path.join(__dirname, 'views', 'landing.html'));
    }

    // Authenticated — serve the dashboard directly through the iframe
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
  } catch (e) {
    next(e);
  }
});

// ─── API Routes ──────────────────────────────────────────────────────────

// Helper: resolve shop from session token (embedded) → session cookie (standalone) → request param
function getShop(req) {
  // req.shop is set by the Bearer token middleware (embedded mode with App Bridge)
  if (req.shop) return req.shop;
  // Fall back to session (standalone mode with cookie)
  if (req.session?.shop) return req.session.shop;
  // Fall back to request body/query
  return req.body?.shop || req.query?.shop || null;
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

async function getToken(shop) {
  const merchant = await db.get('SELECT * FROM merchants WHERE shop = $1 AND is_active = 1', [shop]);
  if (!merchant?.access_token) return null;

  // If the token has an expiry and is within 5 min of expiring (or already expired), refresh it
  if (merchant.expires_at && merchant.refresh_token) {
    const expiresAt = new Date(merchant.expires_at).getTime();
    const fiveMinutesFromNow = Date.now() + 5 * 60 * 1000;
    if (expiresAt < fiveMinutesFromNow) {
      try {
        console.log(`[Token] Refreshing token for ${shop} (expired or expiring soon)`);
        return await refreshShopifyToken(shop, merchant.refresh_token);
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
                  inventoryLevels(first: 10) {
                    edges {
                      node { available }
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
  const shop = getShop(req);
  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Shop not installed' });

  try {
    // Fetch all products + variants + inventory via GraphQL
    const allVariants = [];
    let hasNextPage = true;
    let after = null;

    while (hasNextPage) {
      const gqlRes = await axios.post(
        `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
        { query: SYNC_PRODUCTS_QUERY, variables: { first: 250, after } },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
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
              available += level.node.available;
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

    // Upsert into local DB
    let variantCount = 0;
    await db.transaction(async (tx) => {
      for (const v of allVariants) {
        await tx.run(`
          INSERT INTO products (shopify_product_id, shopify_variant_id, inventory_item_id, shop, title, sku, current_stock)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT(shop, shopify_variant_id) DO UPDATE SET
            title = excluded.title,
            sku = excluded.sku,
            current_stock = excluded.current_stock,
            inventory_item_id = excluded.inventory_item_id
        `, [v.product_id, v.variant_id, v.inventory_item_id, shop, v.title, v.sku, v.current_stock]);
        variantCount++;
      }
    });

    res.json({ synced: variantCount });
  } catch (err) {
    const detail = err.response?.data || err.message;
    const raw = typeof detail === 'object' ? JSON.stringify(detail) : String(detail);
    console.error('Sync error:', raw);
    res.status(500).json({ error: 'Sync failed', detail: raw.substring(0, 500) });
  }
});

// Get low stock products (below reorder point)
app.get('/api/low-stock', async (req, res) => {
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
  const shop = getShop(req);
  const { id, reorder_point, preferred_vendor_id } = req.body;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  await db.run(`
    UPDATE products SET reorder_point = $1, preferred_vendor_id = $2 WHERE id = $3 AND shop = $4
  `, [reorder_point || 0, preferred_vendor_id || null, id, shop]);

  res.json({ success: true });
});

// ─── Vendor Routes ───────────────────────────────────────────────────────

app.get('/api/vendors', async (req, res) => {
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const vendors = await db.all('SELECT * FROM vendors WHERE shop = $1 ORDER BY name', [shop]);
  res.json(vendors);
});

app.post('/api/vendors', async (req, res) => {
  const shop = getShop(req);
  const { name, email, min_order_amount, notes } = req.body;
  if (!shop || !name || !email) return res.status(400).json({ error: 'Missing required fields' });
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
  const shop = getShop(req);
  const { name, email, min_order_amount, notes } = req.body;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
  const shop = getShop(req);
  const { vendor_id, items, notes } = req.body;
  if (!shop || !vendor_id || !items?.length) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });
  // Verify vendor belongs to this shop
  const vendorCheck = await db.get('SELECT id FROM vendors WHERE id = $1 AND shop = $2', [vendor_id, shop]);
  if (!vendorCheck) return res.status(400).json({ error: 'Vendor not found' });

  // Generate PO number
  const poNumber = `PO-${Date.now().toString(36).toUpperCase()}`;
  let total = 0;

  // Calculate total
  for (const item of items) {
    total += item.ordered_qty * (item.unit_cost || 0);
  }

  const poId = await db.transaction(async (tx) => {
    const poResult = await tx.get(`
      INSERT INTO purchase_orders (shop, vendor_id, po_number, total, notes)
      VALUES ($1, $2, $3, $4, $5) RETURNING id
    `, [shop, vendor_id, poNumber, total, notes || '']);

    const newPoId = poResult.id;

    for (const item of items) {
      await tx.run(`
        INSERT INTO po_line_items (po_id, product_id, ordered_qty, unit_cost)
        VALUES ($1, $2, $3, $4)
      `, [newPoId, item.product_id, item.ordered_qty, item.unit_cost || 0]);
    }

    return newPoId;
  });
  res.json({ po_id: poId, po_number: poNumber, total });
});

// Send PO email
app.post('/api/purchase-orders/:id/send', async (req, res) => {
  const { id } = req.params;
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const po = await db.get(`
    SELECT po.*, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.id = $1 AND po.shop = $2
  `, [id, shop]);

  if (!po) return res.status(404).json({ error: 'PO not found' });

  const lineItems = await db.all(`
    SELECT pli.*, p.title, p.sku
    FROM po_line_items pli
    JOIN products p ON pli.product_id = p.id
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
  const shop = getShop(req);
  const { items } = req.body; // [{line_item_id, received_qty}]
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  // Verify PO belongs to this shop
  const po = await db.get('SELECT id FROM purchase_orders WHERE id = $1 AND shop = $2', [id, shop]);
  if (!po) return res.status(404).json({ error: 'PO not found' });

  // Validate quantities: can't receive more than ordered
  for (const item of items) {
    const lineItemCheck = await db.get('SELECT ordered_qty, received_qty FROM po_line_items WHERE id = $1 AND po_id = $2', [item.line_item_id, id]);
    if (!lineItemCheck) return res.status(400).json({ error: `Line item ${item.line_item_id} not found on this PO` });
    const maxReceive = lineItemCheck.ordered_qty - (lineItemCheck.received_qty || 0);
    if (item.received_qty > lineItemCheck.ordered_qty) {
      return res.status(400).json({ error: `Cannot receive more than ${lineItemCheck.ordered_qty} for this item (ordered: ${lineItemCheck.ordered_qty}, already received: ${lineItemCheck.received_qty || 0})` });
    }
  }

  // Collect inventory adjustments needed (computed during transaction below)
  const adjustments = [];

  await db.transaction(async (tx) => {
    for (const item of items) {
      // Get previous received_qty to calculate delta (supports partial receives)
      const before = tx.get('SELECT received_qty FROM po_line_items WHERE id = $1 AND po_id = $2', [item.line_item_id, id]);
      const delta = item.received_qty - (before?.received_qty || 0);

      await tx.run(`
        UPDATE po_line_items SET received_qty = $1 WHERE id = $2 AND po_id = $3
      `, [item.received_qty, item.line_item_id, id]);

      // If adding inventory, record adjustment for Shopify push
      if (delta > 0) {
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
            delta,
          });
        }
      }
    }

    // Check if all items are fully received
    const allItems = tx.all(`
      SELECT ordered_qty, received_qty FROM po_line_items WHERE po_id = $1
    `, [id]);

    const allReceived = allItems.every(i => i.received_qty >= i.ordered_qty);
    const status = allReceived ? 'received' : 'partial';

    tx.run(`
      UPDATE purchase_orders SET status = $1, received_at = CURRENT_TIMESTAMP WHERE id = $2
    `, [status, id]);
  });

  // After transaction: push inventory adjustments to Shopify AND always update local stock
  if (adjustments.length > 0) {
    let shopifySuccess = false;
    try {
      const token = await getToken(shop);
      // Get first location via GraphQL (most merchants have only one)
      const locRes = await axios.post(
        `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
        { query: `{ locations(first: 1) { edges { node { id } } } }` },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' }, timeout: 10000 }
      );
      const locationId = locRes.data?.data?.locations?.edges?.[0]?.node?.id;

      if (locationId) {
        for (const adj of adjustments) {
          const mutation = `
            mutation($input: InventoryAdjustQuantitiesInput!) {
              inventoryAdjustQuantities(input: $input) {
                userErrors { field message }
              }
            }
          `;
          await axios.post(
            `https://${shop}/admin/api/${API_VERSION}/graphql.json`,
            {
              query: mutation,
              variables: {
                input: {
                  reason: "unknown",
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
        }
        shopifySuccess = true;
        console.log(`[Receive] Shopify inventory updated for ${shop}: ${adjustments.length} items adjusted at location ${locRes.data?.data?.locations?.edges?.[0]?.node?.id}`);
      } else {
        console.warn(`[Receive] No locations found for ${shop} — Shopify inventory not updated`);
      }
    } catch (err) {
      console.error(`[Receive] Shopify inventory update failed for ${shop}:`, err.response?.data || err.message);
    }

    // Always update local stock, regardless of Shopify push success
    for (const adj of adjustments) {
      await db.run('UPDATE products SET current_stock = current_stock + $1 WHERE id = $2 AND shop = $3',
        [adj.delta, adj.product_id, shop]);
    }
    console.log(`[Receive] Local stock updated for ${shop}: ${adjustments.length} items adjusted`);
  }

  res.json({ success: true, adjustments: adjustments.length });
});

app.get('/api/purchase-orders', async (req, res) => {
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!await getToken(shop)) return res.status(401).json({ error: 'Shop not installed' });

  const po = await db.get(`
    SELECT po.*, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.id = $1 AND po.shop = $2
  `, [id, shop]);

  if (!po) return res.status(404).json({ error: 'PO not found' });

  const lineItems = await db.all(`
    SELECT pli.*, p.title, p.sku, p.current_stock
    FROM po_line_items pli
    JOIN products p ON pli.product_id = p.id
    WHERE pli.po_id = $1
  `, [id]);

  res.json({ ...po, line_items: lineItems });
});

// Delete a purchase order (only draft POs can be deleted)
app.delete('/api/purchase-orders/:id', async (req, res) => {
  const { id } = req.params;
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
  if (process.env.SKIP_BILLING === 'true') return true;
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
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

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
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const token = await getToken(shop);
  if (!token) return res.status(401).json({ error: 'Not installed' });

  // BILLING_TEST_MODE: skip Shopify's billing API, activate locally
  if (process.env.BILLING_TEST_MODE === 'true') {
    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);
    await db.run(`
      UPDATE merchants SET billing_status = 'trial', trial_ends_at = $1, shopify_charge_id = NULL
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

// Billing test confirm (simulated approval for BILLING_TEST_MODE)
app.get('/billing/test-confirm', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop');
  // Already activated by /api/billing/create, just redirect to dashboard
  res.redirect(`/?shop=${shop}`);
});

// Callback from Shopify after merchant approves (or declines) billing
app.get('/billing/confirm', async (req, res) => {
  const { charge_id, shop, subscription_id } = req.query;
  if (!shop) return res.status(400).send('Missing shop');

  // Merchant declined billing — redirect back to dashboard with declined flag
  if (!charge_id && !subscription_id) {
    return res.redirect(`/?shop=${shop}&billing=declined`);
  }

  const token = await getToken(shop);
  if (!token) return res.status(401).send('Not installed');

  try {
    // With GraphQL, the subscription is already active when they return
    const subId = subscription_id || charge_id;

    // Calculate trial end date (7 days from now)
    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);

    const billingStatus = BILLING_PLAN.trial_days > 0 ? 'trial' : 'active';

    await db.run(`
      UPDATE merchants
      SET shopify_charge_id = $1, billing_status = $2, trial_ends_at = $3
      WHERE shop = $4
    `, [String(subId), billingStatus, trialEnd.toISOString(), shop]);

    console.log(`[Billing] ${shop} subscribed — ${billingStatus} until ${trialEnd.toISOString()}`);

    // Redirect to dashboard
    res.redirect(`/?shop=${shop}`);
  } catch (err) {
    console.error('[Billing] Confirm error:', err.message);
    res.status(500).send('Failed to activate billing. Please try again.');
  }
});

// ─── Cancel pending subscriptions (for stuck billing) ─────────────────────
app.post('/api/billing/cancel-pending', async (req, res) => {
  const shop = getShop(req);
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
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
            query: `mutation { appSubscriptionCancel(id: "${dbChargeId}") { userErrors { field message } } }`,
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
                query: `mutation { appSubscriptionCancel(id: "${id}") { userErrors { field message } } }`,
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

// Database health check (with 5s timeout)
app.get('/api/db-health', async (req, res) => {
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
    const merchants = await db.all('SELECT shop FROM merchants WHERE is_active = 1');

    for (const merchant of merchants) {
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

          const emailText = `StockyShift — Low Stock Alert for ${merchant.shop}\n\n` +
            `The following products are below their reorder point:\n\n${lowStockList}\n\n` +
            `Log in to StockyShift to create purchase orders:\n${process.env.APP_URL || 'https://stockyshift.com'}\n`;

          const merchantInfo = await db.get('SELECT email FROM merchants WHERE shop = $1', [merchant.shop]);
          if (merchantInfo?.email) {
            await sendPOEmail({
              to: merchantInfo.email,
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

  // Delete merchant data for privacy compliance (GDPR / App Store review)
  await db.run('DELETE FROM po_line_items WHERE po_id IN (SELECT id FROM purchase_orders WHERE shop = $1)', [shop]);
  await db.run('DELETE FROM purchase_orders WHERE shop = $1', [shop]);
  await db.run('DELETE FROM products WHERE shop = $1', [shop]);
  await db.run('DELETE FROM vendors WHERE shop = $1', [shop]);
  await db.run('UPDATE merchants SET is_active = 0, uninstalled_at = CURRENT_TIMESTAMP WHERE shop = $1', [shop]);

  console.log(`[Webhook] ${shop} uninstalled StockyShift — data cleaned up`);
  res.status(200).send('OK');
});

// ─── Start ───────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`StockyShift running on port ${PORT}`);
  console.log(`OAuth callback URL: ${APP_URL}/auth/callback`);
  if (!APP_URL) console.error('FATAL: APP_URL not set — billing, OAuth, and webhooks will fail');
});
