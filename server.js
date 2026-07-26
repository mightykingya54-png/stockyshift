require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const axios = require('axios');
const cron = require('node-cron');
const db = require('./db');
const { generatePO } = require('./lib/pdf');
const { sendPOEmail } = require('./lib/email');
const SqliteStore = require('better-sqlite3-session-store')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────

// Capture raw body for webhook HMAC verification
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SqliteStore({
    client: db,
    expired: {
      clear: true,
      intervalMs: 900000, // clean expired sessions every 15 min
    },
  }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 86400000 }, // 24 hours
}));

// ─── Shopify HMAC Verification ────────────────────────────────────────────

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

// Serve static dashboard
app.use(express.static('views'));

// ─── Shopify OAuth ────────────────────────────────────────────────────────

const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const SCOPES = process.env.SCOPES || 'read_products,write_products,read_inventory,write_inventory,write_recurring_charges';
const APP_URL = process.env.SHOPIFY_APP_URL || process.env.APP_URL;

// Step 1: Redirect merchant to Shopify authorization
app.get('/auth', async (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop parameter');

    // Validate shop exists before redirecting to Shopify
  try {
    // Real store returns 401 (no auth, but exists). Fake store returns 404.
    const shopCheck = await axios.get(`https://${shop}/admin/api/2024-04/shop.json`, {
      timeout: 5000,
      maxRedirects: 0,
      validateStatus: () => true,
    });
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
        <p>We couldn't find a Shopify store at <strong>${shop}</strong>.</p>
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
        <p>We couldn't find a Shopify store at <strong>${shop}</strong>.</p>
        <p>Check the spelling and try again.</p>
        <a class="btn" href="/">Try again</a>
      </div>
      </body></html>
    `);
  }

  const state = crypto.randomBytes(16).toString('hex');
  req.session.state = state;
  req.session.shop = shop;

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

  // Verify state
  if (state !== req.session.state) {
    return res.status(403).send('State mismatch. Possible CSRF attack.');
  }

  // Verify shop domain (must end in .myshopify.com)
  if (!shop?.endsWith('.myshopify.com')) {
    return res.status(400).send('Invalid shop domain');
  }

  try {
    // Exchange code for permanent access token
    const tokenResponse = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }
    );

    const accessToken = tokenResponse.data.access_token;

    // Store merchant in database
    const stmt = db.prepare(`
      INSERT INTO merchants (shop, access_token)
      VALUES (?, ?)
      ON CONFLICT(shop) DO UPDATE SET access_token = ?, is_active = 1, uninstalled_at = NULL
    `);
    stmt.run(shop, accessToken, accessToken);

    // Fetch merchant email from Shopify API (async, non-blocking)
    axios.get(`https://${shop}/admin/shop.json`, {
      headers: { 'X-Shopify-Access-Token': accessToken },
      timeout: 5000,
    }).then(shopRes => {
      const email = shopRes.data?.shop?.email;
      if (email) {
        db.prepare('UPDATE merchants SET email = ? WHERE shop = ?').run(email, shop);
      }
    }).catch(err => {
      console.warn(`[OAuth] Could not fetch email for ${shop}: ${err.message}`);
    });

    // Redirect merchant to the embedded app or dashboard
    res.redirect(`/?shop=${shop}`);
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.status(500).send('Installation failed. Please try again.');
  }
});

// ─── Embedded App Entry ──────────────────────────────────────────────────

// Serve the dashboard for any root request with a shop parameter
app.get('/', (req, res) => {
  const { shop } = req.query;
  if (!shop) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>StockyShift</title>
      <style>
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}
        .card{background:white;border-radius:12px;padding:40px;box-shadow:0 2px 12px rgba(0,0,0,0.08);max-width:420px;width:100%;text-align:center}
        h1{font-size:28px;color:#1a1a2e;margin:0 0 8px 0}
        p{color:#666;margin:0 0 24px 0;font-size:15px;line-height:1.5}
        input{width:100%;padding:12px 16px;border:1px solid #ddd;border-radius:8px;font-size:15px;margin-bottom:12px;box-sizing:border-box}
        input:focus{outline:none;border-color:#4a6cf7}
        button{width:100%;padding:12px;background:#1a1a2e;color:white;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
        button:hover{background:#2a2a4e}
        .hint{color:#999;font-size:13px;margin-top:8px}
      </style>
      </head>
      <body>
      <div class="card">
        <h1>StockyShift</h1>
        <p>Purchase orders &amp; low stock alerts for Shopify. The simple Stocky alternative.</p>
        <input type="text" id="shopInput" placeholder="your-store.myshopify.com" onkeydown="if(event.key==='Enter')install()">
        <button onclick="install()">Install on your store</button>
        <p class="hint">Enter your Shopify store name above</p>
      </div>
      <script>
        function install(){const s=document.getElementById('shopInput').value.trim();if(!s)return alert('Enter your store name');window.location.href='/auth?shop='+encodeURIComponent(s.endsWith('.myshopify.com')?s:s+'.myshopify.com')}
      </script>
      </body>
      </html>
    `);
  }

  // Check if merchant exists and has active session
  const merchant = db.prepare('SELECT * FROM merchants WHERE shop = ? AND is_active = 1').get(shop);
  if (!merchant) {
    return res.redirect(`/auth?shop=${shop}`);
  }

  // Serve the dashboard HTML (passed as query param so JS can use it)
  res.redirect(`/dashboard.html?shop=${shop}`);
});

// ─── API Routes ──────────────────────────────────────────────────────────

// Helper: load merchant's access token
function getToken(shop) {
  const merchant = db.prepare('SELECT access_token FROM merchants WHERE shop = ? AND is_active = 1').get(shop);
  return merchant?.access_token;
}

// Sync products from Shopify
app.post('/api/sync-products', async (req, res) => {
  const { shop } = req.body;
  const token = getToken(shop);
  if (!token) return res.status(401).json({ error: 'Shop not installed' });

  try {
    // Fetch all products from Shopify
    let products = [];
    let url = `https://${shop}/admin/api/2024-04/products.json?limit=250&fields=id,title,variants`;

    while (url) {
      const response = await axios.get(url, {
        headers: { 'X-Shopify-Access-Token': token },
      });
      products = products.concat(response.data.products);
      url = null;
      // Check for pagination (Link header)
      const linkHeader = response.headers.link;
      if (linkHeader) {
        const matches = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
        if (matches) url = matches[1];
      }
    }

    // Get inventory levels for all products
    const variantIds = products.flatMap(p => p.variants.map(v => v.inventory_item_id)).filter(Boolean);
    let inventoryLevels = {};
    if (variantIds.length > 0) {
      // Fetch in chunks of 50 (Shopify limit for inventory_levels)
      for (let i = 0; i < variantIds.length; i += 50) {
        const chunk = variantIds.slice(i, i + 50).join(',');
        const invResponse = await axios.get(
          `https://${shop}/admin/api/2024-04/inventory_levels.json?inventory_item_ids=${chunk}`,
          { headers: { 'X-Shopify-Access-Token': token } }
        );
        invResponse.data.inventory_levels.forEach(level => {
          inventoryLevels[level.inventory_item_id] = level.available;
        });
      }
    }

    // Upsert products into local DB
    const upsert = db.prepare(`
      INSERT INTO products (shopify_product_id, shopify_variant_id, shop, title, sku, current_stock)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(shop, shopify_variant_id) DO UPDATE SET
        title = excluded.title,
        sku = excluded.sku,
        current_stock = excluded.current_stock
    `);

    let variantCount = 0;
    const insertMany = db.transaction((prods) => {
      for (const product of prods) {
        for (const variant of product.variants) {
          upsert.run(
            product.id,
            variant.id,
            shop,
            product.title,
            variant.sku || '',
            inventoryLevels[variant.inventory_item_id] || 0
          );
          variantCount++;
        }
      }
    });

    insertMany(products);

    res.json({ synced: variantCount });
  } catch (err) {
    console.error('Sync error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Sync failed' });
  }
});

// Get low stock products (below reorder point)
app.get('/api/low-stock', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  // Join products with vendors to show vendor info alongside low stock items
  const lowStock = db.prepare(`
    SELECT p.*, v.name as vendor_name, v.email as vendor_email
    FROM products p
    LEFT JOIN vendors v ON p.preferred_vendor_id = v.id
    WHERE p.shop = ?
      AND p.is_active = 1
      AND p.reorder_point > 0
      AND p.current_stock <= p.reorder_point
    ORDER BY (p.reorder_point - p.current_stock) DESC
  `).all(shop);

  res.json(lowStock);
});

// Get all products
app.get('/api/products', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const products = db.prepare(`
    SELECT * FROM products WHERE shop = ? AND is_active = 1 ORDER BY title
  `).all(shop);

  res.json(products);
});

// Update reorder point for a product
app.post('/api/products/reorder-point', (req, res) => {
  const { id, reorder_point, preferred_vendor_id, shop } = req.body;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  const stmt = db.prepare(`
    UPDATE products SET reorder_point = ?, preferred_vendor_id = ? WHERE id = ? AND shop = ?
  `);
  stmt.run(reorder_point || 0, preferred_vendor_id || null, id, shop);

  res.json({ success: true });
});

// ─── Vendor Routes ───────────────────────────────────────────────────────

app.get('/api/vendors', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const vendors = db.prepare('SELECT * FROM vendors WHERE shop = ? ORDER BY name').all(shop);
  res.json(vendors);
});

app.post('/api/vendors', (req, res) => {
  const { shop, name, email, min_order_amount, notes } = req.body;
  if (!shop || !name || !email) return res.status(400).json({ error: 'Missing required fields' });

  const stmt = db.prepare('INSERT INTO vendors (shop, name, email, min_order_amount, notes) VALUES (?, ?, ?, ?, ?)');
  const result = stmt.run(shop, name, email, min_order_amount || 0, notes || '');
  res.json({ id: result.lastInsertRowid });
});

// ─── PO Routes ───────────────────────────────────────────────────────────



app.post('/api/purchase-orders', async (req, res) => {
  const { shop, vendor_id, items, notes } = req.body;
  if (!shop || !vendor_id || !items?.length) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Generate PO number
  const poNumber = `PO-${Date.now().toString(36).toUpperCase()}`;
  let total = 0;

  // Calculate total
  for (const item of items) {
    total += item.ordered_qty * (item.unit_cost || 0);
  }

  const insertPO = db.transaction(() => {
    const poResult = db.prepare(`
      INSERT INTO purchase_orders (shop, vendor_id, po_number, total, notes)
      VALUES (?, ?, ?, ?, ?)
    `).run(shop, vendor_id, poNumber, total, notes || '');

    const poId = poResult.lastInsertRowid;

    const insertItem = db.prepare(`
      INSERT INTO po_line_items (po_id, product_id, ordered_qty, unit_cost)
      VALUES (?, ?, ?, ?)
    `);

    for (const item of items) {
      insertItem.run(poId, item.product_id, item.ordered_qty, item.unit_cost || 0);
    }

    return poId;
  });

  const poId = insertPO();
  res.json({ po_id: poId, po_number: poNumber, total });
});

// Send PO email
app.post('/api/purchase-orders/:id/send', async (req, res) => {
  const { id } = req.params;
  const { shop } = req.body;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const po = db.prepare(`
    SELECT po.*, v.name as vendor_name, v.email as vendor_email
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.id = ? AND po.shop = ?
  `).get(id, shop);

  if (!po) return res.status(404).json({ error: 'PO not found' });

  const lineItems = db.prepare(`
    SELECT pli.*, p.title, p.sku
    FROM po_line_items pli
    JOIN products p ON pli.product_id = p.id
    WHERE pli.po_id = ?
  `).all(id);

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
    db.prepare(`
      UPDATE purchase_orders SET status = 'sent', emailed_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(id);

    res.json({ success: true });
  } catch (err) {
    console.error('Email error:', err.message);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// Receive against PO
app.post('/api/purchase-orders/:id/receive', (req, res) => {
  const { id } = req.params;
  const { shop, items } = req.body; // [{line_item_id, received_qty}]
  if (!shop) return res.status(400).json({ error: 'Missing shop' });
  if (!getToken(shop)) return res.status(401).json({ error: 'Not installed' });

  // Verify PO belongs to this shop
  const po = db.prepare('SELECT id FROM purchase_orders WHERE id = ? AND shop = ?').get(id, shop);
  if (!po) return res.status(404).json({ error: 'PO not found' });

  const receiveTx = db.transaction(() => {
    for (const item of items) {
      db.prepare(`
        UPDATE po_line_items SET received_qty = ? WHERE id = ? AND po_id = ?
      `).run(item.received_qty, item.line_item_id, id);
    }

    // Check if all items are fully received
    const allItems = db.prepare(`
      SELECT ordered_qty, received_qty FROM po_line_items WHERE po_id = ?
    `).all(id);

    const allReceived = allItems.every(i => i.received_qty >= i.ordered_qty);
    const status = allReceived ? 'received' : 'partial';

    db.prepare(`
      UPDATE purchase_orders SET status = ?, received_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(status, id);
  });

  receiveTx();
  res.json({ success: true });
});

app.get('/api/purchase-orders', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const pos = db.prepare(`
    SELECT po.*, v.name as vendor_name
    FROM purchase_orders po
    JOIN vendors v ON po.vendor_id = v.id
    WHERE po.shop = ?
    ORDER BY po.created_at DESC
  `).all(shop);

  res.json(pos);
});

// ─── Test Email (remove before production) ────────────────────────────────

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

// ─── Billing (Shopify Billing API) ──────────────────────────────────────

const BILLING_PLAN = {
  name: 'StockyShift Monthly',
  price: 29.00,
  trial_days: 7,
  return_url: `${APP_URL}/billing/confirm`,
  test: process.env.NODE_ENV !== 'production',
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

// Create a Shopify billing charge and return confirmation URL
async function createCharge(shop, token) {
  const response = await axios.post(
    `https://${shop}/admin/api/2024-04/recurring_application_charges.json`,
    { recurring_application_charge: BILLING_PLAN },
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  return response.data.recurring_application_charge;
}

// Activate a Shopify billing charge
async function activateCharge(shop, token, chargeId) {
  const response = await axios.post(
    `https://${shop}/admin/api/2024-04/recurring_application_charges/${chargeId}/activate.json`,
    {},
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );
  return response.data.recurring_application_charge;
}

// Get billing status for the dashboard
app.get('/api/billing/status', (req, res) => {
  const { shop } = req.query;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const merchant = db.prepare('SELECT * FROM merchants WHERE shop = ?').get(shop);
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
  const { shop } = req.body;
  if (!shop) return res.status(400).json({ error: 'Missing shop' });

  const token = getToken(shop);
  if (!token) return res.status(401).json({ error: 'Not installed' });

  try {
    const charge = await createCharge(shop, token);
    // Store charge ID
    db.prepare('UPDATE merchants SET shopify_charge_id = ? WHERE shop = ?').run(String(charge.id), shop);
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

// Callback from Shopify after merchant approves (or declines) billing
app.get('/billing/confirm', async (req, res) => {
  const { charge_id, shop } = req.query;
  if (!shop) return res.status(400).send('Missing shop');

  // Merchant declined billing — redirect back to dashboard with declined flag
  if (!charge_id) {
    return res.redirect(`/?shop=${shop}&billing=declined`);
  }

  const token = getToken(shop);
  if (!token) return res.status(401).send('Not installed');

  try {
    const charge = await activateCharge(shop, token, charge_id);

    // Calculate trial end date (7 days from now)
    const trialEnd = new Date();
    trialEnd.setDate(trialEnd.getDate() + BILLING_PLAN.trial_days);

    const billingStatus = BILLING_PLAN.trial_days > 0 ? 'trial' : 'active';

    db.prepare(`
      UPDATE merchants
      SET shopify_charge_id = ?, billing_status = ?, trial_ends_at = ?
      WHERE shop = ?
    `).run(String(charge.id), billingStatus, trialEnd.toISOString(), shop);

    console.log(`[Billing] ${shop} subscribed — ${billingStatus} until ${trialEnd.toISOString()}`);

    // Redirect to dashboard
    res.redirect(`/?shop=${shop}`);
  } catch (err) {
    console.error('[Billing] Activate charge error:', err.response?.data || err.message);
    res.status(500).send('Failed to activate billing. Please try again.');
  }
});

// ─── Debug: check which API key is active ────────────────────────────────
app.get('/api/debug', (req, res) => {
  const key = process.env.SHOPIFY_API_KEY || 'NOT SET';
  res.json({
    api_key_prefix: key.substring(0, 8) + '...',
    api_key_length: key.length,
    app_url: APP_URL,
    skip_billing: process.env.SKIP_BILLING,
    node_env: process.env.NODE_ENV,
  });
});

// ─── Cron Job: Daily Low Stock Check ─────────────────────────────────────

// Run at 8:00 AM every day
cron.schedule('0 8 * * *', () => {
  console.log('[Cron] Running daily low stock check...');

  const merchants = db.prepare('SELECT shop, access_token FROM merchants WHERE is_active = 1').all();

  for (const merchant of merchants) {
    const lowStock = db.prepare(`
      SELECT p.*, v.name as vendor_name
      FROM products p
      LEFT JOIN vendors v ON p.preferred_vendor_id = v.id
      WHERE p.shop = ?
        AND p.is_active = 1
        AND p.reorder_point > 0
        AND p.current_stock <= p.reorder_point
    `).all(merchant.shop);

    if (lowStock.length > 0) {
      console.log(`[Cron] ${merchant.shop}: ${lowStock.length} products below reorder point`);
      try {
        const lowStockList = lowStock.map(p =>
          `- ${p.product_name} (SKU: ${p.sku}) — Stock: ${p.current_stock}, Reorder at: ${p.reorder_point}`
        ).join('\n');

        const emailText = `StockyShift — Low Stock Alert for ${merchant.shop}\n\n` +
          `The following products are below their reorder point:\n\n${lowStockList}\n\n` +
          `Log in to StockyShift to create purchase orders:\n${process.env.APP_URL || 'https://stockyshift.onrender.com'}\n`;

        const merchantInfo = db.prepare('SELECT email FROM merchants WHERE shop = ?').get(merchant.shop);
        if (merchantInfo?.email) {
          sendPOEmail({
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
});

// ─── Webhook: Handle app uninstall ───────────────────────────────────────

app.post('/webhooks/app/uninstalled', (req, res) => {
  const shop = req.headers['x-shopify-shop-domain'];
  const hmac = req.headers['x-shopify-hmac-sha256'];
  if (!shop) return res.status(400).send('Missing shop');

  // Verify HMAC to ensure this is a real Shopify webhook
  if (!verifyWebhook(req.rawBody, hmac)) {
    console.warn(`[Webhook] Invalid HMAC for uninstall from ${shop}`);
    return res.status(401).send('Invalid HMAC');
  }

  db.prepare(`
    UPDATE merchants SET is_active = 0, uninstalled_at = CURRENT_TIMESTAMP WHERE shop = ?
  `).run(shop);

  console.log(`[Webhook] ${shop} uninstalled StockyShift`);
  res.status(200).send('OK');
});

// ─── Start ───────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`StockyShift running on port ${PORT}`);
  console.log(`OAuth callback URL: ${APP_URL}/auth/callback`);
});
