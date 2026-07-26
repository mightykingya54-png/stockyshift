const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'stockyshift.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrent access
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── Schema ──────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS merchants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop TEXT UNIQUE NOT NULL,
    access_token TEXT NOT NULL,
    email TEXT,
    shopify_charge_id TEXT,
    billing_status TEXT DEFAULT 'pending',
    trial_ends_at DATETIME,
    installed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    uninstalled_at DATETIME,
    is_active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    min_order_amount REAL DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shop) REFERENCES merchants(shop)
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shopify_product_id INTEGER NOT NULL,
    shopify_variant_id INTEGER,
    shop TEXT NOT NULL,
    title TEXT NOT NULL,
    sku TEXT,
    reorder_point INTEGER DEFAULT 0,
    current_stock INTEGER DEFAULT 0,
    preferred_vendor_id INTEGER,
    unit_cost REAL DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shop) REFERENCES merchants(shop),
    FOREIGN KEY (preferred_vendor_id) REFERENCES vendors(id),
    UNIQUE(shop, shopify_variant_id)
  );

  CREATE TABLE IF NOT EXISTS purchase_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    shop TEXT NOT NULL,
    vendor_id INTEGER NOT NULL,
    po_number TEXT NOT NULL,
    status TEXT DEFAULT 'draft',
    total REAL DEFAULT 0,
    emailed_at DATETIME,
    received_at DATETIME,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shop) REFERENCES merchants(shop),
    FOREIGN KEY (vendor_id) REFERENCES vendors(id)
  );

  CREATE TABLE IF NOT EXISTS po_line_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    po_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    ordered_qty INTEGER NOT NULL,
    received_qty INTEGER DEFAULT 0,
    unit_cost REAL DEFAULT 0,
    FOREIGN KEY (po_id) REFERENCES purchase_orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
  );

  CREATE INDEX IF NOT EXISTS idx_products_shop ON products(shop);
  CREATE INDEX IF NOT EXISTS idx_products_reorder ON products(shop, reorder_point, current_stock);
  CREATE INDEX IF NOT EXISTS idx_po_shop ON purchase_orders(shop, status);
`);

// Migrations: add columns to merchants if upgrading from old schema
try { db.exec(`ALTER TABLE merchants ADD COLUMN email TEXT;`); } catch (_) {}
try { db.exec(`ALTER TABLE merchants ADD COLUMN shopify_charge_id TEXT;`); } catch (_) {}
try { db.exec(`ALTER TABLE merchants ADD COLUMN billing_status TEXT DEFAULT 'pending';`); } catch (_) {}
try { db.exec(`ALTER TABLE merchants ADD COLUMN trial_ends_at DATETIME;`); } catch (_) {}

module.exports = db;
