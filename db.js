const Database = require('better-sqlite3');
const path = require('path');

const dbPath = process.env.DB_PATH || path.join(__dirname, 'stockyshift.db');
const sqliteDb = new Database(dbPath);

// Enable WAL mode for better concurrent access
sqliteDb.pragma('journal_mode = WAL');
sqliteDb.pragma('foreign_keys = ON');

// ─── Schema ──────────────────────────────────────────────────────────────

sqliteDb.exec(`
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

  CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    shop TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_products_shop ON products(shop);
  CREATE INDEX IF NOT EXISTS idx_products_reorder ON products(shop, reorder_point, current_stock);
  CREATE INDEX IF NOT EXISTS idx_po_shop ON purchase_orders(shop, status);
`);

// Migrations: add columns to merchants if upgrading from old schema
try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN email TEXT;`); } catch (_) {}
try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN shopify_charge_id TEXT;`); } catch (_) {}
try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN billing_status TEXT DEFAULT 'pending';`); } catch (_) {}
try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN trial_ends_at DATETIME;`); } catch (_) {}
try { sqliteDb.exec(`ALTER TABLE products ADD COLUMN inventory_item_id INTEGER;`); } catch (_) {}
try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN refresh_token TEXT;`); } catch (_) {}
try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN expires_at TEXT;`); } catch (_) {}

// ─── Async Promise Wrapper ───────────────────────────────────────────────
// Converts synchronous better-sqlite3 calls to async promises
// so server.js can use await db.get(...) / await db.all(...) etc.

function toSqlite(sql, params) {
  if (!params || params.length === 0) return { sql, params: [] };
  // Map $N references to actual array indices, building expanded params
  const expanded = [];
  const converted = sql.replace(/\$(\d+)/g, (_, n) => {
    const idx = parseInt(n) - 1;
    if (idx >= 0 && idx < params.length) {
      expanded.push(params[idx]);
      return '?';
    }
    return `$${n}`; // leave as-is if out of range (shouldn't happen)
  });
  return { sql: converted, params: expanded };
}

const db = {
  get: (sql, params) => {
    try {
      const { sql: s, params: p } = toSqlite(sql, params);
      // Handle RETURNING for SQLite — execute INSERT then return lastInsertRowid
      if (/^\s*INSERT\s/i.test(s) && /RETURNING/i.test(s)) {
        const cleanSql = s.replace(/\s+RETURNING\s+\S+/i, '');
        const info = sqliteDb.prepare(cleanSql).run(...(p || []));
        return Promise.resolve({ id: info.lastInsertRowid });
      }
      return Promise.resolve(sqliteDb.prepare(s).get(...(p || [])));
    } catch (e) {
      return Promise.reject(e);
    }
  },
  all: (sql, params) => {
    try {
      const { sql: s, params: p } = toSqlite(sql, params);
      return Promise.resolve(sqliteDb.prepare(s).all(...(p || [])));
    } catch (e) {
      return Promise.reject(e);
    }
  },
  run: (sql, params) => {
    try {
      const { sql: s, params: p } = toSqlite(sql, params);
      const stmt = sqliteDb.prepare(s);
      const info = (p && p.length > 0) ? stmt.run(...p) : stmt.run();
      return Promise.resolve({ changes: info.changes, lastInsertRowid: info.lastInsertRowid });
    } catch (e) {
      return Promise.reject(e);
    }
  },
  exec: (sql) => {
    try { sqliteDb.exec(sql); return Promise.resolve(); }
    catch (e) { return Promise.reject(e); }
  },
  // Transaction — wraps fn in BEGIN/COMMIT with a tx object
  transaction: async (fn) => {
    sqliteDb.exec('BEGIN');
    try {
      // Create a tx object with the same .get/.all/.run interface
      const tx = {
        get: (sql, params) => {
          const { sql: s, params: p } = toSqlite(sql, params);
          if (/^\s*INSERT\s/i.test(s) && /RETURNING/i.test(s)) {
            const cleanSql = s.replace(/\s+RETURNING\s+\S+/i, '');
            const info = sqliteDb.prepare(cleanSql).run(...(p || []));
            return { id: info.lastInsertRowid };
          }
          return sqliteDb.prepare(s).get(...(p || []));
        },
        all: (sql, params) => {
          const { sql: s, params: p } = toSqlite(sql, params);
          return sqliteDb.prepare(s).all(...(p || []));
        },
        run: (sql, params) => {
          const { sql: s, params: p } = toSqlite(sql, params);
          const stmt = sqliteDb.prepare(s);
          const info = (p && p.length > 0) ? stmt.run(...p) : stmt.run();
          return { changes: info.changes, lastInsertRowid: info.lastInsertRowid };
        },
      };
      const result = await fn(tx);
      sqliteDb.exec('COMMIT');
      return result;
    } catch (e) {
      sqliteDb.exec('ROLLBACK');
      throw e;
    }
  },
};

module.exports = db;
