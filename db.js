const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

let pool;
if (DATABASE_URL) {
  // Log partial URL for debugging (mask password)
  const masked = DATABASE_URL.replace(/\/\/.*:.*@/, '//user:***@');
  console.log('[DB] Connecting to:', masked);
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 10000,
  });
} else {
  // Fallback: use SQLite for local dev
  const Database = require('better-sqlite3');
  const path = require('path');
  const dbPath = process.env.DB_PATH || path.join(__dirname, 'stockyshift.db');
  const sqliteDb = new Database(dbPath);
  sqliteDb.pragma('journal_mode = WAL');
  sqliteDb.pragma('foreign_keys = ON');

  // Convert PostgreSQL-style $1,$2 params to SQLite ? params
  function toSqlite(sql, params) {
    if (!params || params.length === 0) return { sql, params, hasReturning: false };
    const converted = sql.replace(/\$(\d+)/g, (_, n) => {
      const idx = parseInt(n) - 1;
      if (idx >= 0 && idx < params.length) return '?';
      return `$${n}`; // keep as-is if out of range
    });
    const hasReturning = /RETURNING\s+/i.test(converted);
    return { sql: converted, params, hasReturning };
  }

  // Helper: execute RETURNING-like query for SQLite
  function returningQuery(originalSql, params, mode) {
    const { sql: s, params: p, hasReturning } = toSqlite(originalSql, params);
    if (hasReturning) {
      // SQLite doesn't support RETURNING. Execute INSERT, then get lastInsertRowid
      const stmt = sqliteDb.prepare(s.replace(/\s+RETURNING\s+\S+/i, ''));
      const info = stmt.run(...(p || []));
      if (mode === 'get') {
        return Promise.resolve({ id: info.lastInsertRowid });
      }
      return Promise.resolve([{ id: info.lastInsertRowid }]);
    }
    if (mode === 'get') {
      return Promise.resolve(sqliteDb.prepare(s).get(...(p || [])));
    }
    return Promise.resolve(sqliteDb.prepare(s).all(...(p || [])));
  }

  // Create a compat wrapper that matches the pg-style API (async)
  const compatDb = {
    get: (sql, params) => returningQuery(sql, params, 'get'),
    all: (sql, params) => returningQuery(sql, params, 'all'),
    run: (sql, params) => {
      try {
        const { sql: s, params: p } = toSqlite(sql, params);
        const stmt = sqliteDb.prepare(s);
        if (p && p.length > 0) stmt.run(...p);
        else stmt.run();
        return Promise.resolve({ changes: sqliteDb.changes });
      } catch (e) { return Promise.reject(e); }
    },
    exec: (sql) => {
      try { sqliteDb.exec(sql); return Promise.resolve(); }
      catch (e) { return Promise.reject(e); }
    },
    // SQLite synchronous transaction
    transaction: (fn) => {
      return Promise.resolve(sqliteDb.transaction(fn)());
    },
  };

  // Initialize SQLite schema
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
    CREATE INDEX IF NOT EXISTS idx_products_shop ON products(shop);
    CREATE INDEX IF NOT EXISTS idx_products_reorder ON products(shop, reorder_point, current_stock);
    CREATE INDEX IF NOT EXISTS idx_po_shop ON purchase_orders(shop, status);
  `);
  // Migrations
  try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN email TEXT;`); } catch (_) {}
  try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN shopify_charge_id TEXT;`); } catch (_) {}
  try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN billing_status TEXT DEFAULT 'pending';`); } catch (_) {}
  try { sqliteDb.exec(`ALTER TABLE merchants ADD COLUMN trial_ends_at DATETIME;`); } catch (_) {}

  module.exports = compatDb;
  return;
}

// ─── PostgreSQL Schema ─────────────────────────────────────────────────────

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS merchants (
      id SERIAL PRIMARY KEY,
      shop TEXT UNIQUE NOT NULL,
      access_token TEXT NOT NULL,
      email TEXT,
      shopify_charge_id TEXT,
      billing_status TEXT DEFAULT 'pending',
      trial_ends_at TIMESTAMP,
      installed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      uninstalled_at TIMESTAMP,
      is_active INTEGER DEFAULT 1
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vendors (
      id SERIAL PRIMARY KEY,
      shop TEXT NOT NULL REFERENCES merchants(shop),
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      min_order_amount DOUBLE PRECISION DEFAULT 0,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      shopify_product_id BIGINT NOT NULL,
      shopify_variant_id BIGINT,
      shop TEXT NOT NULL REFERENCES merchants(shop),
      title TEXT NOT NULL,
      sku TEXT,
      reorder_point INTEGER DEFAULT 0,
      current_stock INTEGER DEFAULT 0,
      preferred_vendor_id INTEGER REFERENCES vendors(id),
      unit_cost DOUBLE PRECISION DEFAULT 0,
      is_active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(shop, shopify_variant_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS purchase_orders (
      id SERIAL PRIMARY KEY,
      shop TEXT NOT NULL REFERENCES merchants(shop),
      vendor_id INTEGER NOT NULL REFERENCES vendors(id),
      po_number TEXT NOT NULL,
      status TEXT DEFAULT 'draft',
      total DOUBLE PRECISION DEFAULT 0,
      emailed_at TIMESTAMP,
      received_at TIMESTAMP,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS po_line_items (
      id SERIAL PRIMARY KEY,
      po_id INTEGER NOT NULL REFERENCES purchase_orders(id),
      product_id INTEGER NOT NULL REFERENCES products(id),
      ordered_qty INTEGER NOT NULL,
      received_qty INTEGER DEFAULT 0,
      unit_cost DOUBLE PRECISION DEFAULT 0
    );
  `);

  // Indexes
  await pool.query('CREATE INDEX IF NOT EXISTS idx_products_shop ON products(shop)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_products_reorder ON products(shop, reorder_point, current_stock)');
  await pool.query('CREATE INDEX IF NOT EXISTS idx_po_shop ON purchase_orders(shop, status)');

  // Add missing columns (idempotent)
  try { await pool.query('ALTER TABLE merchants ADD COLUMN email TEXT'); } catch (_) {}
  try { await pool.query('ALTER TABLE merchants ADD COLUMN shopify_charge_id TEXT'); } catch (_) {}
  try { await pool.query('ALTER TABLE merchants ADD COLUMN billing_status TEXT DEFAULT \'pending\''); } catch (_) {}
  try { await pool.query('ALTER TABLE merchants ADD COLUMN trial_ends_at TIMESTAMP'); } catch (_) {}
}

// Run schema init (with logging)
console.log('[DB] PostgreSQL connecting with timeout 5s...');
const schemaPromise = initSchema().then(() => {
  console.log('[DB] PostgreSQL schema initialized successfully');
}).catch(err => {
  console.error('[DB] Schema init failed:', err.message, err.stack?.substring(0, 500));
});

// ─── Async DB Wrapper ─────────────────────────────────────────────────────

const db = {
  get: async (sql, params) => {
    await schemaPromise;
    const result = await pool.query(sql, params);
    return result.rows[0];
  },
  all: async (sql, params) => {
    await schemaPromise;
    const result = await pool.query(sql, params);
    return result.rows;
  },
  run: async (sql, params) => {
    await schemaPromise;
    const result = await pool.query(sql, params);
    return { changes: result.rowCount };
  },
  exec: async (sql) => {
    await schemaPromise;
    await pool.query(sql);
  },
  // PostgreSQL transaction: run all queries sequentially in a transaction
  transaction: async (fn) => {
    await schemaPromise;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn({
        get: (sql, params) => client.query(sql, params).then(r => r.rows[0]),
        all: (sql, params) => client.query(sql, params).then(r => r.rows),
        run: (sql, params) => client.query(sql, params).then(r => ({ changes: r.rowCount })),
      });
      await client.query('COMMIT');
      return result;
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  },
  // Get a connection for manual transaction management
  connect: async () => {
    await schemaPromise;
    const client = await pool.connect();
    await client.query('BEGIN');
    return client;
  },
};

module.exports = db;
