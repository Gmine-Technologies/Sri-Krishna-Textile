const Database = require('better-sqlite3');
const path = require('path'), fs = require('fs');
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(process.env.DB_FILE || path.join(__dirname, 'data', 'store.db'));
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', created TEXT);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, name TEXT, cat TEXT, sub TEXT, price INTEGER, disc INTEGER, mrp INTEGER, cost INTEGER, col TEXT, fab TEXT, rating REAL, rev INTEGER, stock INTEGER, sku TEXT, occ TEXT, descr TEXT, img TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, user_id INTEGER, email TEXT, name TEXT, address TEXT, total INTEGER, cost INTEGER, pay TEXT, status TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE, product_id TEXT, name TEXT, col TEXT, qty INTEGER, price INTEGER, cost INTEGER);
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY, month TEXT, kind TEXT, amount INTEGER);
CREATE TABLE IF NOT EXISTS order_events(id INTEGER PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE, status TEXT, note TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS ix_orders_created ON orders(created);
CREATE INDEX IF NOT EXISTS ix_events_order ON order_events(order_id);
`);
const addCol = (t, c, def) => { if (!db.prepare(`PRAGMA table_info(${t})`).all().some(r => r.name === c)) db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`); };
[['orders', 'phone', 'TEXT'], ['orders', 'ship', 'INTEGER DEFAULT 0'], ['orders', 'tracking', 'TEXT'], ['orders', 'courier', 'TEXT'], ['orders', 'eta', 'TEXT'], ['users', 'phone', 'TEXT'], ['users', 'address', 'TEXT']].forEach(x => addCol(...x));
module.exports = db;
