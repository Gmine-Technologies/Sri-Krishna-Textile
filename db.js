require('dotenv').config();
const mysql = require('mysql2/promise');

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'sreekrishna_store',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  decimalNumbers: true
};

let pool = null;

async function init() {
  if (!pool) {
    // 1. Try to connect directly to the configured database (Hostinger / cloud / existing DB)
    try {
      const testPool = mysql.createPool(config);
      const conn = await testPool.getConnection();
      conn.release();
      pool = testPool;
    } catch (err) {
      // If the database does not exist (ER_BAD_DB_ERROR), attempt to create it (for local dev / XAMPP)
      if (err.code === 'ER_BAD_DB_ERROR') {
        try {
          const tempConn = await mysql.createConnection({
            host: config.host,
            port: config.port,
            user: config.user,
            password: config.password
          });
          await tempConn.query(`CREATE DATABASE IF NOT EXISTS \`${config.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
          await tempConn.end();
          pool = mysql.createPool(config);
        } catch (createErr) {
          throw new Error(
            `Database '${config.database}' does not exist on MySQL server (${config.host}). ` +
            `On Hostinger, please create the database inside Hostinger hPanel -> Databases -> MySQL Databases, ` +
            `then update DB_NAME, DB_USER, and DB_PASSWORD to match your Hostinger database details.`
          );
        }
      } else {
        throw err;
      }
    }
  }

  // 3. Create tables and indexes
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(191) NOT NULL UNIQUE,
      hash VARCHAR(255) NOT NULL,
      role VARCHAR(32) NOT NULL DEFAULT 'customer',
      phone VARCHAR(20) DEFAULT NULL,
      address VARCHAR(500) DEFAULT NULL,
      created VARCHAR(40)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id VARCHAR(32) PRIMARY KEY,
      name VARCHAR(191),
      cat VARCHAR(100),
      sub VARCHAR(100),
      price INT,
      disc INT,
      mrp INT,
      cost INT,
      col VARCHAR(60),
      fab VARCHAR(100),
      rating DOUBLE DEFAULT 0,
      rev INT DEFAULT 0,
      stock INT DEFAULT 0,
      sku VARCHAR(64),
      occ VARCHAR(60),
      descr TEXT,
      img LONGTEXT,
      created VARCHAR(40),
      sort_order INT AUTO_INCREMENT UNIQUE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_images (
      filename VARCHAR(191) PRIMARY KEY,
      product_id VARCHAR(32),
      mime VARCHAR(64) NOT NULL,
      data LONGBLOB NOT NULL,
      created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX ix_images_prod (product_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id VARCHAR(64) PRIMARY KEY,
      user_id INT DEFAULT NULL,
      email VARCHAR(191),
      name VARCHAR(120),
      address TEXT,
      phone VARCHAR(20),
      ship INT DEFAULT 0,
      total INT,
      cost INT,
      pay VARCHAR(60),
      status VARCHAR(60),
      pay_ref VARCHAR(100) DEFAULT NULL,
      tracking VARCHAR(100) DEFAULT NULL,
      courier VARCHAR(100) DEFAULT NULL,
      eta VARCHAR(100) DEFAULT NULL,
      created VARCHAR(40),
      INDEX ix_orders_created (created),
      INDEX ix_orders_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      order_id VARCHAR(64) NOT NULL,
      product_id VARCHAR(32),
      name VARCHAR(191),
      col VARCHAR(60),
      qty INT,
      price INT,
      cost INT,
      INDEX ix_order_items_order (order_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INT AUTO_INCREMENT PRIMARY KEY,
      month VARCHAR(10),
      kind VARCHAR(60),
      amount INT,
      INDEX ix_expenses_month (month)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_events (
      id INT AUTO_INCREMENT PRIMARY KEY,
      order_id VARCHAR(64) NOT NULL,
      status VARCHAR(60),
      note VARCHAR(255),
      created VARCHAR(40),
      INDEX ix_events_order (order_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      k VARCHAR(100) PRIMARY KEY,
      v TEXT
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_otps (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(191) NOT NULL,
      otp VARCHAR(16) NOT NULL,
      purpose VARCHAR(32) NOT NULL DEFAULT 'forgot_password',
      token VARCHAR(64) DEFAULT NULL,
      verified TINYINT DEFAULT 0,
      attempts INT DEFAULT 0,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL,
      INDEX ix_otps_email_purpose (email, purpose)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  try {
    await pool.query('ALTER TABLE orders ADD COLUMN pay_ref VARCHAR(100) DEFAULT NULL');
  } catch (_) {}

  // Billing & Purchase Management Tables (from purchasedb.sql)
  for (const q of [
    'ALTER TABLE users ADD COLUMN username VARCHAR(150) NULL UNIQUE',
    'ALTER TABLE users ADD COLUMN password VARCHAR(255) NULL',
    'ALTER TABLE users ADD COLUMN is_superuser TINYINT(1) DEFAULT 0',
    'ALTER TABLE users ADD COLUMN is_staff TINYINT(1) DEFAULT 0',
    'ALTER TABLE users ADD COLUMN is_active TINYINT(1) DEFAULT 1',
    'ALTER TABLE users ADD COLUMN first_name VARCHAR(150) DEFAULT ""',
    'ALTER TABLE users ADD COLUMN last_name VARCHAR(150) DEFAULT ""',
    'ALTER TABLE products ADD COLUMN unit_price DECIMAL(12,2) DEFAULT NULL',
    'ALTER TABLE products ADD COLUMN is_active TINYINT(1) DEFAULT 1'
  ]) {
    try { await pool.query(q); } catch (_) {}
  }

  try {
    await pool.query('UPDATE users SET password = hash WHERE password IS NULL OR password = ""');
  } catch (_) {}

  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id INT AUTO_INCREMENT PRIMARY KEY,
      customer_code VARCHAR(50) NOT NULL UNIQUE,
      name VARCHAR(200) NOT NULL,
      phone_number VARCHAR(20) NOT NULL,
      email VARCHAR(254) NULL,
      address TEXT NULL,
      is_active TINYINT(1) DEFAULT 1,
      total_loyalty_points INT DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_cust_phone (phone_number),
      INDEX idx_cust_name (name),
      INDEX idx_cust_code (customer_code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS purchases (
      id INT AUTO_INCREMENT PRIMARY KEY,
      invoice_number VARCHAR(60) NOT NULL UNIQUE,
      customer_id INT NOT NULL,
      record_type VARCHAR(20) NOT NULL DEFAULT 'sale',
      subtotal DECIMAL(12,2) NOT NULL DEFAULT 0.00,
      discount_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
      tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
      final_amount DECIMAL(12,2) NOT NULL DEFAULT 0.00,
      points_earned INT NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'completed',
      idempotency_key VARCHAR(120) NULL UNIQUE,
      created_by_id INT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_purch_inv (invoice_number),
      INDEX idx_purch_type (record_type),
      INDEX idx_purch_status (status),
      INDEX idx_purch_created (created_at),
      INDEX idx_purch_cust (customer_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS purchase_items (
      id INT AUTO_INCREMENT PRIMARY KEY,
      purchase_id INT NOT NULL,
      product_id VARCHAR(64) NULL,
      product_name_snapshot VARCHAR(200) NOT NULL,
      product_sku_snapshot VARCHAR(50) NOT NULL,
      unit_price DECIMAL(12,2) NOT NULL,
      quantity INT NOT NULL DEFAULT 1,
      line_total DECIMAL(12,2) NOT NULL,
      INDEX idx_item_purch (purchase_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS loyalty_transactions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      customer_id INT NOT NULL,
      purchase_id INT NULL,
      transaction_type VARCHAR(20) NOT NULL DEFAULT 'award',
      points_change INT NOT NULL,
      description VARCHAR(255) NOT NULL,
      resulting_balance INT NOT NULL,
      created_by_id INT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_loyalty_cust (customer_id, created_at),
      INDEX idx_loyalty_type (transaction_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
  `);

  try {
    await pool.query('UPDATE products SET unit_price = price WHERE unit_price IS NULL OR unit_price = 0');
  } catch (_) {}

  return pool;
}

async function get(sql, params = []) {
  if (!pool) await init();
  const [rows] = await pool.query(sql, params);
  return rows[0] || null;
}

async function all(sql, params = []) {
  if (!pool) await init();
  const [rows] = await pool.query(sql, params);
  return rows;
}

async function run(sql, params = []) {
  if (!pool) await init();
  const [result] = await pool.query(sql, params);
  return {
    changes: result.affectedRows || 0,
    lastInsertRowid: result.insertId || 0
  };
}

async function transaction(callback) {
  if (!pool) await init();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const tx = {
      async get(sql, params = []) {
        const [rows] = await conn.query(sql, params);
        return rows[0] || null;
      },
      async all(sql, params = []) {
        const [rows] = await conn.query(sql, params);
        return rows;
      },
      async run(sql, params = []) {
        const [result] = await conn.query(sql, params);
        return {
          changes: result.affectedRows || 0,
          lastInsertRowid: result.insertId || 0
        };
      },
      query: conn.query.bind(conn)
    };
    const res = await callback(tx);
    await conn.commit();
    return res;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

async function close() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}

module.exports = {
  init,
  get,
  all,
  run,
  transaction,
  close,
  query: async (...args) => {
    if (!pool) await init();
    return pool.query(...args);
  },
  get pool() {
    return pool;
  }
};
