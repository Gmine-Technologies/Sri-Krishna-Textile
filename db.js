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
  if (pool) return pool;

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
