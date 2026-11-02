require('dotenv').config();
const mysql = require('mysql2/promise');

async function test() {
  console.log(`Connecting to MySQL at ${process.env.DB_HOST}:${process.env.DB_PORT} as user '${process.env.DB_USER}'...`);
  try {
    const conn = await mysql.createConnection({
      host: process.env.DB_HOST || '127.0.0.1',
      port: parseInt(process.env.DB_PORT || '3306', 10),
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || ''
    });
    console.log('>> SUCCESS: Connected to MariaDB/MySQL successfully!');
    
    const dbName = process.env.DB_NAME || 'sreekrishna_store';
    console.log(`>> Creating database '${dbName}' if it does not exist...`);
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
    console.log(`>> SUCCESS: Database '${dbName}' is now visible in phpMyAdmin!`);
    await conn.end();
  } catch (err) {
    console.error('>> ERROR:', err.message);
  }
}

test();
