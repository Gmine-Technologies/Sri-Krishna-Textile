require('dotenv').config();
const db = require('./db');
const seed = require('./seed');

async function reseed() {
  try {
    await db.init();
    console.log('Dropping existing tables to reseed...');
    await db.run('SET FOREIGN_KEY_CHECKS = 0');
    const tables = ['order_events', 'order_items', 'orders', 'expenses', 'products', 'users', 'settings'];
    for (const t of tables) {
      await db.run(`DROP TABLE IF EXISTS \`${t}\``);
    }
    await db.run('SET FOREIGN_KEY_CHECKS = 1');
    console.log('Recreating tables...');
    await db.init();
    console.log('Reseeding data...');
    await seed(db);
    console.log('Reseed complete!');
    await db.close();
    process.exit(0);
  } catch (e) {
    console.error('Reseed failed:', e);
    process.exit(1);
  }
}

reseed();
