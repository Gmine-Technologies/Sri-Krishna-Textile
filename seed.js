// Seeds products, demo customers, historical orders and expenses on first run.
const bcrypt = require('bcryptjs');
const R = (i, m) => (i * 7919 + 13) % m;
const CK = ['Pink', 'Red', 'Green', 'Blue', 'Purple', 'Gold', 'Maroon', 'Black', 'Yellow'];
const SF = [['Kanchipuram Silk', 'Kanchipuram'], ['Banarasi Gold Zari Silk', 'Banarasi'], ['Designer Silk', 'Designer'], ['Wedding Silk', 'Wedding'], ['Tissue Silk', 'Silk'], ['Pure Cotton', 'Cotton'], ['Bridal Kanchipuram', 'Wedding'], ['Party Wear Georgette', 'Party Wear']];
module.exports = function seed(db) {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@sreekrishna.demo').toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
  if (!db.prepare("SELECT 1 FROM users WHERE role='admin'").get()) {
    db.prepare('INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)').run('Admin', adminEmail, bcrypt.hashSync(adminPass, 10), 'admin', new Date().toISOString());
    if (adminPass === 'admin123') console.warn('WARNING: default admin password in use. Set ADMIN_PASSWORD before deploying.');
  }
  if (db.prepare('SELECT COUNT(*) n FROM products').get().n) return;
  const P = [];
  const add = (cat, sub, names, n, base, fab) => {
    for (let i = 0; i < n; i++) {
      const k = P.length, c = CK[(k * 5 + i) % 9], f = fab ? fab[i % fab.length] : null;
      const [fn, sb] = cat === 'Sarees' ? SF[i % 8] : [f, sub];
      const d = [10, 15, 20, 25, 30, 35, 40][R(k, 7)], pr = Math.round((base + R(k, 3600)) / 10) * 10 - 1, num = 1000 + k;
      P.push({ id: 'SK' + num, name: cat === 'Sarees' ? `${c === 'Pink' ? 'Royal Magenta' : c} ${fn} Saree` : `${c} ${names[i % names.length]}`, cat, sub: sb, price: pr, disc: d, mrp: Math.round(pr / (1 - d / 100) / 10) * 10, cost: Math.round(pr * (.52 + R(num, 12) / 100)), col: c, fab: fn, rating: +(3.9 + R(k, 12) / 10).toFixed(1), rev: 20 + R(k, 300), stock: R(k, 40), sku: 'SKT-' + (5000 + k * 13), occ: ['Wedding', 'Festive', 'Party', 'Daily'][R(k, 4)], desc: `A ${fn.toLowerCase()} piece in ${c.toLowerCase()} with fine craftsmanship from heritage looms.` });
    }
  };
  add('Sarees', '', [], 30, 2800);
  add('Lehengas', 'Lehenga', ['Bridal Lehenga', 'Silk Lehenga', 'Designer Lehenga', 'Festive Lehenga'], 10, 8000, ['Silk', 'Net', 'Velvet']);
  add('Kurtis', 'Kurti', ['Cotton Kurti', 'Anarkali Kurti', 'Straight Kurti', 'Embroidered Kurti'], 10, 899, ['Cotton', 'Rayon']);
  add('Suits & Dress Materials', 'Suit', ['Unstitched Suit', 'Dress Material', 'Salwar Set'], 10, 1599, ['Cotton', 'Chanderi']);
  add('Home Decor', 'Decor', ['Silk Cushion Cover', 'Brass Diya Set', 'Table Runner', 'Curtain Pair', 'Bedsheet Set'], 10, 599, ['Silk', 'Brass', 'Cotton']);
  const now = new Date().toISOString();
  const ip = db.prepare('INSERT INTO products(id,name,cat,sub,price,disc,mrp,cost,col,fab,rating,rev,stock,sku,occ,descr,img,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)');
  // demo customers + sample history (clearly sample data; delete via "npm run reseed")
  const cust = [['Priya Nair', 'priya@example.com'], ['Lakshmi Devi', 'lakshmi@example.com'], ['Anita Rao', 'anita@example.com'], ['Meena S', 'meena@example.com'], ['Divya K', 'divya@example.com']];
  const iu = db.prepare('INSERT OR IGNORE INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)'), h = bcrypt.hashSync('customer123', 10);
  const io = db.prepare('INSERT INTO orders(id,user_id,email,name,address,phone,ship,total,cost,pay,status,created,tracking,courier) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)');
  const ive = db.prepare('INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)');
  const later = (iso, d) => new Date(Date.parse(iso) + d * 864e5).toISOString();
  const evs = (id, st, iso) => { ive.run(id, 'Processing', 'Order placed', iso); if (st !== 'Processing') ive.run(id, 'Shipped', 'Packed and handed to courier', later(iso, 1)); if (st === 'Delivered') { ive.run(id, 'Out for Delivery', 'Out for delivery today', later(iso, 3)); ive.run(id, 'Delivered', 'Delivered successfully', later(iso, 3.3)); } };
  const ii = db.prepare('INSERT INTO order_items(order_id,product_id,name,col,qty,price,cost) VALUES(?,?,?,?,?,?,?)');
  const ie = db.prepare('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)');
  const BASE = [205000, 265000, 355000, 430000, 395000, 285000, 240000, 490000, 640000, 310000];
  const year = 2026, pays = ['UPI', 'Credit Card', 'Cash on Delivery', 'Net Banking'];
  db.transaction(() => {
    P.forEach(p => ip.run(p.id, p.name, p.cat, p.sub, p.price, p.disc, p.mrp, p.cost, p.col, p.fab, p.rating, p.rev, p.stock, p.sku, p.occ, p.desc, now));
    const users = cust.map(([n, e]) => { iu.run(n, e, h, 'customer', now); return db.prepare('SELECT id,name,email FROM users WHERE email=?').get(e); });
    let seq = 0, rnd = 12345; const rand = () => (rnd = (rnd * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    BASE.forEach((target, mi) => {
      let sum = 0; const mm = String(mi + 1).padStart(2, '0');
      while (sum < target) {
        const u = users[seq % users.length], lines = 1 + (rand() < .35 ? 1 : 0), items = [];
        for (let l = 0; l < lines; l++) { const p = P[Math.floor(rand() * (rand() < .65 ? 30 : P.length))]; items.push({ p, q: 1 + (rand() < .25 ? 1 : 0) }); }
        const sub = items.reduce((a, x) => a + x.p.price * x.q, 0), total = sub + (sub < 2999 ? 99 : 0), cost = items.reduce((a, x) => a + x.p.cost * x.q, 0);
        const day = String(1 + Math.floor(rand() * (mi === 9 ? 5 : 27))).padStart(2, '0'), id = 'SKT' + (2000000 + (++seq));
        const st = mi === 9 ? ['Processing', 'Shipped', 'Delivered'][seq % 3] : 'Delivered', iso = `${year}-${mm}-${day}T10:00:00.000Z`;
        io.run(id, u.id, u.email, u.name, '12, Gandhi Street, Chennai 600001', '9000000000', total - sub, total, cost, pays[seq % 4], st, iso, st === 'Processing' ? null : 'SKT' + (70000 + seq * 7), st === 'Processing' ? null : 'Delhivery'); evs(id, st, iso);
        items.forEach(x => ii.run(id, x.p.id, x.p.name, x.p.col, x.q, x.p.price, x.p.cost));
        sum += total;
      }
      const ym = `${year}-${mm}`;
      ie.run(ym, 'Rent', 30000); ie.run(ym, 'Salaries', 65000); ie.run(ym, 'Marketing', 12000 + R(mi, 9) * 2000); ie.run(ym, 'Other', 8000);
    });
  })();
  console.log('Database seeded: 70 products, 5 sample customers (password customer123), sample orders & expenses.');
};
