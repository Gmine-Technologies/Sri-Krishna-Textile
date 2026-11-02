// Seeds products, demo customers, historical orders and expenses on first run.
const bcrypt = require('bcryptjs');
const R = (i, m) => (i * 7919 + 13) % m;
const CK = ['Pink', 'Red', 'Green', 'Blue', 'Purple', 'Gold', 'Maroon', 'Black', 'Yellow'];
const SF = [
  ['Kanchipuram Silk', 'Kanchipuram'],
  ['Banarasi Gold Zari Silk', 'Banarasi'],
  ['Designer Silk', 'Designer'],
  ['Wedding Silk', 'Wedding'],
  ['Tissue Silk', 'Silk'],
  ['Pure Cotton', 'Cotton'],
  ['Bridal Kanchipuram', 'Wedding'],
  ['Party Wear Georgette', 'Party Wear']
];

module.exports = async function seed(db) {
  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@sreekrishna.demo').toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';

  const admin = await db.get("SELECT 1 FROM users WHERE role='admin'");
  if (!admin) {
    await db.run(
      'INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)',
      ['Admin', adminEmail, bcrypt.hashSync(adminPass, 10), 'admin', new Date().toISOString()]
    );
    if (adminPass === 'admin123') {
      console.warn('WARNING: default admin password in use. Set ADMIN_PASSWORD before deploying.');
    }
  }

  const prodCount = await db.get('SELECT COUNT(*) AS n FROM products');
  if (prodCount && prodCount.n > 0) return;

  const P = [];
  const add = (cat, sub, names, n, base, fab) => {
    for (let i = 0; i < n; i++) {
      const k = P.length, c = CK[(k * 5 + i) % 9], f = fab ? fab[i % fab.length] : null;
      const [fn, sb] = cat === 'Sarees' ? SF[i % 8] : [f, sub];
      const d = [10, 15, 20, 25, 30, 35, 40][R(k, 7)], pr = Math.round((base + R(k, 3600)) / 10) * 10 - 1, num = 1000 + k;
      P.push({
        id: 'SK' + num,
        name: cat === 'Sarees' ? `${c === 'Pink' ? 'Royal Magenta' : c} ${fn} Saree` : `${c} ${names[i % names.length]}`,
        cat,
        sub: sb,
        price: pr,
        disc: d,
        mrp: Math.round(pr / (1 - d / 100) / 10) * 10,
        cost: Math.round(pr * (.52 + R(num, 12) / 100)),
        col: c,
        fab: fn,
        rating: +(3.9 + R(k, 12) / 10).toFixed(1),
        rev: 20 + R(k, 300),
        stock: R(k, 40),
        sku: 'SKT-' + (5000 + k * 13),
        occ: ['Wedding', 'Festive', 'Party', 'Daily'][R(k, 4)],
        desc: `A ${fn.toLowerCase()} piece in ${c.toLowerCase()} with fine craftsmanship from heritage looms.`
      });
    }
  };

  add('Sarees', '', [], 30, 2800);
  add('Lehengas', 'Lehenga', ['Bridal Lehenga', 'Silk Lehenga', 'Designer Lehenga', 'Festive Lehenga'], 10, 8000, ['Silk', 'Net', 'Velvet']);
  add('Kurtis', 'Kurti', ['Cotton Kurti', 'Anarkali Kurti', 'Straight Kurti', 'Embroidered Kurti'], 10, 899, ['Cotton', 'Rayon']);
  add('Suits & Dress Materials', 'Suit', ['Unstitched Suit', 'Dress Material', 'Salwar Set'], 10, 1599, ['Cotton', 'Chanderi']);
  add('Home Decor', 'Decor', ['Silk Cushion Cover', 'Brass Diya Set', 'Table Runner', 'Curtain Pair', 'Bedsheet Set'], 10, 599, ['Silk', 'Brass', 'Cotton']);

  const now = new Date().toISOString();

  // demo customers + sample history
  const cust = [
    ['Priya Nair', 'priya@example.com'],
    ['Lakshmi Devi', 'lakshmi@example.com'],
    ['Anita Rao', 'anita@example.com'],
    ['Meena S', 'meena@example.com'],
    ['Divya K', 'divya@example.com']
  ];
  const h = bcrypt.hashSync('customer123', 10);
  const later = (iso, d) => new Date(Date.parse(iso) + d * 864e5).toISOString();

  const BASE = [205000, 265000, 355000, 430000, 395000, 285000, 240000, 490000, 640000, 310000];
  const year = 2026, pays = ['UPI', 'Credit Card', 'Cash on Delivery', 'Net Banking'];

  await db.transaction(async (tx) => {
    for (const p of P) {
      await tx.run(
        'INSERT INTO products(id,name,cat,sub,price,disc,mrp,cost,col,fab,rating,rev,stock,sku,occ,descr,img,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?)',
        [p.id, p.name, p.cat, p.sub, p.price, p.disc, p.mrp, p.cost, p.col, p.fab, p.rating, p.rev, p.stock, p.sku, p.occ, p.desc, now]
      );
    }

    const users = [];
    for (const [n, e] of cust) {
      await tx.run(
        'INSERT IGNORE INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)',
        [n, e, h, 'customer', now]
      );
      const u = await tx.get('SELECT id,name,email FROM users WHERE email=?', [e]);
      users.push(u);
    }

    const evs = async (id, st, iso) => {
      await tx.run('INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)', [id, 'Processing', 'Order placed', iso]);
      if (st !== 'Processing') {
        await tx.run('INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)', [id, 'Shipped', 'Packed and handed to courier', later(iso, 1)]);
      }
      if (st === 'Delivered') {
        await tx.run('INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)', [id, 'Out for Delivery', 'Out for delivery today', later(iso, 3)]);
        await tx.run('INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)', [id, 'Delivered', 'Delivered successfully', later(iso, 3.3)]);
      }
    };

    let seq = 0, rnd = 12345;
    const rand = () => (rnd = (rnd * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;

    for (let mi = 0; mi < BASE.length; mi++) {
      const target = BASE[mi];
      let sum = 0;
      const mm = String(mi + 1).padStart(2, '0');

      while (sum < target) {
        const u = users[seq % users.length];
        const lines = 1 + (rand() < .35 ? 1 : 0);
        const items = [];
        for (let l = 0; l < lines; l++) {
          const p = P[Math.floor(rand() * (rand() < .65 ? 30 : P.length))];
          items.push({ p, q: 1 + (rand() < .25 ? 1 : 0) });
        }
        const sub = items.reduce((a, x) => a + x.p.price * x.q, 0);
        const total = sub + (sub < 2999 ? 99 : 0);
        const cost = items.reduce((a, x) => a + x.p.cost * x.q, 0);
        const day = String(1 + Math.floor(rand() * (mi === 9 ? 5 : 27))).padStart(2, '0');
        const id = 'SKT' + (2000000 + (++seq));
        const st = mi === 9 ? ['Processing', 'Shipped', 'Delivered'][seq % 3] : 'Delivered';
        const iso = `${year}-${mm}-${day}T10:00:00.000Z`;

        await tx.run(
          'INSERT INTO orders(id,user_id,email,name,address,phone,ship,total,cost,pay,status,created,tracking,courier) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
          [
            id, u.id, u.email, u.name, '12, Gandhi Street, Chennai 600001', '9000000000',
            total - sub, total, cost, pays[seq % 4], st, iso,
            st === 'Processing' ? null : 'SKT' + (70000 + seq * 7),
            st === 'Processing' ? null : 'Delhivery'
          ]
        );

        await evs(id, st, iso);

        for (const x of items) {
          await tx.run(
            'INSERT INTO order_items(order_id,product_id,name,col,qty,price,cost) VALUES(?,?,?,?,?,?,?)',
            [id, x.p.id, x.p.name, x.p.col, x.q, x.p.price, x.p.cost]
          );
        }

        sum += total;
      }

      const ym = `${year}-${mm}`;
      await tx.run('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)', [ym, 'Rent', 30000]);
      await tx.run('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)', [ym, 'Salaries', 65000]);
      await tx.run('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)', [ym, 'Marketing', 12000 + R(mi, 9) * 2000]);
      await tx.run('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)', [ym, 'Other', 8000]);
    }
  });

  console.log('Database seeded: 70 products, 5 sample customers (password customer123), sample orders & expenses.');
};
