require('dotenv').config();
const express = require('express'), path = require('path'), fs = require('fs'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');
const db = require('./db');
const seed = require('./seed');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET not set, using an insecure development secret.');

const UP = path.join(__dirname, 'data', 'uploads');
fs.mkdirSync(UP, { recursive: true });

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10mb' }));
app.use((q, s, n) => {
  s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'same-origin' });
  n();
});

const err = (c, m) => Object.assign(new Error(m), { status: c });
const wrap = f => async (q, s, n) => {
  try {
    await f(q, s, n);
  } catch (e) {
    if (!e.status) console.error(e);
    s.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' });
  }
};

const sign = u => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '7d' });
const pubU = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, phone: u.phone || '', address: u.address || '' });
const ph = x => String(x || '').replace(/\D/g, '').slice(-10);

app.use('/api', async (q, s, n) => {
  const h = q.headers.authorization || '';
  if (h.startsWith('Bearer ')) {
    try {
      const decoded = jwt.verify(h.slice(7), SECRET);
      q.user = await db.get('SELECT * FROM users WHERE id=?', [decoded.id]);
    } catch (e) {}
  }
  n();
});

const need = (q, s, n) => q.user ? n() : s.status(401).json({ error: 'Please log in' });
const adm = (q, s, n) => q.user && q.user.role === 'admin' ? n() : s.status(403).json({ error: 'Admin access only' });
const tries = new Map();
const limit = (q, s, n) => {
  const k = q.ip, t = Date.now(), r = (tries.get(k) || []).filter(x => t - x < 6e5);
  if (r.length >= 15) return s.status(429).json({ error: 'Too many attempts, try again later' });
  r.push(t); tries.set(k, r); n();
};
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------- auth ----------
app.get('/api/health', (q, s) => s.json({ ok: true }));

app.post('/api/auth/register', limit, wrap(async (q, s) => {
  const name = String(q.body.name || '').trim().slice(0, 80), email = String(q.body.email || '').trim().toLowerCase(), pw = String(q.body.password || '');
  if (!name || !EMAIL.test(email)) throw err(400, 'Enter a valid name and email');
  if (pw.length < 6) throw err(400, 'Password must be at least 6 characters');
  if (await db.get('SELECT 1 FROM users WHERE email=?', [email])) throw err(409, 'An account with this email already exists');
  const res = await db.run('INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)', [name, email, bcrypt.hashSync(pw, 10), 'customer', new Date().toISOString()]);
  const u = await db.get('SELECT * FROM users WHERE id=?', [res.lastInsertRowid]);
  s.status(201).json({ token: sign(u), user: pubU(u) });
}));

app.post('/api/auth/login', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const u = await db.get('SELECT * FROM users WHERE email=?', [email]);
  if (!u || !bcrypt.compareSync(String(q.body.password || ''), u.hash)) throw err(401, 'Invalid email or password');
  if (q.body.role === 'admin' && u.role !== 'admin') throw err(403, 'This is not an admin account');
  if (q.body.role !== 'admin' && u.role === 'admin') throw err(403, 'Admin accounts must log in from the Admin tab');
  s.json({ token: sign(u), user: pubU(u) });
}));

app.get('/api/me', need, (q, s) => s.json(pubU(q.user)));

app.put('/api/me', need, wrap(async (q, s) => {
  const name = String(q.body.name ?? q.user.name).trim().slice(0, 80), phone = ph(q.body.phone ?? q.user.phone), address = String(q.body.address ?? q.user.address ?? '').trim().slice(0, 300);
  if (!name) throw err(400, 'Name is required');
  if (phone && phone.length !== 10) throw err(400, 'Phone must be 10 digits');
  await db.run('UPDATE users SET name=?,phone=?,address=? WHERE id=?', [name, phone, address, q.user.id]);
  const updated = await db.get('SELECT * FROM users WHERE id=?', [q.user.id]);
  s.json(pubU(updated));
}));

app.post('/api/me/password', need, limit, wrap(async (q, s) => {
  const n = String(q.body.new || '');
  if (!bcrypt.compareSync(String(q.body.current || ''), q.user.hash)) throw err(400, 'Current password is incorrect');
  if (n.length < 6) throw err(400, 'New password must be at least 6 characters');
  await db.run('UPDATE users SET hash=? WHERE id=?', [bcrypt.hashSync(n, 10), q.user.id]);
  s.json({ ok: true });
}));

// ---------- store settings ----------
const CFG0 = { store: 'Sreekrishna Textiles', phone: '+91 90000 00000', email: 'care@sreekrishnatextiles.demo', addr: 'Chennai, Tamil Nadu, India', ship: 99, free: 2999, low: 8 };
const getCfg = async () => {
  const c = { ...CFG0 };
  const rows = await db.all('SELECT k,v FROM settings');
  rows.forEach(r => {
    if (r.k in CFG0) c[r.k] = typeof CFG0[r.k] === 'number' ? +r.v : r.v;
  });
  return c;
};

app.get('/api/settings', wrap(async (q, s) => s.json(await getCfg())));

app.put('/api/settings', need, adm, wrap(async (q, s) => {
  await db.transaction(async (tx) => {
    for (const k of Object.keys(CFG0)) {
      if (!(k in q.body)) continue;
      let v = q.body[k];
      if (typeof CFG0[k] === 'number') {
        v = Math.round(+v);
        if (!(v >= 0 && v <= 1e6)) throw err(400, 'Invalid value for ' + k);
      } else {
        v = String(v).trim().slice(0, 200);
        if (!v) throw err(400, k + ' cannot be empty');
      }
      await tx.run('INSERT INTO settings(k,v) VALUES(?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)', [k, String(v)]);
    }
  });
  s.json(await getCfg());
}));

// ---------- products ----------
const mapP = (r, a) => ({
  id: r.id, name: r.name, cat: r.cat, sub: r.sub, price: r.price, disc: r.disc, mrp: r.mrp,
  col: r.col, fab: r.fab, rating: r.rating, rev: r.rev, stock: r.stock, sku: r.sku, occ: r.occ,
  desc: r.descr, img: r.img, ...(a ? { cost: r.cost } : {})
});
const isA = q => q.user && q.user.role === 'admin';
const mrpOf = (p, d) => Math.round(p / (1 - d / 100) / 10) * 10;

function saveImg(id, data) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(data || '');
  if (!m) throw err(400, 'Image must be a JPEG, PNG or WebP data URL');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 3e6) throw err(413, 'Image too large (max 3 MB)');
  const f = `${id}-${Date.now()}.${m[1] === 'jpeg' ? 'jpg' : m[1]}`;
  fs.writeFileSync(path.join(UP, f), buf);
  return '/uploads/' + f;
}
const rmImg = u => {
  if (u && u.startsWith('/uploads/')) fs.rm(path.join(UP, path.basename(u)), () => {});
};

app.get('/api/products', wrap(async (q, s) => {
  const rows = await db.all('SELECT * FROM products ORDER BY sort_order');
  s.json(rows.map(r => mapP(r, isA(q))));
}));

app.post('/api/products', need, adm, wrap(async (q, s) => {
  const b = q.body, name = String(b.name || '').trim(), price = Math.round(+b.price);
  if (!name || !(price > 0)) throw err(400, 'Name and a positive price are required');
  const disc = Math.min(90, Math.max(0, Math.round(+b.disc || 0)));
  const maxRow = await db.get("SELECT MAX(CAST(SUBSTRING(id, 3) AS UNSIGNED)) AS m FROM products");
  const n = (maxRow && maxRow.m ? maxRow.m : 2999) + 1;
  const id = 'SK' + n;

  await db.run(
    'INSERT INTO products(id,name,cat,sub,price,disc,mrp,cost,col,fab,rating,rev,stock,sku,occ,descr,img,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    [
      id, name.slice(0, 120), b.cat || 'Sarees', b.sub || b.cat || 'Silk', price, disc, mrpOf(price, disc),
      Math.round(+b.cost) || Math.round(price * .6), b.col || 'Pink', b.fab || 'Silk', 4.5, 0,
      Math.max(0, Math.round(+b.stock) || 0), 'SKT-' + (7000 + n), b.occ || 'Festive',
      String(b.desc || 'New arrival from Sreekrishna Textiles.').slice(0, 500),
      b.img ? saveImg(id, b.img) : null, new Date().toISOString()
    ]
  );
  const created = await db.get('SELECT * FROM products WHERE id=?', [id]);
  s.status(201).json(mapP(created, true));
}));

app.put('/api/products/:id', need, adm, wrap(async (q, s) => {
  const r = await db.get('SELECT * FROM products WHERE id=?', [q.params.id]);
  if (!r) throw err(404, 'Product not found');
  const b = q.body, n = { ...r }, int = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(+v) || 0));
  if ('name' in b) { const v = String(b.name).trim(); if (!v) throw err(400, 'Name required'); n.name = v.slice(0, 120); }
  for (const k of ['cat', 'col', 'fab', 'occ', 'sub']) if (k in b) n[k] = String(b[k]).slice(0, 60);
  if ('desc' in b) n.descr = String(b.desc).slice(0, 500);
  if ('price' in b) n.price = int(b.price, 1, 1e7);
  if ('disc' in b) n.disc = int(b.disc, 0, 90);
  if ('cost' in b) n.cost = int(b.cost, 0, 1e7);
  if ('stock' in b) n.stock = int(b.stock, 0, 1e6);
  if ('price' in b || 'disc' in b) n.mrp = mrpOf(n.price, n.disc);
  if ('img' in b) {
    if (b.img === null) { rmImg(r.img); n.img = null; }
    else if (/^data:/.test(b.img)) { n.img = saveImg(r.id, b.img); rmImg(r.img); }
  }

  await db.run(
    'UPDATE products SET name=?,cat=?,sub=?,price=?,disc=?,mrp=?,cost=?,col=?,fab=?,stock=?,occ=?,descr=?,img=? WHERE id=?',
    [n.name, n.cat, n.sub, n.price, n.disc, n.mrp, n.cost, n.col, n.fab, n.stock, n.occ, n.descr, n.img, r.id]
  );
  const updated = await db.get('SELECT * FROM products WHERE id=?', [r.id]);
  s.json(mapP(updated, true));
}));

app.delete('/api/products/:id', need, adm, wrap(async (q, s) => {
  const r = await db.get('SELECT img FROM products WHERE id=?', [q.params.id]);
  if (!r) throw err(404, 'Product not found');
  await db.run('DELETE FROM products WHERE id=?', [q.params.id]);
  rmImg(r.img);
  s.json({ ok: true });
}));

// ---------- orders ----------
const STS = ['Processing', 'Shipped', 'Out for Delivery', 'Delivered', 'Cancelled'];
const DN = {
  Processing: 'Order is being processed',
  Shipped: 'Your order has been shipped',
  'Out for Delivery': 'Out for delivery today',
  Delivered: 'Delivered successfully',
  Cancelled: 'Order cancelled'
};

const mapO = async (o, a) => {
  const items = await db.all('SELECT product_id id,col,qty q,name,price FROM order_items WHERE order_id=?', [o.id]);
  const ev = await db.all('SELECT status s,note,created t FROM order_events WHERE order_id=? ORDER BY id', [o.id]);
  return {
    id: o.id, by: o.email, name: o.name, phone: o.phone || '', address: o.address || '',
    ship: o.ship || 0, total: o.total, pay: o.pay, status: o.status,
    tracking: o.tracking || '', courier: o.courier || '', eta: o.eta || '',
    iso: o.created, date: new Date(o.created).toLocaleDateString('en-IN'),
    ...(a ? { cost: o.cost } : {}),
    items, ev
  };
};

const addEv = async (id, st, note, runner = db) => {
  await runner.run(
    'INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)',
    [id, st, String(note || DN[st]).slice(0, 200), new Date().toISOString()]
  );
};

async function changeStatus(o, st, f) {
  await db.transaction(async (tx) => {
    const its = await tx.all('SELECT product_id,qty FROM order_items WHERE order_id=?', [o.id]);
    if (st === 'Cancelled' && o.status !== 'Cancelled') {
      for (const i of its) {
        await tx.run('UPDATE products SET stock=stock+? WHERE id=?', [i.qty, i.product_id]);
      }
    }
    if (o.status === 'Cancelled' && st !== 'Cancelled') {
      for (const i of its) {
        const res = await tx.run('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?', [i.qty, i.product_id, i.qty]);
        if (!res.changes) throw err(409, 'Not enough stock to re-open this order');
      }
    }
    const t = x => (x === undefined || x === null) ? null : String(x).slice(0, 80);
    await tx.run('UPDATE orders SET status=?,tracking=COALESCE(?,tracking),courier=COALESCE(?,courier),eta=COALESCE(?,eta) WHERE id=?', [st, t(f.tracking), t(f.courier), t(f.eta), o.id]);
    await addEv(o.id, st, f.note, tx);
  });
}

app.post('/api/orders', wrap(async (q, s) => {
  const items = Array.isArray(q.body.items) ? q.body.items : [];
  if (!items.length || items.length > 50) throw err(400, 'Cart is empty');
  const pay = ['UPI', 'Credit Card', 'Debit Card', 'Net Banking', 'Cash on Delivery'].includes(q.body.pay) ? q.body.pay : 'UPI';
  const name = String(q.body.name || (q.user && q.user.name) || '').trim().slice(0, 80);
  const address = String(q.body.address || '').trim().slice(0, 300);
  const phone = ph(q.body.phone || (q.user && q.user.phone));
  if (!name || !address) throw err(400, 'Name and address are required');
  if (phone.length !== 10) throw err(400, 'Enter a valid 10-digit phone number');

  const cfg = await getCfg();
  const id = await db.transaction(async (tx) => {
    let sub = 0, cost = 0; const lines = [];
    for (const it of items) {
      const qty = Math.round(+it.q);
      if (!(qty >= 1 && qty <= 20)) throw err(400, 'Invalid quantity');
      const p = await tx.get('SELECT * FROM products WHERE id=?', [String(it.id)]);
      if (!p) throw err(404, 'A product in your cart no longer exists');
      const res = await tx.run('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?', [qty, p.id, qty]);
      if (!res.changes) throw err(409, p.stock > 0 ? `Only ${p.stock} of "${p.name}" available` : `"${p.name}" is out of stock`);
      sub += p.price * qty; cost += p.cost * qty;
      lines.push({ p, qty, col: String(it.col || p.col) });
    }
    const ship = sub < cfg.free ? cfg.ship : 0;
    const oid = 'SKT' + Date.now().toString().slice(-7) + Math.floor(Math.random() * 90 + 10);
    await tx.run(
      'INSERT INTO orders(id,user_id,email,name,address,phone,ship,total,cost,pay,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
      [oid, q.user ? q.user.id : null, q.user ? q.user.email : String(q.body.email || 'guest').slice(0, 120), name, address, phone, ship, sub + ship, cost, pay, 'Processing', new Date().toISOString()]
    );
    for (const l of lines) {
      await tx.run(
        'INSERT INTO order_items(order_id,product_id,name,col,qty,price,cost) VALUES(?,?,?,?,?,?,?)',
        [oid, l.p.id, l.p.name, l.col, l.qty, l.p.price, l.p.cost]
      );
    }
    await addEv(oid, 'Processing', 'Order placed', tx);
    return oid;
  });

  const created = await db.get('SELECT * FROM orders WHERE id=?', [id]);
  s.status(201).json(await mapO(created, isA(q)));
}));

app.get('/api/orders', need, wrap(async (q, s) => {
  const rows = isA(q)
    ? await db.all('SELECT * FROM orders ORDER BY created DESC')
    : await db.all('SELECT * FROM orders WHERE user_id=? ORDER BY created DESC', [q.user.id]);
  const orders = await Promise.all(rows.map(o => mapO(o, isA(q))));
  s.json(orders);
}));

app.get('/api/orders/:id', need, wrap(async (q, s) => {
  const o = await db.get('SELECT * FROM orders WHERE id=?', [q.params.id]);
  if (!o || !(isA(q) || o.user_id === q.user.id)) throw err(404, 'Order not found');
  s.json(await mapO(o, isA(q)));
}));

app.get('/api/track', limit, wrap(async (q, s) => {
  const o = await db.get('SELECT * FROM orders WHERE id=?', [String(q.query.id || '').toUpperCase()]);
  if (!o || !o.phone || o.phone !== ph(q.query.phone)) throw err(404, 'No order found for these details');
  s.json(await mapO(o, false));
}));

app.post('/api/orders/:id/cancel', need, wrap(async (q, s) => {
  const o = await db.get('SELECT * FROM orders WHERE id=?', [q.params.id]);
  if (!o || o.user_id !== q.user.id) throw err(404, 'Order not found');
  if (o.status !== 'Processing') throw err(409, 'This order can no longer be cancelled. Please contact support.');
  await changeStatus(o, 'Cancelled', { note: 'Cancelled by customer' });
  const updated = await db.get('SELECT * FROM orders WHERE id=?', [o.id]);
  s.json(await mapO(updated, false));
}));

app.patch('/api/orders/:id/status', need, adm, wrap(async (q, s) => {
  const st = q.body.status, o = await db.get('SELECT * FROM orders WHERE id=?', [q.params.id]);
  if (!o) throw err(404, 'Order not found');
  if (!STS.includes(st)) throw err(400, 'Invalid status');
  await changeStatus(o, st, q.body);
  const updated = await db.get('SELECT * FROM orders WHERE id=?', [o.id]);
  s.json(await mapO(updated, true));
}));

// ---------- admin analytics ----------
const MN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
app.get('/api/admin/dashboard', need, adm, wrap(async (q, s) => {
  const maxYearRow = await db.get('SELECT MAX(SUBSTRING(created,1,4)) AS y FROM orders');
  const y = String(q.query.year || (maxYearRow && maxYearRow.y) || new Date().getFullYear());
  const o = await db.all("SELECT SUBSTRING(created,1,7) AS ym, CAST(SUM(total) AS SIGNED) AS s, CAST(SUM(cost) AS SIGNED) AS c, COUNT(*) AS n FROM orders WHERE status!='Cancelled' AND SUBSTRING(created,1,4)=? GROUP BY ym", [y]);
  const e = await db.all('SELECT month AS ym, kind, CAST(SUM(amount) AS SIGNED) AS a FROM expenses WHERE SUBSTRING(month,1,4)=? GROUP BY month, kind', [y]);
  const last = Math.max(1, ...o.map(r => +r.ym.slice(5)), ...e.map(r => +r.ym.slice(5))), months = [];

  for (let i = 1; i <= last; i++) {
    const ym = `${y}-${String(i).padStart(2, '0')}`;
    const r = o.find(x => x.ym === ym) || { s: 0, c: 0, n: 0 };
    const sales = +r.s || 0, cogs = +r.c || 0, ordersCount = +r.n || 0;
    const ex = { Rent: 0, Salaries: 0, Marketing: 0, Other: 0 };
    e.filter(x => x.ym === ym).forEach(x => ex[x.kind] = (ex[x.kind] || 0) + (+x.a || 0));
    ex.Shipping = Math.round(sales * .03);
    const te = Object.values(ex).reduce((a, b) => a + b, 0);
    months.push({ m: MN[i - 1], sales, cogs, gp: sales - cogs, exp: ex, te, net: sales - cogs - te, orders: ordersCount });
  }

  const cr = await db.all("SELECT p.cat AS n, CAST(SUM(i.qty * i.price) AS SIGNED) AS v FROM order_items i JOIN orders o ON o.id=i.order_id JOIN products p ON p.id=i.product_id WHERE o.status!='Cancelled' AND SUBSTRING(o.created,1,4)=? GROUP BY p.cat ORDER BY v DESC", [y]);
  const tot = cr.reduce((a, r) => a + (+r.v || 0), 0) || 1;
  const top = await db.all("SELECT i.name, CAST(SUM(i.qty) AS SIGNED) AS units, COALESCE(p.stock, 0) AS stock FROM order_items i JOIN orders o ON o.id=i.order_id LEFT JOIN products p ON p.id=i.product_id WHERE o.status!='Cancelled' AND SUBSTRING(o.created,1,4)=? GROUP BY i.product_id, i.name, p.stock ORDER BY units DESC LIMIT 5", [y]);

  s.json({ year: y, months, cats: cr.map(r => ({ n: r.n, v: (+r.v || 0) / tot })), top: top.map(t => ({ name: t.name, units: +t.units || 0, stock: +t.stock || 0 })) });
}));

app.get('/api/admin/customers', need, adm, wrap(async (q, s) => {
  const rows = await db.all("SELECT u.name, u.email, COUNT(o.id) AS orders, COALESCE(SUM(o.total), 0) AS spent FROM users u LEFT JOIN orders o ON o.user_id=u.id AND o.status!='Cancelled' WHERE u.role='customer' GROUP BY u.id, u.name, u.email ORDER BY spent DESC");
  s.json(rows.map(r => ({ name: r.name, email: r.email, orders: +r.orders || 0, spent: +r.spent || 0 })));
}));

app.get('/api/admin/expenses', need, adm, wrap(async (q, s) => {
  const rows = await db.all('SELECT * FROM expenses ORDER BY month DESC, id DESC LIMIT 200');
  s.json(rows);
}));

app.post('/api/admin/expenses', need, adm, wrap(async (q, s) => {
  const m = String(q.body.month || ''), k = String(q.body.kind || ''), a = Math.round(+q.body.amount);
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(m) || !['Rent', 'Salaries', 'Marketing', 'Other'].includes(k) || !(a > 0)) throw err(400, 'Enter a month (YYYY-MM), type and positive amount');
  await db.run('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)', [m, k, a]);
  s.status(201).json({ ok: true });
}));

app.use('/api', (q, s) => s.status(404).json({ error: 'Not found' }));
app.use('/uploads', express.static(UP, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public')));

async function startServer() {
  try {
    await db.init();
    await seed(db);
    app.listen(PORT, () => console.log(`Sreekrishna Textiles running at http://localhost:${PORT}`));
  } catch (e) {
    if (e.code === 'ECONNREFUSED') {
      console.error(`\n[Database Connection Error] Could not connect to MySQL server at ${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 3306}.`);
      console.error('Please verify that your MySQL service is running and credentials in .env are correct.\n');
    } else if (e.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error(`\n[Database Authentication Error] MySQL Access Denied for user '${process.env.DB_USER || 'root'}'.`);
      console.error('Please verify DB_USER and DB_PASSWORD in your .env file.\n');
    } else {
      console.error('\n[Server Startup Error]', e.message || e);
    }
    process.exit(1);
  }
}

startServer();
