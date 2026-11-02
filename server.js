const express = require('express'), path = require('path'), fs = require('fs'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');
const db = require('./db'); require('./seed')(db);
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET not set, using an insecure development secret.');
const UP = path.join(__dirname, 'data', 'uploads'); fs.mkdirSync(UP, { recursive: true });
const app = express(); app.disable('x-powered-by'); app.use(express.json({ limit: '10mb' }));
app.use((q, s, n) => { s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'same-origin' }); n(); });
const err = (c, m) => Object.assign(new Error(m), { status: c });
const wrap = f => (q, s, n) => { try { f(q, s, n); } catch (e) { if (!e.status) console.error(e); s.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' }); } };
const sign = u => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '7d' });
const pubU = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, phone: u.phone || '', address: u.address || '' });
const ph = x => String(x || '').replace(/\D/g, '').slice(-10);
app.use('/api', (q, s, n) => { const h = q.headers.authorization || ''; if (h.startsWith('Bearer ')) { try { q.user = db.prepare('SELECT * FROM users WHERE id=?').get(jwt.verify(h.slice(7), SECRET).id); } catch (e) { } } n(); });
const need = (q, s, n) => q.user ? n() : s.status(401).json({ error: 'Please log in' });
const adm = (q, s, n) => q.user && q.user.role === 'admin' ? n() : s.status(403).json({ error: 'Admin access only' });
const tries = new Map();
const limit = (q, s, n) => { const k = q.ip, t = Date.now(), r = (tries.get(k) || []).filter(x => t - x < 6e5); if (r.length >= 15) return s.status(429).json({ error: 'Too many attempts, try again later' }); r.push(t); tries.set(k, r); n(); };
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// ---------- auth ----------
app.get('/api/health', (q, s) => s.json({ ok: true }));
app.post('/api/auth/register', limit, wrap((q, s) => {
  const name = String(q.body.name || '').trim().slice(0, 80), email = String(q.body.email || '').trim().toLowerCase(), pw = String(q.body.password || '');
  if (!name || !EMAIL.test(email)) throw err(400, 'Enter a valid name and email'); if (pw.length < 6) throw err(400, 'Password must be at least 6 characters');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw err(409, 'An account with this email already exists');
  const id = db.prepare('INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)').run(name, email, bcrypt.hashSync(pw, 10), 'customer', new Date().toISOString()).lastInsertRowid;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(id); s.status(201).json({ token: sign(u), user: pubU(u) });
}));
app.post('/api/auth/login', limit, wrap((q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase(), u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(String(q.body.password || ''), u.hash)) throw err(401, 'Invalid email or password');
  if (q.body.role === 'admin' && u.role !== 'admin') throw err(403, 'This is not an admin account');
  if (q.body.role !== 'admin' && u.role === 'admin') throw err(403, 'Admin accounts must log in from the Admin tab');
  s.json({ token: sign(u), user: pubU(u) });
}));
app.get('/api/me', need, (q, s) => s.json(pubU(q.user)));
app.put('/api/me', need, wrap((q, s) => {
  const name = String(q.body.name ?? q.user.name).trim().slice(0, 80), phone = ph(q.body.phone ?? q.user.phone), address = String(q.body.address ?? q.user.address ?? '').trim().slice(0, 300);
  if (!name) throw err(400, 'Name is required'); if (phone && phone.length !== 10) throw err(400, 'Phone must be 10 digits');
  db.prepare('UPDATE users SET name=?,phone=?,address=? WHERE id=?').run(name, phone, address, q.user.id); s.json(pubU(db.prepare('SELECT * FROM users WHERE id=?').get(q.user.id)));
}));
app.post('/api/me/password', need, limit, wrap((q, s) => {
  const n = String(q.body.new || ''); if (!bcrypt.compareSync(String(q.body.current || ''), q.user.hash)) throw err(400, 'Current password is incorrect');
  if (n.length < 6) throw err(400, 'New password must be at least 6 characters'); db.prepare('UPDATE users SET hash=? WHERE id=?').run(bcrypt.hashSync(n, 10), q.user.id); s.json({ ok: true });
}));
// ---------- store settings ----------
const CFG0 = { store: 'Sreekrishna Textiles', phone: '+91 90000 00000', email: 'care@sreekrishnatextiles.demo', addr: 'Chennai, Tamil Nadu, India', ship: 99, free: 2999, low: 8 };
const getCfg = () => { const c = { ...CFG0 }; db.prepare('SELECT k,v FROM settings').all().forEach(r => { if (r.k in CFG0) c[r.k] = typeof CFG0[r.k] === 'number' ? +r.v : r.v; }); return c; };
app.get('/api/settings', (q, s) => s.json(getCfg()));
app.put('/api/settings', need, adm, wrap((q, s) => {
  const up = db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v');
  db.transaction(() => { for (const k of Object.keys(CFG0)) { if (!(k in q.body)) continue; let v = q.body[k];
    if (typeof CFG0[k] === 'number') { v = Math.round(+v); if (!(v >= 0 && v <= 1e6)) throw err(400, 'Invalid value for ' + k); } else { v = String(v).trim().slice(0, 200); if (!v) throw err(400, k + ' cannot be empty'); }
    up.run(k, String(v)); } })();
  s.json(getCfg());
}));
// ---------- products ----------
const mapP = (r, a) => ({ id: r.id, name: r.name, cat: r.cat, sub: r.sub, price: r.price, disc: r.disc, mrp: r.mrp, col: r.col, fab: r.fab, rating: r.rating, rev: r.rev, stock: r.stock, sku: r.sku, occ: r.occ, desc: r.descr, img: r.img, ...(a ? { cost: r.cost } : {}) });
const isA = q => q.user && q.user.role === 'admin';
const mrpOf = (p, d) => Math.round(p / (1 - d / 100) / 10) * 10;
function saveImg(id, data) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(data || ''); if (!m) throw err(400, 'Image must be a JPEG, PNG or WebP data URL');
  const buf = Buffer.from(m[2], 'base64'); if (buf.length > 3e6) throw err(413, 'Image too large (max 3 MB)');
  const f = `${id}-${Date.now()}.${m[1] === 'jpeg' ? 'jpg' : m[1]}`; fs.writeFileSync(path.join(UP, f), buf); return '/uploads/' + f;
}
const rmImg = u => { if (u && u.startsWith('/uploads/')) fs.rm(path.join(UP, path.basename(u)), () => { }); };
app.get('/api/products', wrap((q, s) => s.json(db.prepare('SELECT * FROM products ORDER BY rowid').all().map(r => mapP(r, isA(q))))));
app.post('/api/products', need, adm, wrap((q, s) => {
  const b = q.body, name = String(b.name || '').trim(), price = Math.round(+b.price); if (!name || !(price > 0)) throw err(400, 'Name and a positive price are required');
  const disc = Math.min(90, Math.max(0, Math.round(+b.disc || 0))), n = (db.prepare("SELECT MAX(CAST(substr(id,3) AS INTEGER)) m FROM products").get().m || 2999) + 1, id = 'SK' + n;
  db.prepare('INSERT INTO products(id,name,cat,sub,price,disc,mrp,cost,col,fab,rating,rev,stock,sku,occ,descr,img,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(id, name.slice(0, 120), b.cat || 'Sarees', b.sub || b.cat || 'Silk', price, disc, mrpOf(price, disc), Math.round(+b.cost) || Math.round(price * .6), b.col || 'Pink', b.fab || 'Silk', 4.5, 0, Math.max(0, Math.round(+b.stock) || 0), 'SKT-' + (7000 + n), b.occ || 'Festive', String(b.desc || 'New arrival from Sreekrishna Textiles.').slice(0, 500), b.img ? saveImg(id, b.img) : null, new Date().toISOString());
  s.status(201).json(mapP(db.prepare('SELECT * FROM products WHERE id=?').get(id), true));
}));
app.put('/api/products/:id', need, adm, wrap((q, s) => {
  const r = db.prepare('SELECT * FROM products WHERE id=?').get(q.params.id); if (!r) throw err(404, 'Product not found');
  const b = q.body, n = { ...r }, int = (v, lo, hi) => Math.min(hi, Math.max(lo, Math.round(+v) || 0));
  if ('name' in b) { const v = String(b.name).trim(); if (!v) throw err(400, 'Name required'); n.name = v.slice(0, 120); }
  for (const k of ['cat', 'col', 'fab', 'occ', 'sub']) if (k in b) n[k] = String(b[k]).slice(0, 60);
  if ('desc' in b) n.descr = String(b.desc).slice(0, 500);
  if ('price' in b) n.price = int(b.price, 1, 1e7); if ('disc' in b) n.disc = int(b.disc, 0, 90);
  if ('cost' in b) n.cost = int(b.cost, 0, 1e7); if ('stock' in b) n.stock = int(b.stock, 0, 1e6);
  if ('price' in b || 'disc' in b) n.mrp = mrpOf(n.price, n.disc);
  if ('img' in b) { if (b.img === null) { rmImg(r.img); n.img = null; } else if (/^data:/.test(b.img)) { n.img = saveImg(r.id, b.img); rmImg(r.img); } }
  db.prepare('UPDATE products SET name=?,cat=?,sub=?,price=?,disc=?,mrp=?,cost=?,col=?,fab=?,stock=?,occ=?,descr=?,img=? WHERE id=?').run(n.name, n.cat, n.sub, n.price, n.disc, n.mrp, n.cost, n.col, n.fab, n.stock, n.occ, n.descr, n.img, r.id);
  s.json(mapP(db.prepare('SELECT * FROM products WHERE id=?').get(r.id), true));
}));
app.delete('/api/products/:id', need, adm, wrap((q, s) => {
  const r = db.prepare('SELECT img FROM products WHERE id=?').get(q.params.id); if (!r) throw err(404, 'Product not found');
  db.prepare('DELETE FROM products WHERE id=?').run(q.params.id); rmImg(r.img); s.json({ ok: true });
}));
// ---------- orders ----------
const STS = ['Processing', 'Shipped', 'Out for Delivery', 'Delivered', 'Cancelled'];
const DN = { Processing: 'Order is being processed', Shipped: 'Your order has been shipped', 'Out for Delivery': 'Out for delivery today', Delivered: 'Delivered successfully', Cancelled: 'Order cancelled' };
const mapO = (o, a) => ({ id: o.id, by: o.email, name: o.name, phone: o.phone || '', address: o.address || '', ship: o.ship || 0, total: o.total, pay: o.pay, status: o.status, tracking: o.tracking || '', courier: o.courier || '', eta: o.eta || '', iso: o.created, date: new Date(o.created).toLocaleDateString('en-IN'), ...(a ? { cost: o.cost } : {}),
  items: db.prepare('SELECT product_id id,col,qty q,name,price FROM order_items WHERE order_id=?').all(o.id), ev: db.prepare('SELECT status s,note,created t FROM order_events WHERE order_id=? ORDER BY id').all(o.id) });
const addEv = (id, st, note) => db.prepare('INSERT INTO order_events(order_id,status,note,created) VALUES(?,?,?,?)').run(id, st, String(note || DN[st]).slice(0, 200), new Date().toISOString());
function changeStatus(o, st, f) {
  db.transaction(() => {
    const its = db.prepare('SELECT product_id,qty FROM order_items WHERE order_id=?').all(o.id);
    if (st === 'Cancelled' && o.status !== 'Cancelled') its.forEach(i => db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.qty, i.product_id));
    if (o.status === 'Cancelled' && st !== 'Cancelled') its.forEach(i => { if (!db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(i.qty, i.product_id, i.qty).changes) throw err(409, 'Not enough stock to re-open this order'); });
    const t = x => (x === undefined || x === null) ? null : String(x).slice(0, 80);
    db.prepare('UPDATE orders SET status=?,tracking=COALESCE(?,tracking),courier=COALESCE(?,courier),eta=COALESCE(?,eta) WHERE id=?').run(st, t(f.tracking), t(f.courier), t(f.eta), o.id);
    addEv(o.id, st, f.note);
  })();
}
app.post('/api/orders', wrap((q, s) => {
  const items = Array.isArray(q.body.items) ? q.body.items : []; if (!items.length || items.length > 50) throw err(400, 'Cart is empty');
  const pay = ['UPI', 'Credit Card', 'Debit Card', 'Net Banking', 'Cash on Delivery'].includes(q.body.pay) ? q.body.pay : 'UPI';
  const name = String(q.body.name || (q.user && q.user.name) || '').trim().slice(0, 80), address = String(q.body.address || '').trim().slice(0, 300), phone = ph(q.body.phone || (q.user && q.user.phone));
  if (!name || !address) throw err(400, 'Name and address are required'); if (phone.length !== 10) throw err(400, 'Enter a valid 10-digit phone number');
  const cfg = getCfg();
  const id = db.transaction(() => {
    let sub = 0, cost = 0; const lines = [];
    for (const it of items) {
      const qty = Math.round(+it.q); if (!(qty >= 1 && qty <= 20)) throw err(400, 'Invalid quantity');
      const p = db.prepare('SELECT * FROM products WHERE id=?').get(String(it.id)); if (!p) throw err(404, 'A product in your cart no longer exists');
      if (!db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(qty, p.id, qty).changes) throw err(409, p.stock > 0 ? `Only ${p.stock} of "${p.name}" available` : `"${p.name}" is out of stock`);
      sub += p.price * qty; cost += p.cost * qty; lines.push({ p, qty, col: String(it.col || p.col) });
    }
    const ship = sub < cfg.free ? cfg.ship : 0, oid = 'SKT' + Date.now().toString().slice(-7) + Math.floor(Math.random() * 90 + 10);
    db.prepare('INSERT INTO orders(id,user_id,email,name,address,phone,ship,total,cost,pay,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(oid, q.user ? q.user.id : null, q.user ? q.user.email : String(q.body.email || 'guest').slice(0, 120), name, address, phone, ship, sub + ship, cost, pay, 'Processing', new Date().toISOString());
    lines.forEach(l => db.prepare('INSERT INTO order_items(order_id,product_id,name,col,qty,price,cost) VALUES(?,?,?,?,?,?,?)').run(oid, l.p.id, l.p.name, l.col, l.qty, l.p.price, l.p.cost));
    addEv(oid, 'Processing', 'Order placed'); return oid;
  })();
  s.status(201).json(mapO(db.prepare('SELECT * FROM orders WHERE id=?').get(id), isA(q)));
}));
app.get('/api/orders', need, wrap((q, s) => {
  const rows = isA(q) ? db.prepare('SELECT * FROM orders ORDER BY created DESC').all() : db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY created DESC').all(q.user.id);
  s.json(rows.map(o => mapO(o, isA(q))));
}));
app.get('/api/orders/:id', need, wrap((q, s) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(q.params.id); if (!o || !(isA(q) || o.user_id === q.user.id)) throw err(404, 'Order not found'); s.json(mapO(o, isA(q)));
}));
app.get('/api/track', limit, wrap((q, s) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(String(q.query.id || '').toUpperCase());
  if (!o || !o.phone || o.phone !== ph(q.query.phone)) throw err(404, 'No order found for these details'); s.json(mapO(o, false));
}));
app.post('/api/orders/:id/cancel', need, wrap((q, s) => {
  const o = db.prepare('SELECT * FROM orders WHERE id=?').get(q.params.id); if (!o || o.user_id !== q.user.id) throw err(404, 'Order not found');
  if (o.status !== 'Processing') throw err(409, 'This order can no longer be cancelled. Please contact support.');
  changeStatus(o, 'Cancelled', { note: 'Cancelled by customer' }); s.json(mapO(db.prepare('SELECT * FROM orders WHERE id=?').get(o.id), false));
}));
app.patch('/api/orders/:id/status', need, adm, wrap((q, s) => {
  const st = q.body.status, o = db.prepare('SELECT * FROM orders WHERE id=?').get(q.params.id); if (!o) throw err(404, 'Order not found');
  if (!STS.includes(st)) throw err(400, 'Invalid status');
  changeStatus(o, st, q.body); s.json(mapO(db.prepare('SELECT * FROM orders WHERE id=?').get(o.id), true));
}));
// ---------- admin analytics ----------
const MN = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
app.get('/api/admin/dashboard', need, adm, wrap((q, s) => {
  const y = String(q.query.year || db.prepare('SELECT MAX(substr(created,1,4)) y FROM orders').get().y || new Date().getFullYear());
  const o = db.prepare("SELECT substr(created,1,7) ym,SUM(total) s,SUM(cost) c,COUNT(*) n FROM orders WHERE status!='Cancelled' AND substr(created,1,4)=? GROUP BY ym").all(y);
  const e = db.prepare('SELECT month ym,kind,SUM(amount) a FROM expenses WHERE substr(month,1,4)=? GROUP BY month,kind').all(y);
  const last = Math.max(1, ...o.map(r => +r.ym.slice(5)), ...e.map(r => +r.ym.slice(5))), months = [];
  for (let i = 1; i <= last; i++) {
    const ym = `${y}-${String(i).padStart(2, '0')}`, r = o.find(x => x.ym === ym) || { s: 0, c: 0, n: 0 }, ex = { Rent: 0, Salaries: 0, Marketing: 0, Other: 0 };
    e.filter(x => x.ym === ym).forEach(x => ex[x.kind] = (ex[x.kind] || 0) + x.a); ex.Shipping = Math.round(r.s * .03);
    const te = Object.values(ex).reduce((a, b) => a + b, 0); months.push({ m: MN[i - 1], sales: r.s, cogs: r.c, gp: r.s - r.c, exp: ex, te, net: r.s - r.c - te, orders: r.n });
  }
  const cr = db.prepare("SELECT p.cat n,SUM(i.qty*i.price) v FROM order_items i JOIN orders o ON o.id=i.order_id JOIN products p ON p.id=i.product_id WHERE o.status!='Cancelled' AND substr(o.created,1,4)=? GROUP BY p.cat ORDER BY v DESC").all(y), tot = cr.reduce((a, r) => a + r.v, 0) || 1;
  const top = db.prepare("SELECT i.name,SUM(i.qty) units,COALESCE(p.stock,0) stock FROM order_items i JOIN orders o ON o.id=i.order_id LEFT JOIN products p ON p.id=i.product_id WHERE o.status!='Cancelled' AND substr(o.created,1,4)=? GROUP BY i.product_id ORDER BY units DESC LIMIT 5").all(y);
  s.json({ year: y, months, cats: cr.map(r => ({ n: r.n, v: r.v / tot })), top });
}));
app.get('/api/admin/customers', need, adm, wrap((q, s) => s.json(db.prepare("SELECT u.name,u.email,COUNT(o.id) orders,COALESCE(SUM(o.total),0) spent FROM users u LEFT JOIN orders o ON o.user_id=u.id AND o.status!='Cancelled' WHERE u.role='customer' GROUP BY u.id ORDER BY spent DESC").all())));
app.get('/api/admin/expenses', need, adm, wrap((q, s) => s.json(db.prepare('SELECT * FROM expenses ORDER BY month DESC,id DESC LIMIT 200').all())));
app.post('/api/admin/expenses', need, adm, wrap((q, s) => {
  const m = String(q.body.month || ''), k = String(q.body.kind || ''), a = Math.round(+q.body.amount);
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(m) || !['Rent', 'Salaries', 'Marketing', 'Other'].includes(k) || !(a > 0)) throw err(400, 'Enter a month (YYYY-MM), type and positive amount');
  db.prepare('INSERT INTO expenses(month,kind,amount) VALUES(?,?,?)').run(m, k, a); s.status(201).json({ ok: true });
}));
app.use('/api', (q, s) => s.status(404).json({ error: 'Not found' }));
app.use('/uploads', express.static(UP, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log(`Sreekrishna Textiles running at http://localhost:${PORT}`));
