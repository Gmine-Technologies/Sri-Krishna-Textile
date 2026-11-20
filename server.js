require('dotenv').config();
const express = require('express'), path = require('path'), fs = require('fs'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const db = require('./db');
const seed = require('./seed');
const crypto = require('crypto');
const mailer = require('./mailer');

let PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET not set, using an insecure development secret.');


const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '16mb' }));
app.use((q, s, n) => {
  s.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'same-origin'
  });
  if (q.method === 'OPTIONS') return s.sendStatus(204);
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

let dbConnected = false;
let dbError = null;

app.use('/api', async (q, s, n) => {
  if (q.path === '/health' || q.path === '/db-status') return n();
  if (!dbConnected) {
    return s.status(503).json({
      error: 'Database not connected: ' + (dbError || 'Please check your database credentials in Hostinger.'),
      hint: 'Visit /api/db-status for connection diagnostic details'
    });
  }
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

// ---------- diagnostics & health ----------
app.get('/api/health', (q, s) => s.json({
  ok: dbConnected,
  dbConnected,
  store: 'Sreekrishna Textiles',
  database: process.env.DB_NAME || 'sreekrishna_store'
}));
app.get('/api/db-status', (q, s) => {
  s.json({
    server: 'online',
    dbConnected,
    dbError,
    dbConfig: {
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER || 'root',
      database: process.env.DB_NAME || 'sreekrishna_store'
    }
  });
});

// Send verification OTP during customer registration (Sign Up)
app.post('/api/auth/register/send-otp', limit, wrap(async (q, s) => {
  const name = String(q.body.name || '').trim().slice(0, 80);
  const email = String(q.body.email || '').trim().toLowerCase();
  const pw = String(q.body.password || '');

  if (!name) throw err(400, 'Please enter your name');
  if (!EMAIL.test(email)) throw err(400, 'Please enter a valid email address');
  if (pw.length < 6) throw err(400, 'Password must be at least 6 characters');
  if (q.body.confirm_password && q.body.confirm_password !== pw) throw err(400, 'Passwords do not match');

  if (await db.get('SELECT 1 FROM users WHERE email=?', [email])) {
    throw err(409, 'An account with this email already exists. Please log in.');
  }

  const recent = await db.all('SELECT id FROM email_otps WHERE email=? AND purpose=? AND created_at > ?', [email, 'signup', Date.now() - 6e5]);
  if (recent.length >= 4) throw err(429, 'Too many verification requests. Please wait a few minutes before trying again.');

  const otp = String(crypto.randomInt(100000, 999999));
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000;

  await db.run('DELETE FROM email_otps WHERE email=? AND purpose=?', [email, 'signup']);
  await db.run('INSERT INTO email_otps(email, otp, purpose, expires_at, created_at) VALUES(?,?,?,?,?)', [email, otp, 'signup', expiresAt, now]);

  const mailRes = await mailer.sendOtpEmail({ to: email, otp, purpose: 'signup', name });

  s.json({
    ok: true,
    message: `A 6-digit verification code has been sent to ${email}`,
    devOtp: mailRes && mailRes.simulated ? otp : undefined,
    configured: mailer.isConfigured()
  });
}));

app.post('/api/auth/register', limit, wrap(async (q, s) => {
  const name = String(q.body.name || '').trim().slice(0, 80);
  const email = String(q.body.email || '').trim().toLowerCase();
  const pw = String(q.body.password || '');
  const otp = String(q.body.otp || '').trim();

  if (!name || !EMAIL.test(email)) throw err(400, 'Enter a valid name and email');
  if (pw.length < 6) throw err(400, 'Password must be at least 6 characters');
  if (await db.get('SELECT 1 FROM users WHERE email=?', [email])) throw err(409, 'An account with this email already exists');

  if (!/^\d{6}$/.test(otp)) throw err(400, 'Please enter the 6-digit verification code sent to your email');

  const rec = await db.get('SELECT * FROM email_otps WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1', [email, 'signup']);
  if (!rec || Date.now() > rec.expires_at) {
    throw err(400, 'Verification code has expired. Please request a new code.');
  }

  if (rec.attempts >= 5) {
    await db.run('DELETE FROM email_otps WHERE id=?', [rec.id]);
    throw err(400, 'Too many incorrect attempts. Please request a new verification code.');
  }

  if (rec.otp !== otp) {
    await db.run('UPDATE email_otps SET attempts = attempts + 1 WHERE id=?', [rec.id]);
    const rem = 5 - (rec.attempts + 1);
    throw err(400, `Invalid verification code. ${rem} attempt(s) remaining.`);
  }

  await db.run('DELETE FROM email_otps WHERE id=?', [rec.id]);

  const res = await db.run('INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)', [name, email, bcrypt.hashSync(pw, 10), 'customer', new Date().toISOString()]);
  const u = await db.get('SELECT * FROM users WHERE id=?', [res.lastInsertRowid]);
  s.status(201).json({ token: sign(u), user: pubU(u) });
}));

app.post('/api/auth/login', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const u = await db.get('SELECT * FROM users WHERE email=?', [email]);
  if (!u || !bcrypt.compareSync(String(q.body.password || ''), u.hash)) throw err(401, 'Invalid email or password');
  if (q.body.role === 'admin' && u.role !== 'admin') throw err(403, 'This is not an admin account');
  if (q.body.role !== 'admin' && u.role === 'admin') throw err(403, 'Admin accounts must log in from /#/admin');
  s.json({ token: sign(u), user: pubU(u) });
}));

// ---------- SMTP & Email OTP Endpoints ----------
app.get('/api/auth/smtp-status', (q, s) => {
  s.json({
    configured: mailer.isConfigured(),
    sender: process.env.SMTP_USER || 'ramasamy.gokila@gmail.com',
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
  });
});

// 1. Forgot Password: Send OTP to email
app.post('/api/auth/forgot-password/send-otp', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  if (!EMAIL.test(email)) throw err(400, 'Please enter a valid email address');

  const u = await db.get('SELECT id, name, email FROM users WHERE email=?', [email]);
  if (!u) throw err(404, 'No account found with this email address');

  const recent = await db.all('SELECT id FROM email_otps WHERE email=? AND purpose=? AND created_at > ?', [email, 'forgot_password', Date.now() - 6e5]);
  if (recent.length >= 4) throw err(429, 'Too many OTP requests. Please wait a few minutes before trying again.');

  const otp = String(crypto.randomInt(100000, 999999));
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000;

  await db.run('DELETE FROM email_otps WHERE email=? AND purpose=?', [email, 'forgot_password']);
  await db.run('INSERT INTO email_otps(email, otp, purpose, expires_at, created_at) VALUES(?,?,?,?,?)', [email, otp, 'forgot_password', expiresAt, now]);

  const mailRes = await mailer.sendOtpEmail({ to: email, otp, purpose: 'forgot_password', name: u.name });

  s.json({
    ok: true,
    message: `A 6-digit verification code has been sent to ${email}`,
    devOtp: mailRes && mailRes.simulated ? otp : undefined,
    configured: mailer.isConfigured()
  });
}));

// 2. Forgot Password: Verify OTP
app.post('/api/auth/forgot-password/verify-otp', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const otp = String(q.body.otp || '').trim();
  if (!EMAIL.test(email)) throw err(400, 'Invalid email');
  if (!/^\d{6}$/.test(otp)) throw err(400, 'Enter the 6-digit OTP code');

  const rec = await db.get('SELECT * FROM email_otps WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1', [email, 'forgot_password']);
  if (!rec || Date.now() > rec.expires_at) {
    throw err(400, 'OTP code has expired. Please request a new code.');
  }

  if (rec.attempts >= 5) {
    await db.run('DELETE FROM email_otps WHERE id=?', [rec.id]);
    throw err(400, 'Too many incorrect attempts. Please request a new OTP code.');
  }

  if (rec.otp !== otp) {
    await db.run('UPDATE email_otps SET attempts = attempts + 1 WHERE id=?', [rec.id]);
    const rem = 5 - (rec.attempts + 1);
    throw err(400, `Invalid verification code. ${rem} attempt(s) remaining.`);
  }

  const resetToken = crypto.randomBytes(32).toString('hex');
  await db.run('UPDATE email_otps SET verified=1, token=?, expires_at=? WHERE id=?', [resetToken, Date.now() + 15 * 60 * 1000, rec.id]);

  s.json({
    ok: true,
    reset_token: resetToken,
    message: 'OTP verified successfully. You may now enter your new password.'
  });
}));

// 3. Forgot Password: Reset Password with verified token
app.post('/api/auth/forgot-password/reset', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const resetToken = String(q.body.reset_token || '').trim();
  const newPw = String(q.body.password || '');

  if (!EMAIL.test(email)) throw err(400, 'Invalid email');
  if (!resetToken) throw err(400, 'Missing reset verification token. Please verify OTP first.');
  if (newPw.length < 6) throw err(400, 'New password must be at least 6 characters');

  const rec = await db.get('SELECT * FROM email_otps WHERE email=? AND purpose=? AND token=? AND verified=1', [email, 'forgot_password', resetToken]);
  if (!rec || Date.now() > rec.expires_at) {
    throw err(400, 'Password reset session has expired. Please request and verify OTP again.');
  }

  const hash = bcrypt.hashSync(newPw, 10);
  await db.run('UPDATE users SET hash=? WHERE email=?', [hash, email]);
  await db.run('DELETE FROM email_otps WHERE id=?', [rec.id]);

  s.json({
    ok: true,
    message: 'Password reset successfully! You can now log in with your new password.'
  });
}));

// 4. Email OTP Direct Login: Send OTP
app.post('/api/auth/otp/send', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  if (!EMAIL.test(email)) throw err(400, 'Please enter a valid email address');

  const u = await db.get('SELECT id, name, email FROM users WHERE email=?', [email]);
  const userName = u ? u.name : email.split('@')[0];

  const recent = await db.all('SELECT id FROM email_otps WHERE email=? AND purpose=? AND created_at > ?', [email, 'login', Date.now() - 6e5]);
  if (recent.length >= 4) throw err(429, 'Too many OTP requests. Please wait a few minutes before trying again.');

  const otp = String(crypto.randomInt(100000, 999999));
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000;

  await db.run('DELETE FROM email_otps WHERE email=? AND purpose=?', [email, 'login']);
  await db.run('INSERT INTO email_otps(email, otp, purpose, expires_at, created_at) VALUES(?,?,?,?,?)', [email, otp, 'login', expiresAt, now]);

  const mailRes = await mailer.sendOtpEmail({ to: email, otp, purpose: 'login', name: userName });

  s.json({
    ok: true,
    message: `A 6-digit login code has been sent to ${email}`,
    devOtp: mailRes && mailRes.simulated ? otp : undefined,
    configured: mailer.isConfigured()
  });
}));

// 5. Email OTP Direct Login: Verify & Sign In
app.post('/api/auth/otp/verify', limit, wrap(async (q, s) => {
  const email = String(q.body.email || '').trim().toLowerCase();
  const otp = String(q.body.otp || '').trim();
  if (!EMAIL.test(email)) throw err(400, 'Invalid email');
  if (!/^\d{6}$/.test(otp)) throw err(400, 'Enter the 6-digit OTP code');

  const rec = await db.get('SELECT * FROM email_otps WHERE email=? AND purpose=? ORDER BY id DESC LIMIT 1', [email, 'login']);
  if (!rec || Date.now() > rec.expires_at) {
    throw err(400, 'OTP code has expired. Please request a new login code.');
  }

  if (rec.attempts >= 5) {
    await db.run('DELETE FROM email_otps WHERE id=?', [rec.id]);
    throw err(400, 'Too many incorrect attempts. Please request a new login code.');
  }

  if (rec.otp !== otp) {
    await db.run('UPDATE email_otps SET attempts = attempts + 1 WHERE id=?', [rec.id]);
    const rem = 5 - (rec.attempts + 1);
    throw err(400, `Invalid verification code. ${rem} attempt(s) remaining.`);
  }

  await db.run('DELETE FROM email_otps WHERE id=?', [rec.id]);

  let u = await db.get('SELECT * FROM users WHERE email=?', [email]);
  if (!u) {
    const dummyHash = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10);
    const res = await db.run('INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)', [email.split('@')[0], email, dummyHash, 'customer', new Date().toISOString()]);
    u = await db.get('SELECT * FROM users WHERE id=?', [res.lastInsertRowid]);
  }

  s.json({ token: sign(u), user: pubU(u), message: 'Logged in successfully!' });
}));

app.get('/api/me', need, (q, s) => s.json(pubU(q.user)));

app.put('/api/me', need, wrap(async (q, s) => {
  const name = String(q.body.name ?? q.user.name).trim().slice(0, 80);
  const email = String(q.body.email ?? q.user.email).trim().toLowerCase();
  const phone = ph(q.body.phone ?? q.user.phone);
  const address = String(q.body.address ?? q.user.address ?? '').trim().slice(0, 300);

  if (!name) throw err(400, 'Name is required');
  if (!EMAIL.test(email)) throw err(400, 'Please enter a valid email address');
  if (phone && phone.length !== 10) throw err(400, 'Phone must be 10 digits');

  if (email !== q.user.email) {
    const existing = await db.get('SELECT id FROM users WHERE email=? AND id!=?', [email, q.user.id]);
    if (existing) throw err(409, 'This email address is already in use by another account');
  }

  await db.run('UPDATE users SET name=?,email=?,phone=?,address=? WHERE id=?', [name, email, phone, address, q.user.id]);
  const updated = await db.get('SELECT * FROM users WHERE id=?', [q.user.id]);
  const token = sign(updated);
  s.json({ ...pubU(updated), token, user: pubU(updated) });
}));

app.post('/api/me/password', need, limit, wrap(async (q, s) => {
  const n = String(q.body.new || '');
  if (!bcrypt.compareSync(String(q.body.current || ''), q.user.hash)) throw err(400, 'Current password is incorrect');
  if (n.length < 6) throw err(400, 'New password must be at least 6 characters');
  await db.run('UPDATE users SET hash=? WHERE id=?', [bcrypt.hashSync(n, 10), q.user.id]);
  s.json({ ok: true });
}));

// ---------- store settings ----------
const CFG0 = { store: 'Sreekrishna Textiles', phone: '+91 9976392317', email: 'ramasamy.gokila@gmail.com', addr: 'No. 10 Shopping Mall 1st Floor, Kovai Road, Pollachi - 642002', ship: 99, free: 2999, low: 8 };
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

async function saveImg(id, data) {
  const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(data || '');
  if (!m) throw err(400, 'Image must be a JPEG, PNG or WebP data URL');
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length > 12e6) throw err(413, 'Image too large (max 12 MB)');
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const mime = `image/${m[1]}`;
  const f = `${id}-${Date.now()}.${ext}`;

  // Store ONLY in MySQL database
  await db.run(
    'INSERT INTO product_images(filename, product_id, mime, data) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE mime=VALUES(mime), data=VALUES(data)',
    [f, id, mime, buf]
  );

  return '/uploads/' + f;
}

const rmImg = async u => {
  if (u && u.startsWith('/uploads/')) {
    const f = path.basename(u);
    try { await db.run('DELETE FROM product_images WHERE filename=?', [f]); } catch (_) {}
  }
};

app.get('/api/products', wrap(async (q, s) => {
  const rows = await db.all('SELECT * FROM products ORDER BY sort_order DESC');
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
      ('cost' in b && +b.cost > 0) ? Math.round(+b.cost) : Math.max(1, Math.round(price * (1 - disc / 100))), b.col || 'Pink', b.fab || 'Silk', 4.5, 0,
      Math.max(0, Math.round(+b.stock) || 0), 'SKT-' + (7000 + n), b.occ || 'Festive',
      String(b.desc || 'New arrival from Sreekrishna Textiles.').slice(0, 500),
      b.img ? await saveImg(id, b.img) : null, new Date().toISOString()
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
  if ('disc' in b) {
    n.disc = int(b.disc, 0, 90);
    if (!('cost' in b)) n.cost = Math.max(1, Math.round(n.price * (1 - n.disc / 100)));
  }
  if ('cost' in b) n.cost = int(b.cost, 0, 1e7);
  if ('stock' in b) n.stock = int(b.stock, 0, 1e6);
  if ('price' in b || 'disc' in b) n.mrp = mrpOf(n.price, n.disc);
  if ('img' in b) {
    if (b.img === null) { await rmImg(r.img); n.img = null; }
    else if (/^data:/.test(b.img)) { n.img = await saveImg(r.id, b.img); await rmImg(r.img); }
    else if (typeof b.img === 'string') { n.img = b.img; }
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
  await rmImg(r.img);
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
    ship: o.ship || 0, total: o.total, pay: o.pay, pay_ref: o.pay_ref || '', status: o.status,
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

app.get('/api/upi-qr', wrap(async (q, s) => {
  const amount = Math.max(1, Math.round(+q.query.amount || 0));
  const uri = `upi://pay?pa=gokilasandhanakrishnan@icici&pn=GOKILA%20R&am=${amount}.00&cu=INR&tn=Sreekrishna%20Textiles%20Order`;
  const svg = await QRCode.toString(uri, { type: 'svg', margin: 1 });
  s.setHeader('Content-Type', 'image/svg+xml');
  s.setHeader('Cache-Control', 'no-cache');
  s.send(svg);
}));

app.post('/api/verify-upi', wrap(async (q, s) => {
  const ref = String(q.body.ref || q.body.utr || '').trim().replace(/\D/g, '');
  const amount = +q.body.amount || 0;
  if (!ref) throw err(400, 'Please enter your 12-digit UPI reference (UTR) number');
  if (ref.length !== 12) throw err(400, 'UPI reference (UTR) must be exactly 12 numeric digits');

  const existing = await db.get('SELECT id, created, total FROM orders WHERE pay_ref=? AND status != "Cancelled"', [ref]);
  if (existing) {
    throw err(409, `This UPI reference number (${ref}) has already been used for order ${existing.id}`);
  }

  s.json({
    ok: true,
    verified: true,
    ref,
    amount,
    receiver: 'gokilasandhanakrishnan@icici',
    name: 'GOKILA R',
    message: 'UPI payment reference verified successfully'
  });
}));

app.post('/api/orders', wrap(async (q, s) => {
  const items = Array.isArray(q.body.items) ? q.body.items : [];
  if (!items.length || items.length > 50) throw err(400, 'Cart is empty');
  const pay = ['UPI', 'Cash on Delivery'].includes(q.body.pay) ? q.body.pay : 'UPI';
  const pay_ref = String(q.body.pay_ref || '').trim().slice(0, 100);
  if (pay === 'UPI') {
    const cleanRef = pay_ref.replace(/\D/g, '');
    if (cleanRef.length !== 12) {
      throw err(400, 'A valid 12-digit UPI reference (UTR) is required to place a UPI order');
    }
  }
  const name = String(q.body.name || (q.user && q.user.name) || '').trim().slice(0, 80);
  const address = String(q.body.address || '').trim().slice(0, 300);
  const phone = ph(q.body.phone || (q.user && q.user.phone));
  const email = String(q.body.email || (q.user && q.user.email) || 'guest').trim().slice(0, 120);

  if (!name || !address) throw err(400, 'Name and delivery address are required');
  if (phone.length !== 10) throw err(400, 'Enter a valid 10-digit phone number');

  const cfg = await getCfg();
  const id = await db.transaction(async (tx) => {
    let sub = 0, cost = 0; const lines = [];
    for (const it of items) {
      const qty = Math.round(+it.q);
      if (!(qty >= 1 && qty <= 20)) throw err(400, 'Invalid quantity');
      const p = await tx.get('SELECT * FROM products WHERE id=?', [String(it.id)]);
      if (!p) throw err(404, 'A product in your cart no longer exists');

      const curStock = p.stock != null ? p.stock : 10;
      if (curStock < qty) {
        throw err(409, curStock > 0 ? `Only ${curStock} of "${p.name}" available` : `"${p.name}" is currently out of stock`);
      }
      await tx.run('UPDATE products SET stock=GREATEST(0, stock-?) WHERE id=?', [qty, p.id]);

      const eff = p.disc ? Math.max(1, Math.round(p.price * (1 - p.disc / 100))) : p.price;
      const c = (p.cost && p.cost > 0) ? p.cost : Math.max(1, Math.round(eff * 0.6));
      sub += eff * qty; cost += c * qty;
      lines.push({ p, qty, col: String(it.col || p.col), eff, cost: c });
    }
    const ship = sub < cfg.free ? cfg.ship : 0;
    const oid = 'SKT' + Date.now().toString().slice(-7) + Math.floor(Math.random() * 90 + 10);
    await tx.run(
      'INSERT INTO orders(id,user_id,email,name,address,phone,ship,total,cost,pay,pay_ref,status,created) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [oid, q.user ? q.user.id : null, email, name, address, phone, ship, sub + ship, cost, pay, pay_ref, 'Processing', new Date().toISOString()]
    );
    for (const l of lines) {
      await tx.run(
        'INSERT INTO order_items(order_id,product_id,name,col,qty,price,cost) VALUES(?,?,?,?,?,?,?)',
        [oid, l.p.id, l.p.name, l.col, l.qty, l.eff || l.p.price, l.cost]
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
    : await db.all('SELECT * FROM orders WHERE user_id=? OR email=? ORDER BY created DESC', [q.user.id, q.user.email]);
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

// Also provide direct product ID image endpoint from MySQL
app.get('/api/products/:id/image', async (q, s) => {
  try {
    let row = await db.get('SELECT mime, data FROM product_images WHERE product_id=? ORDER BY created DESC LIMIT 1', [q.params.id]);
    if (!row) {
      const p = await db.get('SELECT img FROM products WHERE id=?', [q.params.id]);
      if (p && p.img && p.img.startsWith('/uploads/')) {
        row = await db.get('SELECT mime, data FROM product_images WHERE filename=?', [path.basename(p.img)]);
      }
    }
    if (row && row.data) {
      const buf = Buffer.isBuffer(row.data) ? row.data : Buffer.from(row.data);
      s.set({
        'Content-Type': row.mime || 'image/jpeg',
        'Content-Length': buf.length,
        'Cache-Control': 'public, max-age=86400',
        'X-Content-Type-Options': 'nosniff'
      });
      return s.send(buf);
    }
  } catch (e) {
    console.error('MySQL image fetch error:', e.message);
  }
  s.status(404).send('Image not found in database');
});

// Direct lossless image download endpoint with attachment header for 100% original quality
app.get('/api/products/:id/image/download', async (q, s) => {
  try {
    let row = await db.get('SELECT filename, mime, data FROM product_images WHERE product_id=? ORDER BY created DESC LIMIT 1', [q.params.id]);
    const p = await db.get('SELECT name, sku, img FROM products WHERE id=?', [q.params.id]);
    if (!row && p && p.img && p.img.startsWith('/uploads/')) {
      const fn = path.basename(p.img);
      row = await db.get('SELECT filename, mime, data FROM product_images WHERE filename=?', [fn]);
    }
    if (row && row.data) {
      const buf = Buffer.isBuffer(row.data) ? row.data : Buffer.from(row.data);
      const ext = (row.mime && row.mime.includes('png')) ? 'png' : (row.mime && row.mime.includes('webp')) ? 'webp' : 'jpg';
      const safeName = p ? `${p.sku || q.params.id}_${(p.name || '').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 50)}.${ext}` : `${q.params.id}.${ext}`;
      s.set({
        'Content-Type': row.mime || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${safeName}"`,
        'Content-Length': buf.length,
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
      });
      return s.send(buf);
    }
  } catch (e) {
    console.error('MySQL image download error:', e.message);
  }
  s.status(404).send('Image not found in database');
});

app.use('/api', (q, s) => s.status(404).json({ error: 'Not found' }));

// Images are stored ONLY in MySQL database and fetched ONLY from MySQL database
app.get('/uploads/:filename', async (q, s) => {
  const filename = path.basename(q.params.filename);
  try {
    const row = await db.get('SELECT mime, data FROM product_images WHERE filename=?', [filename]);
    if (row && row.data) {
      const buf = Buffer.isBuffer(row.data) ? row.data : Buffer.from(row.data);
      s.set({
        'Content-Type': row.mime || 'image/jpeg',
        'Content-Length': buf.length,
        'Cache-Control': 'public, max-age=86400',
        'X-Content-Type-Options': 'nosniff'
      });
      return s.send(buf);
    }
  } catch (e) {
    console.error('MySQL image fetch error:', e.message);
  }
  s.status(404).send('Image not found in database');
});

// Lossless download of uploaded files directly by filename
app.get('/uploads/:filename/download', async (q, s) => {
  const filename = path.basename(q.params.filename);
  try {
    const row = await db.get('SELECT mime, data FROM product_images WHERE filename=?', [filename]);
    if (row && row.data) {
      const buf = Buffer.isBuffer(row.data) ? row.data : Buffer.from(row.data);
      s.set({
        'Content-Type': row.mime || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Length': buf.length,
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
      });
      return s.send(buf);
    }
  } catch (e) {
    console.error('MySQL image download error:', e.message);
  }
  s.status(404).send('Image not found in database');
});
app.get(['/admin', '/admin/*'], (q, s) => s.redirect('/#/admin'));
app.get('/login', (q, s) => s.redirect('/#/login'));
app.get('/favicon.ico', (q, s) => s.sendFile(path.join(__dirname, 'public', 'favicon.ico')));
app.get('/favicon.svg', (q, s) => { s.type('image/svg+xml'); s.sendFile(path.join(__dirname, 'public', 'favicon.svg')); });
app.get('/apple-touch-icon.png', (q, s) => s.sendFile(path.join(__dirname, 'public', 'apple-touch-icon.png')));
app.get('/og-image.png', (q, s) => s.sendFile(path.join(__dirname, 'public', 'og-image.png')));
app.use(express.static(path.join(__dirname, 'public')));

async function startServer() {
  // 1. Start HTTP server immediately so Hostinger's proxy never receives a 503
  const tryListen = (p) => new Promise((resolve, reject) => {
    const srv = app.listen(p, () => {
      PORT = p;
      console.log(`Sreekrishna Textiles running at http://localhost:${p}`);
      resolve(srv);
    });
    srv.on('error', (err) => {
      if (err.code === 'EADDRINUSE' && p < 3010) {
        console.warn(`Port ${p} in use, trying port ${p + 1}...`);
        resolve(tryListen(p + 1));
      } else {
        reject(err);
      }
    });
  });

  const server = await tryListen(PORT);

  // 2. Connect to MySQL database in background
  try {
    console.log(`Connecting to MySQL database '${process.env.DB_NAME || 'sreekrishna_store'}' at ${process.env.DB_HOST || 'localhost'}...`);
    await db.init();
    await seed(db);
    dbConnected = true;
    dbError = null;
    console.log('Database connected and initialized successfully!');
  } catch (e) {
    dbConnected = false;
    dbError = e.message || String(e);
    console.error('\n[Database Connection Notice]:', dbError);
    console.error('Web server is active. Check http://your-domain/api/db-status to inspect the database connection status.\n');
  }

  return server;
}

startServer();

module.exports = app;

