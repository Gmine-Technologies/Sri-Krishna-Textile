const express = require('express');
const router = express.Router();
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./db');
const { generateTokens, authMiddleware, optionalAuthMiddleware } = require('./billingAuth');

function getPool() {
  return db.pool;
}

// -------------------------------------------------------------
// HELPER: Auto-generate invoice number (INV-YYYY-XXXXXX or PO-YYYY-XXXXXX)
// -------------------------------------------------------------
async function getNextInvoiceNumber(connection, type = 'sale') {
  const year = new Date().getFullYear();
  const tag = (type === 'purchase') ? 'PO' : 'INV';
  const prefix = `${tag}-${year}-`;
  const [rows] = await connection.query(
    'SELECT invoice_number FROM purchases WHERE invoice_number LIKE ? ORDER BY id DESC LIMIT 1',
    [`${prefix}%`]
  );
  let nextSeq = 1;
  if (rows.length > 0) {
    const parts = rows[0].invoice_number.split('-');
    const lastNum = parseInt(parts[parts.length - 1], 10);
    if (!isNaN(lastNum)) nextSeq = lastNum + 1;
  }
  let candidate = `${prefix}${String(nextSeq).padStart(6, '0')}`;
  // Ensure uniqueness
  while (true) {
    const [chk] = await connection.query('SELECT id FROM purchases WHERE invoice_number = ?', [candidate]);
    if (chk.length === 0) break;
    nextSeq++;
    candidate = `${prefix}${String(nextSeq).padStart(6, '0')}`;
  }
  return candidate;
}

// -------------------------------------------------------------
// HELPER: Auto-generate customer code (CUST-XXXX)
// -------------------------------------------------------------
async function getNextCustomerCode(connection, requestedCode) {
  if (requestedCode && requestedCode.trim()) {
    const code = requestedCode.trim().toUpperCase();
    const [existing] = await connection.query('SELECT id FROM customers WHERE customer_code = ?', [code]);
    if (existing.length === 0) return code;
  }
  const [rows] = await connection.query('SELECT customer_code FROM customers WHERE customer_code LIKE "CUST-%"');
  let maxNum = 0;
  for (const r of rows) {
    const m = r.customer_code.match(/CUST-(\d+)/);
    if (m) {
      const v = parseInt(m[1], 10);
      if (v > maxNum) maxNum = v;
    }
  }
  let nextNum = maxNum + 1;
  let candidate = `CUST-${String(nextNum).padStart(4, '0')}`;
  while (true) {
    const [chk] = await connection.query('SELECT id FROM customers WHERE customer_code = ?', [candidate]);
    if (chk.length === 0) break;
    nextNum++;
    candidate = `CUST-${String(nextNum).padStart(4, '0')}`;
  }
  return candidate;
}

// =============================================================
// 1. AUTHENTICATION ROUTES (/api/auth)
// =============================================================

// POST /api/auth/login/
router.post('/api/auth/login/', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ detail: 'Username and password are required.' });
  }

  try {
    const pool = getPool();
    const [users] = await pool.query('SELECT * FROM users WHERE username = ? OR email = ?', [username.trim(), username.trim().toLowerCase()]);
    if (users.length === 0) {
      return res.status(401).json({ detail: 'Invalid credentials. Please verify your username and password.' });
    }

    const user = users[0];
    if (user.is_active === 0) {
      return res.status(403).json({ detail: 'This account has been deactivated.' });
    }

    const pwHash = user.password || user.hash;
    const valid = pwHash ? await bcrypt.compare(password, pwHash) : false;
    if (!valid) {
      return res.status(401).json({ detail: 'Invalid credentials. Please verify your username and password.' });
    }

    const tokens = generateTokens(user);
    res.json({
      access: tokens.access,
      refresh: tokens.refresh,
      user: {
        id: user.id,
        username: user.username || (user.email ? user.email.split('@')[0] : 'admin'),
        email: user.email || '',
        first_name: user.first_name || user.name || 'Admin',
        last_name: user.last_name || '',
        is_staff: Boolean(user.is_staff || user.role === 'admin'),
        is_superuser: Boolean(user.is_superuser || user.role === 'admin')
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ detail: 'Internal server error.' });
  }
});

// Bridge endpoint: generate billing token for already-authenticated store admin
router.post('/api/auth/billing-token', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.user_id]);
    const user = users[0] || { id: 1, username: 'admin', is_staff: 1, is_superuser: 1 };
    const tokens = generateTokens(user);
    res.json({
      access: tokens.access,
      refresh: tokens.refresh,
      user: {
        id: user.id,
        username: user.username || (user.email ? user.email.split('@')[0] : 'admin'),
        email: user.email || '',
        first_name: user.first_name || user.name || 'Admin',
        last_name: user.last_name || '',
        is_staff: true,
        is_superuser: true
      }
    });
  } catch (err) {
    res.status(500).json({ detail: 'Error generating billing token' });
  }
});

// GET /api/auth/me/
router.get('/api/auth/me/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.user_id]);
    if (users.length === 0) return res.status(404).json({ detail: 'User not found.' });
    const user = users[0];
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      is_staff: Boolean(user.is_staff),
      is_superuser: Boolean(user.is_superuser)
    });
  } catch (err) {
    res.status(500).json({ detail: 'Internal server error.' });
  }
});

// POST /api/auth/refresh/
router.post('/api/auth/refresh/', (req, res) => {
  const { refresh } = req.body;
  if (!refresh) return res.status(400).json({ detail: 'Refresh token required' });
  try {
    const jwt = require('jsonwebtoken');
    const { JWT_SECRET } = require('./auth');
    const decoded = jwt.verify(refresh, JWT_SECRET);
    const access = jwt.sign(
      { user_id: decoded.user_id, username: decoded.username, is_staff: decoded.is_staff, is_superuser: decoded.is_superuser },
      JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.json({ access });
  } catch (err) {
    res.status(401).json({ detail: 'Token is invalid or expired', code: 'token_not_valid' });
  }
});

// =============================================================
// 2. CUSTOMERS ROUTES (/api/customers)
// =============================================================

// GET /api/customers/
router.get('/api/customers/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const search = (req.query.search || '').trim();
    const isActive = req.query.is_active;
    const ordering = req.query.ordering || '-total_loyalty_points';

    let query = 'SELECT * FROM customers WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as total FROM customers WHERE 1=1';
    const params = [];
    const countParams = [];

    if (search) {
      const s = `%${search}%`;
      const searchClause = ' AND (name LIKE ? OR customer_code LIKE ? OR phone_number LIKE ? OR address LIKE ?)';
      query += searchClause;
      countQuery += searchClause;
      params.push(s, s, s, s);
      countParams.push(s, s, s, s);
    }
    if (isActive !== undefined && isActive !== '') {
      const activeVal = isActive === 'true' || isActive === '1' ? 1 : 0;
      query += ' AND is_active = ?';
      countQuery += ' AND is_active = ?';
      params.push(activeVal);
      countParams.push(activeVal);
    }

    // Determine SQL sorting
    let orderBy = 'ORDER BY total_loyalty_points DESC, created_at DESC';
    if (ordering === 'total_loyalty_points') {
      orderBy = 'ORDER BY total_loyalty_points ASC, created_at DESC';
    } else if (ordering === '-created_at') {
      orderBy = 'ORDER BY created_at DESC';
    } else if (ordering === 'created_at') {
      orderBy = 'ORDER BY created_at ASC';
    } else if (ordering === 'name') {
      orderBy = 'ORDER BY name ASC';
    } else if (ordering === '-name') {
      orderBy = 'ORDER BY name DESC';
    }
    query += ` ${orderBy}`;

    const [countRows] = await pool.query(countQuery, countParams);
    const totalCount = countRows[0].total;

    // Handle pagination if requested
    const page = parseInt(req.query.page, 10);
    const pageSize = parseInt(req.query.page_size, 10);
    if (!isNaN(page) && page > 0 && !isNaN(pageSize) && pageSize > 0) {
      const offset = (page - 1) * pageSize;
      query += ' LIMIT ? OFFSET ?';
      params.push(pageSize, offset);
    }

    const [rows] = await pool.query(query, params);
    res.json({
      count: totalCount,
      results: rows
    });
  } catch (err) {
    console.error('Fetch customers error:', err);
    res.status(500).json({ error: 'Failed to fetch customers.' });
  }
});

// POST /api/customers/
router.post('/api/customers/', authMiddleware, async (req, res) => {
  const { name, phone_number, email, address, is_active } = req.body;
  if (!phone_number || !phone_number.trim()) {
    return res.status(400).json({ phone_number: ['Phone number is compulsory and cannot be blank.'] });
  }
  if (!name || !name.trim()) {
    return res.status(400).json({ name: ['Customer Name is required.'] });
  }

  const rawPhone = phone_number.trim();
  const digits = rawPhone.replace(/\D/g, '');
  const last10 = digits.length >= 6 ? digits.slice(-10) : digits;

  const rawAmount = req.body.total_purchase !== undefined ? req.body.total_purchase : (req.body.initial_purchase_amount !== undefined ? req.body.initial_purchase_amount : req.body.amount);
  const purchaseAmount = rawAmount !== undefined && rawAmount !== '' ? parseFloat(rawAmount) : 0;
  const billNo = (req.body.bill_no || req.body.initial_bill_no || req.body.custom_bill_no || '').trim();

  const pool = getPool();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Check if customer already exists by phone
    let [matchedRows] = await conn.query('SELECT * FROM customers WHERE phone_number = ? LIMIT 1 FOR UPDATE', [rawPhone]);
    if (matchedRows.length === 0 && last10.length >= 6) {
      [matchedRows] = await conn.query('SELECT * FROM customers WHERE phone_number LIKE ? LIMIT 1 FOR UPDATE', [`%${last10}`]);
    }

    let customerId;
    let customerCode;
    let matchedExisting = false;
    let previousPoints = 0;

    if (matchedRows.length > 0) {
      // Existing customer matched! Update info if provided
      matchedExisting = true;
      const existingCust = matchedRows[0];
      customerId = existingCust.id;
      customerCode = existingCust.customer_code;
      previousPoints = existingCust.total_loyalty_points || 0;

      await conn.query(
        `UPDATE customers SET name = ?, email = COALESCE(?, email), address = COALESCE(?, address), is_active = COALESCE(?, is_active) WHERE id = ?`,
        [name.trim(), email ? email.trim() : null, address ? address.trim() : null, is_active !== undefined ? (is_active ? 1 : 0) : null, customerId]
      );
    } else {
      // New customer
      customerCode = await getNextCustomerCode(conn, req.body.customer_code);
      const [insertRes] = await conn.query(
        `INSERT INTO customers (customer_code, name, phone_number, email, address, is_active, total_loyalty_points)
         VALUES (?, ?, ?, ?, ?, ?, 0)`,
        [customerCode, name.trim(), rawPhone, email ? email.trim() : null, address ? address.trim() : '', is_active !== undefined ? (is_active ? 1 : 0) : 1]
      );
      customerId = insertRes.insertId;
    }

    // Process Purchase & Loyalty Points (₹100 = 1 point)
    let pointsToAdd = 0;
    let createdInvoice = null;

    if (purchaseAmount > 0) {
      pointsToAdd = Math.floor(purchaseAmount / 100);
      createdInvoice = billNo ? billNo : await getNextInvoiceNumber(conn, 'sale');

      const [pRes] = await conn.query(
        `INSERT INTO purchases (invoice_number, customer_id, record_type, subtotal, discount_amount, tax_amount, final_amount, points_earned, status, created_by_id)
         VALUES (?, ?, 'sale', ?, 0.00, 0.00, ?, ?, 'completed', ?)`,
        [createdInvoice, customerId, purchaseAmount, purchaseAmount, pointsToAdd, req.user.user_id]
      );
      const purchaseId = pRes.insertId;

      await conn.query(
        `INSERT INTO purchase_items (purchase_id, product_name_snapshot, product_sku_snapshot, unit_price, quantity, line_total)
         VALUES (?, 'Store Purchase', 'GEN-001', ?, 1, ?)`,
        [purchaseId, purchaseAmount, purchaseAmount]
      );

      const newTotalPoints = previousPoints + pointsToAdd;
      await conn.query('UPDATE customers SET total_loyalty_points = ? WHERE id = ?', [newTotalPoints, customerId]);

      if (pointsToAdd > 0) {
        await conn.query(
          `INSERT INTO loyalty_transactions (customer_id, purchase_id, transaction_type, points_change, description, resulting_balance, created_by_id)
           VALUES (?, ?, 'award', ?, ?, ?, ?)`,
          [customerId, purchaseId, pointsToAdd, `Loyalty points for bill #${createdInvoice} (₹${purchaseAmount})`, newTotalPoints, req.user.user_id]
        );
      }
    }

    await conn.commit();

    const [freshCust] = await pool.query('SELECT * FROM customers WHERE id = ?', [customerId]);
    const responseData = {
      ...freshCust[0],
      matched_existing: matchedExisting,
      points_added: pointsToAdd,
      purchase_invoice: createdInvoice,
      message: matchedExisting
        ? (pointsToAdd > 0
            ? `Matched existing customer '${name}' (${customerCode}). Purchase ${createdInvoice} (₹${purchaseAmount}) recorded & ${pointsToAdd} points added (Balance: ${freshCust[0].total_loyalty_points} pts).`
            : `Matched existing customer '${name}' (${customerCode}). Profile updated.`)
        : (pointsToAdd > 0
            ? `New customer '${name}' (${customerCode}) registered & Purchase ${createdInvoice} (₹${purchaseAmount}) recorded with ${pointsToAdd} points.`
            : `New customer '${name}' (${customerCode}) registered successfully.`)
    };

    res.status(matchedExisting ? 200 : 201).json(responseData);
  } catch (err) {
    await conn.rollback();
    console.error('Create/Match customer error:', err);
    res.status(400).json({ error: err.message || 'Failed to process customer.' });
  } finally {
    conn.release();
  }
});

// GET /api/customers/by-phone/?phone=...
router.get('/api/customers/by-phone/', authMiddleware, async (req, res) => {
  const phone = (req.query.phone || '').trim();
  if (!phone) {
    return res.json({ found: false, customer: null, message: 'Phone parameter is required.' });
  }
  try {
    const pool = getPool();
    // 1. Exact match
    let [rows] = await pool.query('SELECT * FROM customers WHERE phone_number = ? LIMIT 1', [phone]);

    // 2. Trailing 10-digits match if exact match not found
    if (rows.length === 0) {
      const digits = phone.replace(/\D/g, '');
      if (digits.length >= 6) {
        const last10 = digits.slice(-10);
        [rows] = await pool.query('SELECT * FROM customers WHERE phone_number LIKE ? LIMIT 1', [`%${last10}`]);
      }
    }

    if (rows.length > 0) {
      const cust = rows[0];
      return res.json({
        found: true,
        customer: cust,
        message: `Customer '${cust.name}' found with ${cust.total_loyalty_points} loyalty points.`
      });
    }

    return res.json({
      found: false,
      customer: null,
      message: `No customer found with phone ${phone}`
    });
  } catch (err) {
    console.error('Customer lookup error:', err);
    res.status(500).json({ error: 'Database error.' });
  }
});

// GET /api/customers/:id/
router.get('/api/customers/:id/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [rows] = await pool.query('SELECT * FROM customers WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ detail: 'Customer not found.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database error.' });
  }
});

// PUT/PATCH /api/customers/:id/
router.all(['/api/customers/:id/'], authMiddleware, async (req, res, next) => {
  if (req.method !== 'PUT' && req.method !== 'PATCH') return next();
  const { name, phone_number, email, address, is_active } = req.body;
  try {
    const pool = getPool();
    const [exists] = await pool.query('SELECT * FROM customers WHERE id = ?', [req.params.id]);
    if (exists.length === 0) return res.status(404).json({ detail: 'Customer not found.' });

    const current = exists[0];
    const newName = name !== undefined ? name.trim() : current.name;
    const newPhone = phone_number !== undefined ? phone_number.trim() : current.phone_number;
    const newEmail = email !== undefined ? (email ? email.trim() : null) : current.email;
    const newAddr = address !== undefined ? address.trim() : current.address;
    const newActive = is_active !== undefined ? (is_active ? 1 : 0) : current.is_active;

    await pool.query(
      `UPDATE customers SET name = ?, phone_number = ?, email = ?, address = ?, is_active = ? WHERE id = ?`,
      [newName, newPhone, newEmail, newAddr, newActive, req.params.id]
    );

    const [updated] = await pool.query('SELECT * FROM customers WHERE id = ?', [req.params.id]);
    res.json(updated[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// DELETE /api/customers/:id/ - Permanent Delete from Database
router.delete('/api/customers/:id/', authMiddleware, async (req, res) => {
  const customerId = req.params.id;
  const pool = getPool();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [exists] = await conn.query('SELECT * FROM customers WHERE id = ? FOR UPDATE', [customerId]);
    if (exists.length === 0) {
      throw new Error('Customer not found.');
    }
    const customer = exists[0];

    // 1. Delete loyalty transactions for this customer
    await conn.query('DELETE FROM loyalty_transactions WHERE customer_id = ?', [customerId]);

    // 2. Delete purchase items for purchases belonging to this customer
    await conn.query(`
      DELETE pi FROM purchase_items pi
      JOIN purchases p ON pi.purchase_id = p.id
      WHERE p.customer_id = ?
    `, [customerId]);

    // 3. Delete purchases belonging to this customer
    await conn.query('DELETE FROM purchases WHERE customer_id = ?', [customerId]);

    // 4. Delete customer record
    await conn.query('DELETE FROM customers WHERE id = ?', [customerId]);

    await conn.commit();
    res.json({
      success: true,
      message: `Customer '${customer.name}' (${customer.customer_code}) and all related records deleted successfully.`
    });
  } catch (err) {
    await conn.rollback();
    console.error('Delete customer error:', err);
    res.status(400).json({ error: err.message || 'Failed to delete customer.' });
  } finally {
    conn.release();
  }
});

// GET /api/customers/:id/purchases/
router.get('/api/customers/:id/purchases/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [purchases] = await pool.query(
      `SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
       FROM purchases p
       JOIN customers c ON p.customer_id = c.id
       WHERE p.customer_id = ? ORDER BY p.created_at DESC`,
      [req.params.id]
    );
    res.json(purchases);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// GET /api/customers/:id/loyalty-transactions/
router.get('/api/customers/:id/loyalty-transactions/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [txs] = await pool.query(
      `SELECT lt.*, p.invoice_number as purchase_invoice
       FROM loyalty_transactions lt
       LEFT JOIN purchases p ON lt.purchase_id = p.id
       WHERE lt.customer_id = ? ORDER BY lt.created_at DESC`,
      [req.params.id]
    );
    res.json(txs);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// =============================================================
// 3. PRODUCTS ROUTES (/api/products)
// =============================================================

// GET /api/products/
router.get('/api/products/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const search = (req.query.search || '').trim();
    let query = 'SELECT * FROM products WHERE is_active = 1';
    const params = [];
    if (search) {
      query += ' AND (name LIKE ? OR sku LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }
    query += ' ORDER BY name ASC';
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/products/
router.post('/api/products/', authMiddleware, async (req, res) => {
  const { name, sku, unit_price, description, is_active } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ name: ['Product name is required.'] });
  if (unit_price === undefined || parseFloat(unit_price) < 0) {
    return res.status(400).json({ unit_price: ['Valid unit price is required.'] });
  }

  try {
    const pool = getPool();
    let autoSku = sku && sku.trim() ? sku.trim().toUpperCase() : null;
    if (!autoSku) {
      const [cnt] = await pool.query('SELECT COUNT(*) as count FROM products');
      autoSku = `PRD-${String(cnt[0].count + 1).padStart(4, '0')}`;
    }

    const [result] = await pool.query(
      `INSERT INTO products (sku, name, description, unit_price, is_active)
       VALUES (?, ?, ?, ?, ?)`,
      [autoSku, name.trim(), description || '', parseFloat(unit_price), is_active !== undefined ? (is_active ? 1 : 0) : 1]
    );

    const [newP] = await pool.query('SELECT * FROM products WHERE id = ?', [result.insertId]);
    res.status(201).json(newP[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// GET /api/products/:id/
router.get('/api/products/:id/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [rows] = await pool.query('SELECT * FROM products WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ detail: 'Product not found.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// =============================================================
// 4. PURCHASES ROUTES (/api/purchases)
// =============================================================

// GET /api/purchases/
router.get('/api/purchases/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const search = (req.query.search || '').trim();
    const statusParam = (req.query.status || '').trim();
    const recordType = (req.query.record_type || req.query.type || '').trim();
    const qualifyingOnly = req.query.qualifying_only === 'true' || req.query.qualifying_only === '1';
    const dateParam = (req.query.date || '').trim();
    const dateFrom = (req.query.date_from || '').trim();
    const dateTo = (req.query.date_to || '').trim();

    let query = `
      SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
      FROM purchases p
      JOIN customers c ON p.customer_id = c.id
      WHERE 1=1
    `;
    const params = [];

    if (recordType) {
      query += ' AND p.record_type = ?';
      params.push(recordType);
    }
    if (qualifyingOnly) {
      query += ' AND p.points_earned > 0';
    }
    if (search) {
      query += ' AND (p.invoice_number LIKE ? OR c.name LIKE ? OR c.customer_code LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (statusParam) {
      query += ' AND p.status = ?';
      params.push(statusParam.toLowerCase());
    }
    if (dateParam) {
      query += ' AND DATE(p.created_at) = ?';
      params.push(dateParam);
    }
    if (dateFrom) {
      query += ' AND DATE(p.created_at) >= ?';
      params.push(dateFrom);
    }
    if (dateTo) {
      query += ' AND DATE(p.created_at) <= ?';
      params.push(dateTo);
    }

    query += ' ORDER BY p.created_at DESC';
    const [rows] = await pool.query(query, params);

    // Attach items summary
    for (const p of rows) {
      const [items] = await pool.query('SELECT * FROM purchase_items WHERE purchase_id = ?', [p.id]);
      p.items = items;
      p.total_quantity = items.reduce((sum, it) => sum + parseInt(it.quantity || 1, 10), 0);
    }

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/purchases/ - Create purchase / sale with atomic loyalty calculation
router.post('/api/purchases/', authMiddleware, async (req, res) => {
  const { customer_id, items, discount_amount, tax_amount, idempotency_key, invoice_number, bill_no } = req.body;
  const recordType = (req.body.record_type || req.body.type || 'sale').toLowerCase();

  if (!customer_id) return res.status(400).json({ error: 'customer_id is required' });
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'At least one item is required.' });
  }

  const pool = getPool();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. Idempotency check
    if (idempotency_key) {
      const [existing] = await conn.query('SELECT * FROM purchases WHERE idempotency_key = ?', [idempotency_key]);
      if (existing.length > 0) {
        await conn.commit();
        const p = existing[0];
        const [itemsRows] = await pool.query('SELECT * FROM purchase_items WHERE purchase_id = ?', [p.id]);
        p.items = itemsRows;
        return res.json({ id: p.id, ...p, purchase: p, is_duplicate: true });
      }
    }

    // 2. Validate customer
    const [custRows] = await conn.query('SELECT * FROM customers WHERE id = ? FOR UPDATE', [customer_id]);
    if (custRows.length === 0) {
      throw new Error(`Customer with ID ${customer_id} does not exist.`);
    }
    const customer = custRows[0];
    if (!customer.is_active) {
      throw new Error(`Customer ${customer.name} is inactive.`);
    }

    // 3. Process items and calculate subtotal
    let subtotal = 0;
    const processedItems = [];

    for (const it of items) {
      let prodId = it.product_id || it.product;
      let prodName = '';
      let prodSku = '';
      let unitPrice = 0;

      if (!prodId && it.custom_name && it.custom_price !== undefined) {
        // One-off custom item
        unitPrice = parseFloat(it.custom_price);
        prodName = it.custom_name.trim();
        prodSku = 'CUSTOM';
      } else if (prodId) {
        const [pRows] = await conn.query('SELECT * FROM products WHERE id = ?', [prodId]);
        if (pRows.length === 0) throw new Error(`Product ID ${prodId} not found.`);
        const prod = pRows[0];
        unitPrice = parseFloat(prod.unit_price);
        prodName = prod.name;
        prodSku = prod.sku;
      } else {
        unitPrice = parseFloat(it.unit_price || 0);
        prodName = (it.name || 'Store Item').trim();
        prodSku = 'MANUAL';
      }

      const qty = parseInt(it.quantity || 1, 10);
      const lineTotal = unitPrice * qty;
      subtotal += lineTotal;

      processedItems.push({
        product_id: prodId || null,
        product_name_snapshot: prodName,
        product_sku_snapshot: prodSku,
        unit_price: unitPrice,
        quantity: qty,
        line_total: lineTotal
      });
    }

    const discount = parseFloat(discount_amount || 0);
    const tax = parseFloat(tax_amount || 0);
    const finalAmount = Math.max(0, subtotal - discount + tax);

    // Rule: ₹100 = 1 loyalty point for customer sales
    const pointsEarned = recordType === 'sale' ? Math.floor(finalAmount / 100) : 0;

    const customInv = (invoice_number || bill_no || '').trim();
    const invoiceNum = customInv || await getNextInvoiceNumber(conn, recordType);

    // Insert purchase / sale
    const [purchRes] = await conn.query(
      `INSERT INTO purchases (invoice_number, customer_id, record_type, subtotal, discount_amount, tax_amount, final_amount, points_earned, status, created_by_id, idempotency_key)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?, ?)`,
      [invoiceNum, customer_id, recordType, subtotal, discount, tax, finalAmount, pointsEarned, req.user.user_id, idempotency_key || null]
    );
    const purchaseId = purchRes.insertId;

    // Insert purchase items
    for (const pItem of processedItems) {
      await conn.query(
        `INSERT INTO purchase_items (purchase_id, product_id, product_name_snapshot, product_sku_snapshot, unit_price, quantity, line_total)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [purchaseId, pItem.product_id, pItem.product_name_snapshot, pItem.product_sku_snapshot, pItem.unit_price, pItem.quantity, pItem.line_total]
      );
    }

    // Update customer loyalty points (for sales)
    const previousPoints = customer.total_loyalty_points || 0;
    const updatedPoints = previousPoints + pointsEarned;

    if (pointsEarned > 0) {
      await conn.query('UPDATE customers SET total_loyalty_points = ? WHERE id = ?', [updatedPoints, customer_id]);
      await conn.query(
        `INSERT INTO loyalty_transactions (customer_id, purchase_id, transaction_type, points_change, description, resulting_balance, created_by_id)
         VALUES (?, ?, 'award', ?, ?, ?, ?)`,
        [customer_id, purchaseId, pointsEarned, `Loyalty reward for bill ${invoiceNum} (Final amount ₹${finalAmount})`, updatedPoints, req.user.user_id]
      );
    }

    await conn.commit();

    const [savedPurch] = await pool.query(
      `SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
       FROM purchases p JOIN customers c ON p.customer_id = c.id WHERE p.id = ?`,
      [purchaseId]
    );
    const purchaseData = savedPurch[0];
    purchaseData.items = processedItems;

    res.status(201).json({
      id: purchaseId,
      ...purchaseData,
      purchase: purchaseData,
      is_duplicate: false,
      previous_points: previousPoints,
      points_earned: pointsEarned,
      updated_points: updatedPoints,
      message: `${recordType === 'sale' ? 'Sale Bill' : 'Purchase Order'} ${invoiceNum} saved successfully.`
    });
  } catch (err) {
    await conn.rollback();
    console.error('Purchase creation error:', err);
    res.status(400).json({ error: err.message || 'Failed to complete transaction.' });
  } finally {
    conn.release();
  }
});

// GET /api/purchases/:id/
router.get('/api/purchases/:id/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [pRows] = await pool.query(
      `SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
       FROM purchases p JOIN customers c ON p.customer_id = c.id WHERE p.id = ?`,
      [req.params.id]
    );
    if (pRows.length === 0) return res.status(404).json({ detail: 'Purchase not found.' });
    const purchase = pRows[0];
    const [items] = await pool.query('SELECT * FROM purchase_items WHERE purchase_id = ?', [purchase.id]);
    purchase.items = items;
    res.json(purchase);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// PATCH /api/purchases/:id/ - Edit bill no, amount, points
router.patch('/api/purchases/:id/', authMiddleware, async (req, res) => {
  const pool = getPool();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [pRows] = await conn.query('SELECT * FROM purchases WHERE id = ? FOR UPDATE', [req.params.id]);
    if (pRows.length === 0) throw new Error('Purchase not found.');
    const purchase = pRows[0];

    const newInvoice = req.body.invoice_number || req.body.bill_no;
    const newAmount = req.body.final_amount !== undefined ? req.body.final_amount : req.body.amount;
    let newPoints = req.body.points_earned !== undefined ? req.body.points_earned : req.body.points;

    // 1. Bill no check
    if (newInvoice !== undefined) {
      const invStr = String(newInvoice).trim();
      if (!invStr) throw new Error('Bill number cannot be blank.');
      if (invStr !== purchase.invoice_number) {
        const [chk] = await conn.query('SELECT id FROM purchases WHERE invoice_number = ? AND id != ?', [invStr, purchase.id]);
        if (chk.length > 0) throw new Error(`Bill number '${invStr}' already exists.`);
        await conn.query('UPDATE purchases SET invoice_number = ? WHERE id = ?', [invStr, purchase.id]);
      }
    }

    // 2. Amount update
    if (newAmount !== undefined) {
      const decAmount = parseFloat(newAmount);
      if (isNaN(decAmount) || decAmount < 0) throw new Error('Amount cannot be negative.');
      await conn.query('UPDATE purchases SET final_amount = ?, subtotal = ? WHERE id = ?', [decAmount, decAmount, purchase.id]);
      await conn.query('UPDATE purchase_items SET unit_price = ?, line_total = ? WHERE purchase_id = ? LIMIT 1', [decAmount, decAmount, purchase.id]);
    }

    // 3. Points update
    if (newPoints !== undefined) {
      const intPoints = parseInt(newPoints, 10);
      if (isNaN(intPoints) || intPoints < 0) throw new Error('Points cannot be negative.');
      const oldPoints = purchase.points_earned;
      const diff = intPoints - oldPoints;

      await conn.query('UPDATE purchases SET points_earned = ? WHERE id = ?', [intPoints, purchase.id]);

      if (diff !== 0) {
        const [cRows] = await conn.query('SELECT * FROM customers WHERE id = ? FOR UPDATE', [purchase.customer_id]);
        const cust = cRows[0];
        const newTotal = Math.max(0, cust.total_loyalty_points + diff);
        await conn.query('UPDATE customers SET total_loyalty_points = ? WHERE id = ?', [newTotal, cust.id]);

        const [txRows] = await conn.query('SELECT * FROM loyalty_transactions WHERE purchase_id = ? LIMIT 1', [purchase.id]);
        if (txRows.length > 0) {
          await conn.query(
            `UPDATE loyalty_transactions SET points_change = ?, resulting_balance = ?, description = ? WHERE id = ?`,
            [intPoints, newTotal, `Updated loyalty points for bill ${newInvoice || purchase.invoice_number}`, txRows[0].id]
          );
        } else {
          await conn.query(
            `INSERT INTO loyalty_transactions (customer_id, purchase_id, transaction_type, points_change, description, resulting_balance, created_by_id)
             VALUES (?, ?, 'award', ?, ?, ?, ?)`,
            [cust.id, purchase.id, intPoints, `Updated loyalty reward for bill ${newInvoice || purchase.invoice_number}`, newTotal, req.user.user_id]
          );
        }
      }
    }

    await conn.commit();

    const [updated] = await pool.query(
      `SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
       FROM purchases p JOIN customers c ON p.customer_id = c.id WHERE p.id = ?`,
      [purchase.id]
    );
    const [items] = await pool.query('SELECT * FROM purchase_items WHERE purchase_id = ?', [purchase.id]);
    const resData = updated[0];
    resData.items = items;
    resData.message = `Bill updated successfully.`;
    res.json(resData);
  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// GET /api/purchases/:id/bill/
router.get(['/api/purchases/:id/bill/', '/api/purchases/:id/print-data/'], authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [pRows] = await pool.query(
      `SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone, c.email as customer_email, c.address as customer_address, c.total_loyalty_points as customer_current_points
       FROM purchases p JOIN customers c ON p.customer_id = c.id WHERE p.id = ?`,
      [req.params.id]
    );
    if (pRows.length === 0) return res.status(404).json({ detail: 'Purchase not found.' });
    const p = pRows[0];
    const [items] = await pool.query('SELECT * FROM purchase_items WHERE purchase_id = ?', [p.id]);

    const curPts = Number(p.customer_current_points) || 0;
    const earnedPts = Number(p.points_earned) || 0;
    const prevPts = Math.max(0, curPts - earnedPts);

    const formattedDate = new Date(p.created_at).toLocaleString('en-IN', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });

    const mappedItems = items.map(it => ({
      name: it.product_name_snapshot,
      sku: it.product_sku_snapshot,
      quantity: it.quantity,
      unit_price: it.unit_price,
      total: it.line_total,
      line_total: it.line_total
    }));

    res.json({
      id: p.id,
      bill_id: p.id,
      invoice_number: p.invoice_number,
      record_type: p.record_type || 'sale',
      date: p.created_at,
      purchase_date: formattedDate,
      created_at: p.created_at,
      status: p.status,

      // Flat monetary properties
      subtotal: p.subtotal,
      discount_amount: p.discount_amount,
      tax_amount: p.tax_amount,
      final_amount: p.final_amount,

      // Flat loyalty properties
      points_earned: earnedPts,
      previous_points: prevPts,
      updated_points: curPts,

      customer: {
        id: p.customer_id,
        name: p.customer_name,
        code: p.customer_code,
        customer_code: p.customer_code,
        phone: p.customer_phone,
        phone_number: p.customer_phone,
        email: p.customer_email || 'N/A',
        address: p.customer_address,
        total_points: curPts
      },
      items: mappedItems,
      pricing: {
        subtotal: p.subtotal,
        discount: p.discount_amount,
        tax: p.tax_amount,
        final_amount: p.final_amount
      },
      loyalty: {
        points_earned: earnedPts,
        previous_points: prevPts,
        updated_points: curPts
      }
    });
  } catch (err) {
    console.error('Bill retrieval error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/purchases/:id/cancel/
router.post('/api/purchases/:id/cancel/', authMiddleware, async (req, res) => {
  const pool = getPool();
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [pRows] = await conn.query('SELECT * FROM purchases WHERE id = ? FOR UPDATE', [req.params.id]);
    if (pRows.length === 0) throw new Error('Purchase not found.');
    const p = pRows[0];
    if (p.status === 'cancelled') throw new Error('This purchase has already been cancelled.');

    if (p.points_earned > 0) {
      const [cRows] = await conn.query('SELECT * FROM customers WHERE id = ? FOR UPDATE', [p.customer_id]);
      const cust = cRows[0];
      const newBalance = Math.max(0, cust.total_loyalty_points - p.points_earned);
      await conn.query('UPDATE customers SET total_loyalty_points = ? WHERE id = ?', [newBalance, cust.id]);

      await conn.query(
        `INSERT INTO loyalty_transactions (customer_id, purchase_id, transaction_type, points_change, description, resulting_balance, created_by_id)
         VALUES (?, ?, 'reversal', ?, ?, ?, ?)`,
        [cust.id, p.id, -p.points_earned, `Points reversed for cancelled purchase ${p.invoice_number}`, newBalance, req.user.user_id]
      );
    }

    await conn.query('UPDATE purchases SET status = "cancelled" WHERE id = ?', [p.id]);
    await conn.commit();
    res.json({ message: `Purchase ${p.invoice_number} cancelled successfully.` });
  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// =============================================================
// 5. LOYALTY ROUTES (/api/loyalty)
// =============================================================

// GET /api/loyalty/transactions/
router.get('/api/loyalty/transactions/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const customerId = req.query.customer;
    const transType = req.query.type;

    let query = `
      SELECT lt.*, c.name as customer_name, c.customer_code, p.invoice_number as purchase_invoice
      FROM loyalty_transactions lt
      JOIN customers c ON lt.customer_id = c.id
      LEFT JOIN purchases p ON lt.purchase_id = p.id
      WHERE 1=1
    `;
    const params = [];
    if (customerId) {
      query += ' AND lt.customer_id = ?';
      params.push(customerId);
    }
    if (transType) {
      query += ' AND lt.transaction_type = ?';
      params.push(transType);
    }
    query += ' ORDER BY lt.created_at DESC';

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// POST /api/loyalty/preview/
router.post('/api/loyalty/preview/', authMiddleware, (req, res) => {
  const amount = parseFloat(req.body.amount || req.body.final_amount || 0);
  const points = Math.max(0, Math.floor(amount / 100));
  res.json({
    amount: amount,
    points_to_earn: points,
    rule: '₹100 = 1 loyalty point'
  });
});

// =============================================================
// 6. DASHBOARD ROUTES (/api/dashboard)
// =============================================================

// GET /api/dashboard/summary/
router.get('/api/dashboard/summary/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const [custCnt] = await pool.query('SELECT COUNT(*) as cnt FROM customers WHERE is_active = 1');

    // 1. Customer Sales Metrics (record_type = 'sale')
    const [salesToday] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'sale' AND DATE(created_at) = CURDATE()
    `);
    const [salesWeek] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'sale' AND YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1)
    `);
    const [salesMonth] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'sale' AND YEAR(created_at) = YEAR(CURDATE()) AND MONTH(created_at) = MONTH(CURDATE())
    `);
    const [salesTotal] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val, COALESCE(SUM(points_earned), 0) as pts
      FROM purchases WHERE status = 'completed' AND record_type = 'sale'
    `);

    // 2. Store Purchases Metrics (record_type = 'purchase')
    const [purchToday] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'purchase' AND DATE(created_at) = CURDATE()
    `);
    const [purchWeek] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'purchase' AND YEARWEEK(created_at, 1) = YEARWEEK(CURDATE(), 1)
    `);
    const [purchMonth] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'purchase' AND YEAR(created_at) = YEAR(CURDATE()) AND MONTH(created_at) = MONTH(CURDATE())
    `);
    const [purchTotal] = await pool.query(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(final_amount), 0) as val
      FROM purchases WHERE status = 'completed' AND record_type = 'purchase'
    `);

    // 3. Past 7-Day Performance Trend
    const dailyTrends = [];
    const now = new Date();
    const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, '0');
      const dt = String(d.getDate()).padStart(2, '0');
      const dateStr = `${y}-${m}-${dt}`;

      const [dayRow] = await pool.query(`
        SELECT 
          COALESCE(SUM(CASE WHEN record_type = 'sale' THEN final_amount ELSE 0 END), 0) as sales_val,
          SUM(CASE WHEN record_type = 'sale' THEN 1 ELSE 0 END) as sales_cnt,
          COALESCE(SUM(CASE WHEN record_type = 'purchase' THEN final_amount ELSE 0 END), 0) as purch_val,
          SUM(CASE WHEN record_type = 'purchase' THEN 1 ELSE 0 END) as purch_cnt,
          COALESCE(SUM(final_amount), 0) as tot_val,
          COUNT(*) as tot_cnt
        FROM purchases WHERE status = 'completed' AND DATE(created_at) = ?
      `, [dateStr]);

      const r = dayRow[0];
      const salesVal = parseFloat(r.sales_val) || 0;
      const purchVal = parseFloat(r.purch_val) || 0;
      const totVal = parseFloat(r.tot_val) || 0;
      const totCnt = Number(r.tot_cnt) || 0;

      dailyTrends.push({
        date: dateStr,
        label: `${d.getDate()} ${monthNames[d.getMonth()]}`,
        day_name: dayNames[d.getDay()],
        total_amount: totVal,
        purchases_count: totCnt,
        sales_amount: salesVal,
        sales_count: Number(r.sales_cnt) || 0,
        purchase_amount: purchVal,
        purchase_count: Number(r.purch_cnt) || 0,
        is_today: i === 0
      });
    }

    const todaySalesVal = parseFloat(salesToday[0].val) || 0;
    const weekSalesVal = parseFloat(salesWeek[0].val) || 0;
    const monthSalesVal = parseFloat(salesMonth[0].val) || 0;
    const totalSalesVal = parseFloat(salesTotal[0].val) || 0;

    const todayPurchVal = parseFloat(purchToday[0].val) || 0;
    const weekPurchVal = parseFloat(purchWeek[0].val) || 0;
    const monthPurchVal = parseFloat(purchMonth[0].val) || 0;
    const totalPurchVal = parseFloat(purchTotal[0].val) || 0;

    res.json({
      total_customers: custCnt[0].cnt || 0,

      // Customer Sales (Customer Side)
      sales: {
        today_value: todaySalesVal.toFixed(2),
        today_count: Number(salesToday[0].cnt) || 0,
        week_value: weekSalesVal.toFixed(2),
        week_count: Number(salesWeek[0].cnt) || 0,
        month_value: monthSalesVal.toFixed(2),
        month_count: Number(salesMonth[0].cnt) || 0,
        total_value: totalSalesVal.toFixed(2),
        total_count: Number(salesTotal[0].cnt) || 0,
        points_awarded: Number(salesTotal[0].pts) || 0
      },

      // Store Purchases (Procurement Side)
      purchases: {
        today_value: todayPurchVal.toFixed(2),
        today_count: Number(purchToday[0].cnt) || 0,
        week_value: weekPurchVal.toFixed(2),
        week_count: Number(purchWeek[0].cnt) || 0,
        month_value: monthPurchVal.toFixed(2),
        month_count: Number(purchMonth[0].cnt) || 0,
        total_value: totalPurchVal.toFixed(2),
        total_count: Number(purchTotal[0].cnt) || 0
      },

      // Top-level fields for direct backward compatibility
      today_sales_value: todaySalesVal.toFixed(2),
      today_sales_count: Number(salesToday[0].cnt) || 0,
      week_sales_value: weekSalesVal.toFixed(2),
      week_sales_count: Number(salesWeek[0].cnt) || 0,
      month_sales_value: monthSalesVal.toFixed(2),
      month_sales_count: Number(salesMonth[0].cnt) || 0,
      total_sales_value: totalSalesVal.toFixed(2),
      total_sales_count: Number(salesTotal[0].cnt) || 0,

      today_purchase_value: todayPurchVal.toFixed(2),
      today_purchases_count: Number(purchToday[0].cnt) || 0,
      week_purchase_value: weekPurchVal.toFixed(2),
      week_purchases_count: Number(purchWeek[0].cnt) || 0,
      month_purchase_value: monthPurchVal.toFixed(2),
      month_purchases_count: Number(purchMonth[0].cnt) || 0,
      total_purchase_value: totalPurchVal.toFixed(2),
      total_purchases: Number(purchTotal[0].cnt) || 0,

      daily_trends: dailyTrends
    });
  } catch (err) {
    console.error('Dashboard summary error:', err);
    res.status(500).json({ error: 'Database error in dashboard summary.' });
  }
});

// GET /api/dashboard/recent-purchases/
router.get('/api/dashboard/recent-purchases/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const search = (req.query.search || '').trim();
    const recordType = (req.query.record_type || req.query.type || '').trim();

    let query = `
      SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
      FROM purchases p
      JOIN customers c ON p.customer_id = c.id
      WHERE 1=1
    `;
    const params = [];

    if (recordType) {
      query += ' AND p.record_type = ?';
      params.push(recordType);
    }
    if (search) {
      query += ' AND (p.invoice_number LIKE ? OR c.name LIKE ? OR c.customer_code LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY p.created_at DESC LIMIT 15';

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Dashboard recent purchases error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// =============================================================
// 7. REPORTS ROUTES (/api/reports)
// =============================================================

// Helper for Date Bounds in Reports
function getReportDateBounds(periodParam, dateFromStr, dateToStr) {
  const now = new Date();
  let dFrom = null;
  let dTo = null;

  if (dateFromStr) {
    const parsed = new Date(dateFromStr);
    if (!isNaN(parsed.getTime())) dFrom = dateFromStr.slice(0, 10);
  }
  if (dateToStr) {
    const parsed = new Date(dateToStr);
    if (!isNaN(parsed.getTime())) dTo = dateToStr.slice(0, 10);
  }

  const p = (periodParam || '').toLowerCase().trim();
  if (!dFrom && !dTo && p) {
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, '0');
    const d = String(now.getDate()).padStart(2, '0');
    const todayStr = `${y}-${m}-${d}`;

    if (p === 'day' || p === 'today') {
      dFrom = todayStr;
      dTo = todayStr;
    } else if (p === 'week' || p === 'weekly') {
      const dayOfWeek = now.getDay();
      const distanceToMon = (dayOfWeek + 6) % 7;
      const monday = new Date(now);
      monday.setDate(now.getDate() - distanceToMon);
      const my = monday.getFullYear();
      const mm = String(monday.getMonth() + 1).padStart(2, '0');
      const md = String(monday.getDate()).padStart(2, '0');
      dFrom = `${my}-${mm}-${md}`;
      dTo = todayStr;
    } else if (p === 'month' || p === 'monthly') {
      dFrom = `${y}-${m}-01`;
      dTo = todayStr;
    } else if (p === 'year' || p === 'yearly') {
      dFrom = `${y}-01-01`;
      dTo = todayStr;
    }
  }

  return { dFrom, dTo, period: p || 'custom' };
}

// GET /api/reports/summary/
router.get('/api/reports/summary/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const { dFrom, dTo, period } = getReportDateBounds(req.query.period, req.query.date_from, req.query.date_to);
    const customer = (req.query.customer || '').trim();
    const customerSearch = (req.query.customer_search || req.query.customer_code || '').trim();

    let whereSql = " WHERE p.status = 'completed'";
    const whereParams = [];

    if (dFrom) {
      whereSql += ' AND DATE(p.created_at) >= ?';
      whereParams.push(dFrom);
    }
    if (dTo) {
      whereSql += ' AND DATE(p.created_at) <= ?';
      whereParams.push(dTo);
    }
    if (customer) {
      whereSql += ' AND p.customer_id = ?';
      whereParams.push(customer);
    } else if (customerSearch) {
      const cs = `%${customerSearch}%`;
      whereSql += ' AND (c.customer_code LIKE ? OR c.name LIKE ? OR c.phone_number LIKE ?)';
      whereParams.push(cs, cs, cs);
    }

    // 1. Customer Sales metrics (record_type = 'sale')
    const [sStats] = await pool.query(`
      SELECT 
        COUNT(p.id) as total_count,
        COALESCE(SUM(p.final_amount), 0) as total_val,
        COALESCE(AVG(p.final_amount), 0) as avg_val,
        SUM(CASE WHEN p.points_earned > 0 THEN 1 ELSE 0 END) as qualifying_count
      FROM purchases p
      JOIN customers c ON p.customer_id = c.id
      ${whereSql} AND p.record_type = 'sale'
    `, whereParams);

    const [sUnits] = await pool.query(`
      SELECT COALESCE(SUM(pi.quantity), 0) as total_qty
      FROM purchase_items pi
      JOIN purchases p ON pi.purchase_id = p.id
      JOIN customers c ON p.customer_id = c.id
      ${whereSql} AND p.record_type = 'sale'
    `, whereParams);

    // 2. Store Purchases metrics (record_type = 'purchase')
    const [pStats] = await pool.query(`
      SELECT 
        COUNT(p.id) as total_count,
        COALESCE(SUM(p.final_amount), 0) as total_val,
        COALESCE(AVG(p.final_amount), 0) as avg_val
      FROM purchases p
      JOIN customers c ON p.customer_id = c.id
      ${whereSql} AND p.record_type = 'purchase'
    `, whereParams);

    const [pUnits] = await pool.query(`
      SELECT COALESCE(SUM(pi.quantity), 0) as total_qty
      FROM purchase_items pi
      JOIN purchases p ON pi.purchase_id = p.id
      JOIN customers c ON p.customer_id = c.id
      ${whereSql} AND p.record_type = 'purchase'
    `, whereParams);

    // 3. Loyalty metrics
    let loyaltyWhere = ' WHERE 1=1';
    const loyaltyParams = [];
    if (dFrom) {
      loyaltyWhere += ' AND DATE(lt.created_at) >= ?';
      loyaltyParams.push(dFrom);
    }
    if (dTo) {
      loyaltyWhere += ' AND DATE(lt.created_at) <= ?';
      loyaltyParams.push(dTo);
    }
    if (customer) {
      loyaltyWhere += ' AND lt.customer_id = ?';
      loyaltyParams.push(customer);
    } else if (customerSearch) {
      const cs = `%${customerSearch}%`;
      loyaltyWhere += ' AND (c.customer_code LIKE ? OR c.name LIKE ? OR c.phone_number LIKE ?)';
      loyaltyParams.push(cs, cs, cs);
    }

    const [lStats] = await pool.query(`
      SELECT 
        COALESCE(SUM(CASE WHEN lt.transaction_type = 'award' THEN lt.points_change ELSE 0 END), 0) as pts_awarded,
        COALESCE(SUM(CASE WHEN lt.transaction_type = 'reversal' THEN ABS(lt.points_change) ELSE 0 END), 0) as pts_reversed,
        COUNT(DISTINCT CASE WHEN lt.transaction_type = 'award' THEN lt.customer_id ELSE NULL END) as custs_with_points
      FROM loyalty_transactions lt
      JOIN customers c ON lt.customer_id = c.id
      ${loyaltyWhere}
    `, loyaltyParams);

    const totalSales = Number(sStats[0].total_count) || 0;
    const totalSalesVal = Number(sStats[0].total_val) || 0;
    const avgSalesVal = Number(sStats[0].avg_val) || 0;
    const qualifyingSales = Number(sStats[0].qualifying_count) || 0;
    const totalUnitsSold = Number(sUnits[0].total_qty) || 0;

    const totalPurchases = Number(pStats[0].total_count) || 0;
    const totalPurchVal = Number(pStats[0].total_val) || 0;
    const avgPurchVal = Number(pStats[0].avg_val) || 0;
    const totalUnitsPurchased = Number(pUnits[0].total_qty) || 0;

    const ptsAwarded = Number(lStats[0].pts_awarded) || 0;
    const ptsReversed = Number(lStats[0].pts_reversed) || 0;
    const netPoints = ptsAwarded - ptsReversed;
    const customersWithPoints = Number(lStats[0].custs_with_points) || 0;

    // 4. Periodic breakdown (Optimized: single aggregated query)
    const breakdown = [];
    const now = new Date();
    const curYear = now.getFullYear();

    if (period === 'year') {
      const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const [yearRows] = await pool.query(`
        SELECT 
          MONTH(p.created_at) as month_num,
          COALESCE(SUM(CASE WHEN p.record_type = 'sale' THEN p.final_amount ELSE 0 END), 0) as sales_val,
          SUM(CASE WHEN p.record_type = 'sale' THEN 1 ELSE 0 END) as sales_cnt,
          COALESCE(SUM(CASE WHEN p.record_type = 'purchase' THEN p.final_amount ELSE 0 END), 0) as purch_val,
          SUM(CASE WHEN p.record_type = 'purchase' THEN 1 ELSE 0 END) as purch_cnt,
          COALESCE(SUM(p.final_amount), 0) as total_sales,
          COUNT(p.id) as orders_count,
          COALESCE(SUM(p.points_earned), 0) as points_awarded
        FROM purchases p
        JOIN customers c ON p.customer_id = c.id
        ${whereSql} AND YEAR(p.created_at) = ?
        GROUP BY MONTH(p.created_at)
      `, [...whereParams, curYear]);

      const monthMap = {};
      yearRows.forEach(r => { monthMap[r.month_num] = r; });

      for (let m = 1; m <= 12; m++) {
        const row = monthMap[m] || {};
        breakdown.push({
          period: `${monthNames[m - 1]} ${curYear}`,
          total_sales: parseFloat(row.total_sales || 0).toFixed(2),
          orders_count: Number(row.orders_count || 0),
          sales_val: parseFloat(row.sales_val || 0).toFixed(2),
          sales_count: Number(row.sales_cnt || 0),
          purchase_val: parseFloat(row.purch_val || 0).toFixed(2),
          purchase_count: Number(row.purch_cnt || 0),
          points_awarded: Number(row.points_awarded || 0)
        });
      }
    } else if (dFrom && dTo) {
      const [dayRows] = await pool.query(`
        SELECT 
          DATE_FORMAT(p.created_at, '%Y-%m-%d') as day_str,
          COALESCE(SUM(CASE WHEN p.record_type = 'sale' THEN p.final_amount ELSE 0 END), 0) as sales_val,
          SUM(CASE WHEN p.record_type = 'sale' THEN 1 ELSE 0 END) as sales_cnt,
          COALESCE(SUM(CASE WHEN p.record_type = 'purchase' THEN p.final_amount ELSE 0 END), 0) as purch_val,
          SUM(CASE WHEN p.record_type = 'purchase' THEN 1 ELSE 0 END) as purch_cnt,
          COALESCE(SUM(p.final_amount), 0) as total_sales,
          COUNT(p.id) as orders_count,
          COALESCE(SUM(p.points_earned), 0) as points_awarded
        FROM purchases p
        JOIN customers c ON p.customer_id = c.id
        ${whereSql}
        GROUP BY DATE_FORMAT(p.created_at, '%Y-%m-%d')
        ORDER BY day_str ASC
      `, whereParams);

      const dayMap = {};
      dayRows.forEach(r => { dayMap[r.day_str] = r; });

      const start = new Date(dFrom);
      const end = new Date(dTo);
      const diffDays = Math.ceil(Math.abs(end - start) / (1000 * 60 * 60 * 24));

      if (diffDays <= 62) {
        let cur = new Date(start);
        while (cur <= end) {
          const cy = cur.getFullYear();
          const cm = String(cur.getMonth() + 1).padStart(2, '0');
          const cd = String(cur.getDate()).padStart(2, '0');
          const dateStr = `${cy}-${cm}-${cd}`;
          const r = dayMap[dateStr] || {};

          const dayLabel = cur.toLocaleDateString('en-US', { day: '2-digit', month: 'short', weekday: 'short' });
          breakdown.push({
            period: dayLabel,
            date: dateStr,
            total_sales: parseFloat(r.total_sales || 0).toFixed(2),
            orders_count: Number(r.orders_count || 0),
            sales_val: parseFloat(r.sales_val || 0).toFixed(2),
            sales_count: Number(r.sales_cnt || 0),
            purchase_val: parseFloat(r.purch_val || 0).toFixed(2),
            purchase_count: Number(r.purch_cnt || 0),
            points_awarded: Number(r.points_awarded || 0)
          });
          cur.setDate(cur.getDate() + 1);
        }
      }
    }

    res.json({
      // Distinct Customer Sales Board
      sales_summary: {
        total_sales: totalSales,
        total_sales_value: totalSalesVal.toFixed(2),
        average_sales_value: avgSalesVal.toFixed(2),
        qualifying_sales: qualifyingSales,
        total_units_sold: totalUnitsSold
      },

      // Distinct Store Purchases Board
      purchase_summary: {
        total_purchases: totalPurchases,
        total_purchase_value: totalPurchVal.toFixed(2),
        average_purchase_value: avgPurchVal.toFixed(2),
        total_units_purchased: totalUnitsPurchased,
        // Also support old keys so existing components work
        qualifying_purchases: totalPurchases,
        total_units_sold: totalUnitsPurchased
      },

      // Loyalty Summary Board
      loyalty_summary: {
        total_points_awarded: ptsAwarded,
        total_points_reversed: ptsReversed,
        net_points_awarded: netPoints,
        customers_with_points: customersWithPoints
      },

      periodic_breakdown: breakdown,
      active_bounds: {
        date_from: dFrom,
        date_to: dTo,
        period: period || 'custom'
      }
    });
  } catch (err) {
    console.error('Reports summary error:', err);
    res.status(500).json({ error: 'Database error in reports summary.' });
  }
});

// GET /api/reports/purchases/
router.get('/api/reports/purchases/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const { dFrom, dTo, period } = getReportDateBounds(req.query.period, req.query.date_from, req.query.date_to);
    const customer = (req.query.customer || '').trim();
    const customerSearch = (req.query.customer_search || req.query.customer_code || '').trim();
    const statusParam = (req.query.status || '').trim();
    const recordType = (req.query.record_type || req.query.type || '').trim();
    const qualifyingOnly = req.query.qualifying_only === 'true' || req.query.qualifying_only === '1';
    const ordering = (req.query.ordering || '-created_at').trim();
    const exportCsv = (req.query.export || '').toLowerCase() === 'csv';

    let query = `
      SELECT p.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone
      FROM purchases p
      JOIN customers c ON p.customer_id = c.id
      WHERE 1=1
    `;
    const params = [];

    if (recordType) {
      query += ' AND p.record_type = ?';
      params.push(recordType);
    }
    if (dFrom) {
      query += ' AND DATE(p.created_at) >= ?';
      params.push(dFrom);
    }
    if (dTo) {
      query += ' AND DATE(p.created_at) <= ?';
      params.push(dTo);
    }
    if (customer) {
      query += ' AND p.customer_id = ?';
      params.push(customer);
    } else if (customerSearch) {
      const cs = `%${customerSearch}%`;
      query += ' AND (c.customer_code LIKE ? OR c.name LIKE ? OR c.phone_number LIKE ?)';
      params.push(cs, cs, cs);
    }
    if (statusParam) {
      query += ' AND p.status = ?';
      params.push(statusParam.toLowerCase());
    }
    if (qualifyingOnly) {
      query += ' AND p.points_earned > 0';
    }

    // Ordering
    let orderBy = 'ORDER BY p.created_at DESC';
    if (ordering === 'points_earned' || ordering === '-points_earned') {
      orderBy = ordering === 'points_earned' ? 'ORDER BY p.points_earned ASC, p.created_at DESC' : 'ORDER BY p.points_earned DESC, p.created_at DESC';
    } else if (ordering === 'created_at') {
      orderBy = 'ORDER BY p.created_at ASC';
    } else if (ordering === '-final_amount') {
      orderBy = 'ORDER BY p.final_amount DESC, p.created_at DESC';
    } else if (ordering === 'final_amount') {
      orderBy = 'ORDER BY p.final_amount ASC, p.created_at DESC';
    }
    query += ` ${orderBy}`;

    const [rows] = await pool.query(query, params);

    // Fetch items snapshot for each purchase
    for (const p of rows) {
      const [itRows] = await pool.query('SELECT product_name_snapshot, quantity, line_total FROM purchase_items WHERE purchase_id = ?', [p.id]);
      p.items = itRows;
      p.total_quantity = itRows.reduce((acc, cur) => acc + (cur.quantity || 1), 0);
      p.items_summary = itRows.map((it) => `${it.product_name_snapshot} (${it.quantity})`).join(', ');
    }

    if (exportCsv) {
      const isSalesExport = recordType === 'sale';
      const filename = isSalesExport ? 'customer_sales_report.csv' : (recordType === 'purchase' ? 'store_purchases_report.csv' : 'transactions_report.csv');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      // UTF-8 BOM for Microsoft Excel
      let csv = '\ufeff';
      csv += isSalesExport ? 'GMINE RETAIL - CUSTOMER SALES REPORT\r\n' : 'GMINE RETAIL - STORE PURCHASES REPORT\r\n';
      csv += '81/10, No TEN, Shopping Mall, Pollachi, Kovai Road, Tamil Nadu - 642 002 | info@gmine.in\r\n';
      csv += `Period: ${dFrom || 'All Time'} to ${dTo || 'Present'},Generated: ${new Date().toLocaleString('en-IN')}\r\n\r\n`;
      csv += 'Bill / Invoice Number,Type,Customer / Supplier Code,Name,Phone,Date & Time,Items Summary,Total Qty,Subtotal (INR),Discount (INR),Tax (INR),Final Amount (INR),Points Earned,Status\r\n';

      let totQty = 0;
      let totSub = 0;
      let totDisc = 0;
      let totTax = 0;
      let totFinal = 0;
      let totPts = 0;

      for (const p of rows) {
        const qty = p.total_quantity || 1;
        const sub = parseFloat(p.subtotal || 0);
        const disc = parseFloat(p.discount_amount || 0);
        const tax = parseFloat(p.tax_amount || 0);
        const fin = parseFloat(p.final_amount || 0);
        const pts = p.points_earned || 0;

        totQty += qty;
        totSub += sub;
        totDisc += disc;
        totTax += tax;
        totFinal += fin;
        totPts += pts;

        const dateStr = new Date(p.created_at).toLocaleString('en-IN');
        const summarySafe = `"${(p.items_summary || '').replace(/"/g, '""')}"`;
        const nameSafe = `"${(p.customer_name || '').replace(/"/g, '""')}"`;
        const typeLabel = p.record_type === 'purchase' ? 'Store Purchase' : 'Customer Sale';

        csv += `${p.invoice_number},${typeLabel},${p.customer_code},${nameSafe},${p.customer_phone || ''},${dateStr},${summarySafe},${qty},${sub.toFixed(2)},${disc.toFixed(2)},${tax.toFixed(2)},${fin.toFixed(2)},${pts},${p.status}\r\n`;
      }

      csv += `TOTALS,,,,,,Total:,${totQty},${totSub.toFixed(2)},${totDisc.toFixed(2)},${totTax.toFixed(2)},${totFinal.toFixed(2)},${totPts},\r\n`;
      return res.send(csv);
    }

    res.json(rows);
  } catch (err) {
    console.error('Reports purchases error:', err);
    res.status(500).json({ error: 'Database error in purchases report.' });
  }
});

// GET /api/reports/loyalty/
router.get('/api/reports/loyalty/', authMiddleware, async (req, res) => {
  try {
    const pool = getPool();
    const { dFrom, dTo, period } = getReportDateBounds(req.query.period, req.query.date_from, req.query.date_to);
    const customer = (req.query.customer || '').trim();
    const customerSearch = (req.query.customer_search || req.query.customer_code || '').trim();
    const typeParam = (req.query.type || '').trim();
    const exportCsv = (req.query.export || '').toLowerCase() === 'csv';

    let query = `
      SELECT lt.*, c.name as customer_name, c.customer_code, c.phone_number as customer_phone, p.invoice_number as purchase_invoice
      FROM loyalty_transactions lt
      JOIN customers c ON lt.customer_id = c.id
      LEFT JOIN purchases p ON lt.purchase_id = p.id
      WHERE 1=1
    `;
    const params = [];

    if (dFrom) {
      query += ' AND DATE(lt.created_at) >= ?';
      params.push(dFrom);
    }
    if (dTo) {
      query += ' AND DATE(lt.created_at) <= ?';
      params.push(dTo);
    }
    if (customer) {
      query += ' AND lt.customer_id = ?';
      params.push(customer);
    } else if (customerSearch) {
      const cs = `%${customerSearch}%`;
      query += ' AND (c.customer_code LIKE ? OR c.name LIKE ? OR c.phone_number LIKE ?)';
      params.push(cs, cs, cs);
    }
    if (typeParam) {
      query += ' AND lt.transaction_type = ?';
      params.push(typeParam.toLowerCase());
    }

    query += ' ORDER BY lt.created_at DESC';

    const [rows] = await pool.query(query, params);

    if (exportCsv) {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="loyalty_activity_report.csv"');
      let csv = '\ufeff';
      csv += 'Date & Time,Customer Code,Customer Name,Invoice,Type,Points Change,Resulting Balance,Description\r\n';

      for (const t of rows) {
        const dateStr = new Date(t.created_at).toLocaleString('en-IN');
        const nameSafe = `"${(t.customer_name || '').replace(/"/g, '""')}"`;
        const descSafe = `"${(t.description || '').replace(/"/g, '""')}"`;
        const invoiceStr = t.purchase_invoice || 'N/A';
        const typeStr = t.transaction_type === 'award' ? 'Points Awarded' : 'Points Reversed';

        csv += `${dateStr},${t.customer_code},${nameSafe},${invoiceStr},${typeStr},${t.points_change},${t.resulting_balance},${descSafe}\r\n`;
      }

      return res.send(csv);
    }

    res.json(rows);
  } catch (err) {
    console.error('Reports loyalty error:', err);
    res.status(500).json({ error: 'Database error in loyalty report.' });
  }
});


// Serve Billing frontend SPA at /billing and its subpaths
router.get(['/billing', '/billing/*', '/dashboard', '/dashboard/*', '/purchases', '/purchases/*', '/customers', '/customers/*', '/reports', '/reports/*'], (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'billing', 'index.html'));
});

module.exports = router;
