const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function generateTokens(user) {
  const payload = {
    user_id: user.id,
    username: user.username || user.email || 'admin',
    is_staff: Boolean(user.is_staff || user.role === 'admin'),
    is_superuser: Boolean(user.is_superuser || user.role === 'admin')
  };
  const access = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  const refresh = jwt.sign(payload, JWT_SECRET, { expiresIn: '14d' });
  return { access, refresh };
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ detail: 'Authentication credentials were not provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      user_id: decoded.user_id || decoded.id || 1,
      username: decoded.username || 'admin',
      is_staff: Boolean(decoded.is_staff || decoded.role === 'admin'),
      is_superuser: Boolean(decoded.is_superuser || decoded.role === 'admin')
    };
    next();
  } catch (err) {
    return res.status(401).json({ detail: 'Given token not valid for any token type', code: 'token_not_valid' });
  }
}

function optionalAuthMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = {
        user_id: decoded.user_id || decoded.id || 1,
        username: decoded.username || 'admin',
        is_staff: Boolean(decoded.is_staff || decoded.role === 'admin'),
        is_superuser: Boolean(decoded.is_superuser || decoded.role === 'admin')
      };
    } catch (e) {
      // ignore
    }
  }
  next();
}

module.exports = {
  JWT_SECRET,
  generateTokens,
  authMiddleware,
  optionalAuthMiddleware
};
