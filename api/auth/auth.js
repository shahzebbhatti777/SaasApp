const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authorization token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = {
      ...user,
      role: user.role || 'user',
      parentId: user.parentId || null,
      accountOwnerId: user.accountOwnerId || user.parentId || user.id,
    };
    next();
  });
}

module.exports = { authenticateToken };
