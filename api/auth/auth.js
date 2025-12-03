const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const MFA_MAX_AGE_MS = 10 * 60 * 1000;

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

async function requireRecentMfa(req, res, next) {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: 'Authorization token required' });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { mfaEnabled: true, lastMfaVerifiedAt: true },
    });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (!user.mfaEnabled) {
      return next();
    }

    if (!user.lastMfaVerifiedAt) {
      return res.status(403).json({ error: 'Recent MFA verification required', mfaRequired: true });
    }

    const ageMs = Date.now() - new Date(user.lastMfaVerifiedAt).getTime();

    if (Number.isNaN(ageMs) || ageMs > MFA_MAX_AGE_MS) {
      return res.status(403).json({ error: 'Recent MFA verification required', mfaRequired: true });
    }

    return next();
  } catch (error) {
    console.error('MFA recency check error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
}

module.exports = { authenticateToken, requireRecentMfa };
