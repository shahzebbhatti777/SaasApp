const express = require('express');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const { authenticateToken } = require('../auth/auth');

const router = express.Router();
const prisma = new PrismaClient();
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.use(authenticateToken);

function ensureParentAccess(req) {
  if (req.user.role === 'sub') {
    return { allowed: false, response: { status: 403, body: { error: 'Sub-accounts cannot manage child accounts' } } };
  }

  const accountOwnerId = req.user.accountOwnerId || req.user.id;
  return { allowed: true, accountOwnerId };
}

router.post('/sub-accounts', async (req, res) => {
  const { email, password, permissions, name } = req.body || {};
  const accessCheck = ensureParentAccess(req);

  if (!accessCheck.allowed) {
    return res.status(accessCheck.response.status).json(accessCheck.response.body);
  }

  if (!email || !password || !EMAIL_REGEX.test(email)) {
    return res.status(400).json({ error: 'Valid email and password are required' });
  }

  try {
    const parent = await prisma.user.findUnique({ where: { id: accessCheck.accountOwnerId } });

    if (!parent) {
      return res.status(404).json({ error: 'Parent account not found' });
    }

    if (parent.accountLocked) {
      return res.status(403).json({ error: 'Account locked by admin' });
    }

    if (!parent.emailVerified) {
      return res.status(403).json({ error: 'Email not verified for parent account' });
    }

    if (parent.forcePasswordReset) {
      return res.status(403).json({ error: 'Password reset required for parent account', mustReset: true });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });

    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const normalizedPermissions = Array.isArray(permissions) ? permissions : [];

    const subAccount = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: name || email.split('@')[0] || 'Sub Account',
        parentId: accessCheck.accountOwnerId,
        role: 'sub',
        permissions: normalizedPermissions,
        emailVerified: true,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        parentId: true,
        permissions: true,
        createdAt: true,
      },
    });

    if (parent.role === 'user') {
      await prisma.user.update({ where: { id: parent.id }, data: { role: 'parent' } });
    }

    return res.status(201).json({ subAccount });
  } catch (error) {
    console.error('Sub-account creation error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/sub-accounts', async (req, res) => {
  const accessCheck = ensureParentAccess(req);

  if (!accessCheck.allowed) {
    return res.status(accessCheck.response.status).json(accessCheck.response.body);
  }

  try {
    const subAccounts = await prisma.user.findMany({
      where: { parentId: accessCheck.accountOwnerId },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        permissions: true,
        createdAt: true,
        accountLocked: true,
        forcePasswordReset: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return res.json({ subAccounts });
  } catch (error) {
    console.error('Sub-account list error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/sub-accounts/:id', async (req, res) => {
  const accessCheck = ensureParentAccess(req);

  if (!accessCheck.allowed) {
    return res.status(accessCheck.response.status).json(accessCheck.response.body);
  }

  const { id } = req.params;

  if (id === accessCheck.accountOwnerId) {
    return res.status(400).json({ error: 'Cannot delete the parent account from this endpoint' });
  }

  try {
    const subAccount = await prisma.user.findFirst({ where: { id, parentId: accessCheck.accountOwnerId } });

    if (!subAccount) {
      return res.status(404).json({ error: 'Sub-account not found' });
    }

    await prisma.$transaction([
      prisma.refreshToken.deleteMany({ where: { userId: id } }),
      prisma.sessionLog.deleteMany({ where: { userId: id } }),
      prisma.passwordReset.deleteMany({ where: { userId: id } }),
      prisma.emailVerificationToken.deleteMany({ where: { userId: id } }),
      prisma.auditLog.deleteMany({ where: { OR: [{ adminId: id }, { userId: id }] } }),
      prisma.user.delete({ where: { id } }),
    ]);

    return res.json({ message: 'Sub-account removed' });
  } catch (error) {
    console.error('Sub-account deletion error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
