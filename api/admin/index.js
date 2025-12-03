const express = require('express');
const { PrismaClient } = require('@prisma/client');
const { authenticateToken } = require('../auth/auth');

const router = express.Router();
const prisma = new PrismaClient();

router.use(authenticateToken);

async function recordAudit(adminId, userId, action, reason) {
  try {
    if (!adminId || !userId) return;
    await prisma.auditLog.create({
      data: {
        adminId,
        userId,
        action,
        reason: reason || null,
      },
    });
  } catch (error) {
    console.error('Audit logging error:', error);
  }
}

router.post('/users/:id/lock', async (req, res) => {
  const { id } = req.params;
  const { locked, reason } = req.body || {};

  const lockState = typeof locked === 'boolean' ? locked : true;

  try {
    const user = await prisma.user.findUnique({ where: { id } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updated = await prisma.user.update({
      where: { id },
      data: { accountLocked: lockState },
      select: { id: true, email: true, name: true, accountLocked: true, forcePasswordReset: true },
    });

    await recordAudit(req.user?.id, id, lockState ? 'lock' : 'unlock', reason);

    return res.json({
      message: lockState ? 'Account locked' : 'Account unlocked',
      user: updated,
    });
  } catch (error) {
    console.error('Account lock error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/users/:id/force-password-reset', async (req, res) => {
  const { id } = req.params;
  const { force, reason } = req.body || {};

  const forceReset = typeof force === 'boolean' ? force : true;

  try {
    const user = await prisma.user.findUnique({ where: { id } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const updated = await prisma.user.update({
      where: { id },
      data: { forcePasswordReset: forceReset },
      select: { id: true, email: true, name: true, accountLocked: true, forcePasswordReset: true },
    });

    await recordAudit(req.user?.id, id, forceReset ? 'force_reset' : 'clear_force_reset', reason);

    return res.json({
      message: forceReset ? 'Password reset required' : 'Password reset requirement cleared',
      user: updated,
    });
  } catch (error) {
    console.error('Force password reset error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
