const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const { authenticateToken } = require('./auth');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');

const router = express.Router();
const prisma = new PrismaClient();

const frontendBaseUrl = (process.env.FRONTEND_URL || 'https://yourfrontend.com').replace(/\/$/, '');
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL_TOKEN_EXPIRES_IN_MS = 60 * 60 * 1000;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function resolveAccountOwner(user) {
  if (!user.parentId) {
    return { owner: user, parent: null };
  }

  const parent = await prisma.user.findUnique({ where: { id: user.parentId } });
  return { owner: parent || user, parent };
}

function evaluateAccountStatus(actor, owner) {
  const controlling = owner || actor;

  if (!controlling) {
    return { status: 401, body: { error: 'Account unavailable' } };
  }

  if (actor.accountLocked || controlling.accountLocked) {
    return { status: 403, body: { error: 'Account locked by admin' } };
  }

  if ((!actor.parentId && !actor.emailVerified) || (actor.parentId && !controlling.emailVerified)) {
    return { status: 403, body: { error: 'Email not verified' } };
  }

  if (actor.forcePasswordReset || controlling.forcePasswordReset) {
    return { status: 403, body: { error: 'Password reset required', mustReset: true } };
  }

  return null;
}

function buildTokenPayload(user) {
  const parentId = user.parentId || null;
  return {
    id: user.id,
    email: user.email,
    role: user.role || 'user',
    parentId,
    accountOwnerId: parentId || user.id,
  };
}

function createAccessToken(user) {
  return jwt.sign(buildTokenPayload(user), process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });
}

async function issueTokens(user, req) {
  const sessionContext = getClientContext(req);
  const accessToken = createAccessToken(user);
  const { token: refreshToken } = await createRefreshToken(user.id, sessionContext);

  return { accessToken, refreshToken };
}

function getClientContext(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  const forwardedIp = Array.isArray(forwardedFor)
    ? forwardedFor[0]
    : typeof forwardedFor === 'string'
    ? forwardedFor.split(',')[0]
    : undefined;

  return {
    userAgent: req.headers['user-agent'] || 'Unknown',
    ipAddress: forwardedIp || req.ip || 'Unknown',
    deviceId: req.body?.deviceId || req.query?.deviceId || req.headers['x-device-id'] || 'unknown',
    location: req.body?.location || req.query?.location || req.headers['x-user-location'] || null,
  };
}

async function logSession({ userId, refreshToken, userAgent, ipAddress, deviceId, location, expiresAt }) {
  try {
    await prisma.sessionLog.create({
      data: {
        userId,
        refreshToken,
        userAgent,
        ipAddress,
        deviceId,
        location,
        expiresAt,
      },
    });
  } catch (error) {
    console.error('Session logging error:', error);
  }
}

async function createRefreshToken(userId, sessionContext) {
  const tokenValue = crypto.randomBytes(40).toString('hex');
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN_MS);

  const refreshToken = await prisma.refreshToken.create({
    data: {
      token: tokenValue,
      userId,
      expiresAt,
    },
  });

  if (sessionContext) {
    await logSession({
      userId,
      refreshToken: refreshToken.token,
      expiresAt,
      ...sessionContext,
    });
  }

  return { token: refreshToken.token, expiresAt };
}

async function revokeRefreshToken(token) {
  try {
    await prisma.refreshToken.update({
      where: { token },
      data: { revoked: true },
    });
  } catch (error) {
    if (error.code !== 'P2025') {
      console.error('Refresh token revocation error:', error);
    }
  }
}

async function revokeSessionByRefreshToken(token) {
  try {
    await prisma.sessionLog.updateMany({
      where: { refreshToken: token, revoked: false },
      data: { revoked: true },
    });
  } catch (error) {
    console.error('Session revocation error:', error);
  }
}

function createEmailTransporter() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;

  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    console.warn('Email transport is not fully configured. Verification emails will not be sent.');
    return null;
  }

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT) || 587,
    secure: false,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
}

async function createEmailVerificationToken(userId) {
  const tokenValue = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + EMAIL_TOKEN_EXPIRES_IN_MS);

  await prisma.emailVerificationToken.deleteMany({ where: { userId } });

  await prisma.emailVerificationToken.create({
    data: {
      token: tokenValue,
      userId,
      expiresAt,
    },
  });

  return { token: tokenValue, expiresAt };
}

async function sendVerificationEmail(email, token) {
  const transporter = createEmailTransporter();

  if (!transporter) {
    throw new Error('Email transport not configured');
  }

  const verifyUrl = `${frontendBaseUrl}/verify-email?token=${encodeURIComponent(token)}`;

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || 'no-reply@marqos.local',
    to: email,
    subject: 'Verify your email address',
    text: `Welcome to MARQ OS! Please verify your email by visiting: ${verifyUrl}\n\nIf you did not request this, you can ignore this email.`,
    html: `<p>Welcome to MARQ OS!</p><p>Please verify your email by clicking the link below:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p><p>If you did not request this, you can ignore this email.</p>`,
  });
}

async function revokeSessionById(sessionId, userId) {
  try {
    const session = await prisma.sessionLog.findUnique({ where: { id: sessionId } });

    if (!session || session.userId !== userId) {
      return null;
    }

    await prisma.sessionLog.update({ where: { id: sessionId }, data: { revoked: true } });

    await revokeRefreshToken(session.refreshToken);

    return session;
  } catch (error) {
    console.error('Session revocation by ID error:', error);
    return null;
  }
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/api/auth/google/callback',
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails && profile.emails[0] && profile.emails[0].value;

        if (!email) {
          return done(null, false, { message: 'Email not available from Google profile' });
        }

        const nameFromProfile =
          profile.displayName ||
          [profile.name?.givenName, profile.name?.familyName].filter(Boolean).join(' ') ||
          'Google User';

        let user = await prisma.user.findUnique({ where: { email } });

        if (!user) {
          user = await prisma.user.create({
            data: {
              email,
              name: nameFromProfile,
              password: '',
              emailVerified: true,
            },
          });
        } else if (!user.emailVerified) {
          user = await prisma.user.update({
            where: { id: user.id },
            data: { emailVerified: true },
          });
        }

        return done(null, {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          parentId: user.parentId,
          accountLocked: user.accountLocked,
          forcePasswordReset: user.forcePasswordReset,
          emailVerified: user.emailVerified,
        });
      } catch (error) {
        console.error('Google authentication error:', error);
        return done(error);
      }
    }
  )
);

router.post('/register', async (req, res) => {
  const { email, password, name } = req.body || {};

  if (!email || !password || !name || !EMAIL_REGEX.test(email)) {
    return res.status(400).json({ error: 'Invalid or missing fields' });
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });

    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        emailVerified: false,
      },
    });

    const { token } = await createEmailVerificationToken(user.id);
    await sendVerificationEmail(user.email, token);

    return res.status(201).json({
      message: 'Registration successful. Please verify your email to continue.',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        emailVerified: user.emailVerified,
        role: user.role,
        parentId: user.parentId,
        accountOwnerId: user.parentId || user.id,
        permissions: user.permissions,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/send-verification-email', async (req, res) => {
  const { email } = req.body || {};

  if (!email || !EMAIL_REGEX.test(email)) {
    return res.status(400).json({ error: 'Valid email is required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.emailVerified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    const { token } = await createEmailVerificationToken(user.id);
    await sendVerificationEmail(user.email, token);

    return res.json({ message: 'Verification email sent' });
  } catch (error) {
    console.error('Send verification email error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password || !EMAIL_REGEX.test(email)) {
    return res.status(400).json({ error: 'Invalid or missing fields' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { owner } = await resolveAccountOwner(user);
    const statusError = evaluateAccountStatus(user, owner);

    if (statusError) {
      return res.status(statusError.status).json(statusError.body);
    }

    if (user.mfaEnabled) {
      return res.status(403).json({ error: 'MFA required', mfaRequired: true });
    }

    const { accessToken, refreshToken } = await issueTokens(user, req);

    return res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        parentId: user.parentId,
        accountOwnerId: owner?.id || user.id,
        permissions: user.permissions,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/mfa/login', async (req, res) => {
  const { email, password, token } = req.body || {};

  if (!email || !password || !token || !EMAIL_REGEX.test(email)) {
    return res.status(400).json({ error: 'Invalid or missing fields' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.mfaEnabled || !user.mfaSecret) {
      return res.status(400).json({ error: 'MFA is not enabled for this account' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { owner } = await resolveAccountOwner(user);
    const statusError = evaluateAccountStatus(user, owner);

    if (statusError) {
      return res.status(statusError.status).json(statusError.body);
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA token' });
    }

    const { accessToken, refreshToken } = await issueTokens(user, req);

    return res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        parentId: user.parentId,
        accountOwnerId: owner?.id || user.id,
        permissions: user.permissions,
      },
    });
  } catch (error) {
    console.error('MFA login error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  try {
    const resetRequest = await prisma.passwordReset.findUnique({ where: { token } });

    if (!resetRequest || resetRequest.expiresAt <= new Date()) {
      if (resetRequest) {
        await prisma.passwordReset.delete({ where: { id: resetRequest.id } });
      }

      return res.status(404).json({ error: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: resetRequest.userId },
      data: { password: hashedPassword, forcePasswordReset: false },
    });

    await prisma.passwordReset.delete({ where: { id: resetRequest.id } });

    return res.json({ message: 'Password reset successful.' });
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body || {};

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required' });
  }

  try {
    const existingToken = await prisma.refreshToken.findUnique({ where: { token: refreshToken } });

    if (!existingToken || existingToken.revoked || existingToken.expiresAt <= new Date()) {
      if (existingToken && existingToken.expiresAt <= new Date()) {
        await revokeRefreshToken(refreshToken);
        await revokeSessionByRefreshToken(refreshToken);
      }

      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = await prisma.user.findUnique({ where: { id: existingToken.userId } });

    if (!user) {
      await revokeRefreshToken(refreshToken);
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const { owner } = await resolveAccountOwner(user);
    const statusError = evaluateAccountStatus(user, owner);

    if (statusError) {
      return res.status(statusError.status).json(statusError.body);
    }

    const sessionContext = getClientContext(req);

    await revokeRefreshToken(refreshToken);
    await revokeSessionByRefreshToken(refreshToken);

    const { token: newRefreshToken } = await createRefreshToken(user.id, sessionContext);
    const accessToken = createAccessToken(user);

    return res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error('Refresh token error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/verify-email', async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).send('Verification token is required.');
  }

  try {
    const record = await prisma.emailVerificationToken.findUnique({ where: { token } });

    if (!record) {
      return res.status(400).send('Invalid or expired verification link.');
    }

    if (record.expiresAt <= new Date()) {
      await prisma.emailVerificationToken.delete({ where: { id: record.id } });
      return res.status(400).send('Verification link has expired. Please request a new email.');
    }

    await prisma.user.update({ where: { id: record.userId }, data: { emailVerified: true } });
    await prisma.emailVerificationToken.deleteMany({ where: { userId: record.userId } });

    return res.send('Email verified successfully. You can close this window.');
  } catch (error) {
    console.error('Email verification error:', error);
    return res.status(500).send('Server error verifying email.');
  }
});

router.post('/logout', authenticateToken, async (req, res) => {
  const { refreshToken } = req.body || {};

  if (refreshToken) {
    await revokeRefreshToken(refreshToken);
    await revokeSessionByRefreshToken(refreshToken);
  }

  return res.json({ message: 'Logged out successfully.' });
});

router.post('/mfa/setup', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const secret = speakeasy.generateSecret({ name: `MARQ OS (${user.email})` });
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    await prisma.user.update({
      where: { id: user.id },
      data: { mfaSecret: secret.base32, mfaEnabled: false },
    });

    return res.json({ qrCodeUrl, manualCode: secret.base32 });
  } catch (error) {
    console.error('MFA setup error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/mfa/verify', authenticateToken, async (req, res) => {
  const { token } = req.body || {};

  if (!token) {
    return res.status(400).json({ error: 'Token is required' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user || !user.mfaSecret) {
      return res.status(400).json({ error: 'MFA setup has not been initiated' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1,
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    await prisma.user.update({ where: { id: user.id }, data: { mfaEnabled: true } });

    return res.json({ message: 'MFA enabled successfully' });
  } catch (error) {
    console.error('MFA verify error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      parentId: user.parentId,
      accountOwnerId: user.parentId || user.id,
      permissions: user.permissions,
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

router.get(
  '/google/callback',
  passport.authenticate('google', { session: false, failureRedirect: '/api/auth/google/failure' }),
  async (req, res) => {
    try {
      const dbUser = await prisma.user.findUnique({ where: { id: req.user.id } });

      if (!dbUser) {
        return res.status(404).json({ error: 'User not found' });
      }

      const { owner } = await resolveAccountOwner(dbUser);
      const statusError = evaluateAccountStatus(dbUser, owner);

      if (statusError) {
        return res.status(statusError.status).json(statusError.body);
      }

      const sessionContext = getClientContext(req);
      const accessToken = createAccessToken(dbUser);
      const { token: refreshToken } = await createRefreshToken(dbUser.id, sessionContext);

      const redirectUrl = `${frontendBaseUrl}/auth/callback?accessToken=${encodeURIComponent(
        accessToken
      )}&refreshToken=${encodeURIComponent(refreshToken)}`;

      return res.redirect(redirectUrl);
    } catch (error) {
      console.error('Google callback token error:', error);
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

router.get('/google/failure', (_req, res) => {
  return res.status(401).json({ error: 'Google authentication failed' });
});

router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const sessions = await prisma.sessionLog.findMany({
      where: {
        userId: req.user.id,
        revoked: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    return res.json({
      sessions: sessions.map((session) => ({
        id: session.id,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
        deviceId: session.deviceId,
        location: session.location,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
      })),
    });
  } catch (error) {
    console.error('Session list error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.delete('/sessions/:id', authenticateToken, async (req, res) => {
  try {
    const revokedSession = await revokeSessionById(req.params.id, req.user.id);

    if (!revokedSession) {
      return res.status(404).json({ error: 'Session not found' });
    }

    return res.json({ message: 'Session revoked' });
  } catch (error) {
    console.error('Session revoke error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
