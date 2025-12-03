const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const { authenticateToken } = require('./auth');

const router = express.Router();
const prisma = new PrismaClient();

const frontendBaseUrl = (process.env.FRONTEND_URL || 'https://yourfrontend.com').replace(/\/$/, '');
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN_MS = 7 * 24 * 60 * 60 * 1000;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function createAccessToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });
}

async function createRefreshToken(userId) {
  const tokenValue = crypto.randomBytes(40).toString('hex');
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN_MS);

  const refreshToken = await prisma.refreshToken.create({
    data: {
      token: tokenValue,
      userId,
      expiresAt,
    },
  });

  return refreshToken.token;
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
            },
          });
        }

        return done(null, {
          id: user.id,
          email: user.email,
          name: user.name,
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
      },
    });

    const accessToken = createAccessToken(user);
    const refreshToken = await createRefreshToken(user.id);

    return res.status(201).json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
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

    const accessToken = createAccessToken(user);
    const refreshToken = await createRefreshToken(user.id);

    return res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
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
      data: { password: hashedPassword },
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
      }

      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = await prisma.user.findUnique({ where: { id: existingToken.userId } });

    if (!user) {
      await revokeRefreshToken(refreshToken);
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    await revokeRefreshToken(refreshToken);

    const newRefreshToken = await createRefreshToken(user.id);
    const accessToken = createAccessToken(user);

    return res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error('Refresh token error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.post('/logout', authenticateToken, async (req, res) => {
  const { refreshToken } = req.body || {};

  if (refreshToken) {
    await revokeRefreshToken(refreshToken);
  }

  return res.json({ message: 'Logged out successfully.' });
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
      const accessToken = createAccessToken(req.user);
      const refreshToken = await createRefreshToken(req.user.id);

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

module.exports = router;
