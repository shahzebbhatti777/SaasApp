const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const axios = require('axios');
const { authenticateToken, requireRecentMfa } = require('./auth');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');

const router = express.Router();
const prisma = new PrismaClient();

const frontendBaseUrl = (process.env.FRONTEND_URL || 'https://yourfrontend.com').replace(/\/$/, '');
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN_MS = 7 * 24 * 60 * 60 * 1000;
const EMAIL_TOKEN_EXPIRES_IN_MS = 60 * 60 * 1000;
const SUPPORTED_OAUTH_PROVIDERS = ['google', 'apple', 'tiktok', 'wechat'];

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function formatUserResponse(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    parentId: user.parentId,
    accountOwnerId: user.parentId || user.id,
    permissions: user.permissions,
    provider: user.provider,
    providerId: user.providerId,
    avatar: user.avatar,
    emailVerified: user.emailVerified,
  };
}

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

async function cleanupExpiredRefreshTokens(userId) {
  const now = new Date();
  const expiredTokens = await prisma.refreshToken.findMany({
    where: { userId, expiresAt: { lte: now } },
    select: { token: true },
  });

  if (!expiredTokens.length) {
    return;
  }

  const expiredTokenValues = expiredTokens.map((t) => t.token);

  await prisma.sessionLog.updateMany({
    where: { refreshToken: { in: expiredTokenValues } },
    data: { revoked: true },
  });

  await prisma.refreshToken.deleteMany({ where: { token: { in: expiredTokenValues } } });
}

async function rotateUserSessions(userId) {
  await cleanupExpiredRefreshTokens(userId);

  await prisma.refreshToken.updateMany({
    where: { userId, revoked: false },
    data: { revoked: true },
  });

  await prisma.sessionLog.updateMany({ where: { userId, revoked: false }, data: { revoked: true } });
}

async function issueTokens(user, req, options = {}) {
  const { rotateSessions = false } = options;

  if (rotateSessions) {
    await rotateUserSessions(user.id);
  } else {
    await cleanupExpiredRefreshTokens(user.id);
  }

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

async function recordMfaVerification(userId) {
  try {
    await prisma.user.update({ where: { id: userId }, data: { lastMfaVerifiedAt: new Date() } });
  } catch (error) {
    console.error('MFA verification timestamp error:', error);
  }
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

function getCallbackUrl(req, provider) {
  const base = (process.env.API_BASE_URL || `${req.protocol}://${req.get('host') || ''}`).replace(/\/$/, '');
  return `${base}/api/auth/oauth/${provider}/callback`;
}

function resolveRedirectTarget(state) {
  if (state && state.startsWith(frontendBaseUrl)) {
    return state;
  }

  return `${frontendBaseUrl}/auth/callback`;
}

function getOAuthProviderSettings(provider) {
  switch (provider) {
    case 'google':
      return {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        scope: ['profile', 'email'],
      };
    case 'apple':
      return {
        clientId: process.env.APPLE_CLIENT_ID,
        clientSecret: process.env.APPLE_CLIENT_SECRET,
        scope: ['name', 'email'],
      };
    case 'tiktok':
      return {
        clientId: process.env.TIKTOK_CLIENT_KEY,
        clientSecret: process.env.TIKTOK_CLIENT_SECRET,
        scope: ['user.info.basic', 'user.info.email'],
      };
    case 'wechat':
      return {
        clientId: process.env.WECHAT_APP_ID,
        clientSecret: process.env.WECHAT_APP_SECRET,
        scope: ['snsapi_login'],
      };
    default:
      return null;
  }
}

function buildAuthUrl(provider, callbackUrl, state) {
  const settings = getOAuthProviderSettings(provider);

  if (!settings || !settings.clientId || !settings.clientSecret) {
    return null;
  }

  const params = new URLSearchParams();

  switch (provider) {
    case 'google': {
      params.set('client_id', settings.clientId);
      params.set('redirect_uri', callbackUrl);
      params.set('response_type', 'code');
      params.set('scope', settings.scope.join(' '));
      params.set('access_type', 'offline');
      params.set('prompt', 'consent');
      if (state) params.set('state', state);
      return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
    }
    case 'apple': {
      params.set('client_id', settings.clientId);
      params.set('redirect_uri', callbackUrl);
      params.set('response_type', 'code');
      params.set('response_mode', 'query');
      params.set('scope', settings.scope.join(' '));
      if (state) params.set('state', state);
      return `https://appleid.apple.com/auth/authorize?${params.toString()}`;
    }
    case 'tiktok': {
      params.set('client_key', settings.clientId);
      params.set('redirect_uri', callbackUrl);
      params.set('response_type', 'code');
      params.set('scope', settings.scope.join(','));
      if (state) params.set('state', state);
      return `https://www.tiktok.com/v2/auth/authorize/?${params.toString()}`;
    }
    case 'wechat': {
      params.set('appid', settings.clientId);
      params.set('redirect_uri', callbackUrl);
      params.set('response_type', 'code');
      params.set('scope', 'snsapi_login');
      if (state) params.set('state', state);
      return `https://open.weixin.qq.com/connect/qrconnect?${params.toString()}#wechat_redirect`;
    }
    default:
      return null;
  }
}

async function exchangeCodeForProfile(provider, code, callbackUrl) {
  const settings = getOAuthProviderSettings(provider);

  if (!settings || !settings.clientId || !settings.clientSecret) {
    throw new Error('OAuth provider not configured');
  }

  switch (provider) {
    case 'google': {
      const tokenResponse = await axios.post(
        'https://oauth2.googleapis.com/token',
        new URLSearchParams({
          code,
          client_id: settings.clientId,
          client_secret: settings.clientSecret,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const accessToken = tokenResponse.data.access_token;

      const profileResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      const profile = profileResponse.data || {};

      return {
        email: profile.email,
        name: profile.name || profile.given_name || profile.family_name || 'Google User',
        provider: 'google',
        providerId: profile.sub,
        avatar: profile.picture,
      };
    }
    case 'apple': {
      const tokenResponse = await axios.post(
        'https://appleid.apple.com/auth/token',
        new URLSearchParams({
          code,
          client_id: settings.clientId,
          client_secret: settings.clientSecret,
          grant_type: 'authorization_code',
          redirect_uri: callbackUrl,
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );

      const idToken = tokenResponse.data.id_token;
      const decoded = jwt.decode(idToken) || {};

      return {
        email: decoded.email,
        name: decoded.name || decoded.email || 'Apple User',
        provider: 'apple',
        providerId: decoded.sub,
        avatar: null,
      };
    }
    case 'tiktok': {
      const tokenResponse = await axios.post(
        'https://open.tiktokapis.com/v2/oauth/token',
        {
          client_key: settings.clientId,
          client_secret: settings.clientSecret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: callbackUrl,
        },
        { headers: { 'Content-Type': 'application/json' } }
      );

      const tokenData = tokenResponse.data?.data || tokenResponse.data || {};
      const accessToken = tokenData.access_token;
      const openId = tokenData.open_id || tokenData.openid;

      const profileResponse = await axios.post(
        'https://open.tiktokapis.com/v2/user/info/',
        { fields: ['open_id', 'union_id', 'avatar_url', 'display_name', 'email'] },
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      const profile = profileResponse.data?.data?.user || profileResponse.data?.data || {};

      return {
        email: profile.email,
        name: profile.display_name || 'TikTok User',
        provider: 'tiktok',
        providerId: profile.open_id || profile.union_id || openId,
        avatar: profile.avatar_url,
      };
    }
    case 'wechat': {
      const tokenResponse = await axios.get('https://api.weixin.qq.com/sns/oauth2/access_token', {
        params: {
          appid: settings.clientId,
          secret: settings.clientSecret,
          code,
          grant_type: 'authorization_code',
        },
      });

      const { access_token: accessToken, openid, unionid } = tokenResponse.data || {};

      const profileResponse = await axios.get('https://api.weixin.qq.com/sns/userinfo', {
        params: {
          access_token: accessToken,
          openid,
          lang: 'en',
        },
      });

      const profile = profileResponse.data || {};

      return {
        email: null,
        name: profile.nickname || 'WeChat User',
        provider: 'wechat',
        providerId: unionid || openid,
        avatar: profile.headimgurl,
      };
    }
    default:
      throw new Error('Unsupported provider');
  }
}

async function findOrCreateOAuthUser(profile) {
  if (!profile.provider || (!profile.email && !profile.providerId)) {
    throw new Error('Missing provider profile data');
  }

  const fallbackEmail = `${profile.providerId || crypto.randomBytes(10).toString('hex')}@${profile.provider}.oauth`;

  let user = null;

  if (profile.providerId) {
    user = await prisma.user.findFirst({ where: { provider: profile.provider, providerId: profile.providerId } });
  }

  if (!user && profile.email) {
    user = await prisma.user.findUnique({ where: { email: profile.email } });
  }

  if (user) {
    const updates = {};

    if (!user.emailVerified && profile.email) {
      updates.emailVerified = true;
    }

    if (!user.provider) {
      updates.provider = profile.provider;
    }

    if (!user.providerId && profile.providerId) {
      updates.providerId = profile.providerId;
    }

    if (profile.avatar && profile.avatar !== user.avatar) {
      updates.avatar = profile.avatar;
    }

    if (!user.name && profile.name) {
      updates.name = profile.name;
    }

    if (Object.keys(updates).length) {
      user = await prisma.user.update({ where: { id: user.id }, data: updates });
    }
  } else {
    user = await prisma.user.create({
      data: {
        email: profile.email || fallbackEmail,
        password: '',
        name: profile.name || `${profile.provider} user`,
        provider: profile.provider,
        providerId: profile.providerId,
        avatar: profile.avatar || null,
        emailVerified: true,
      },
    });
  }

  return user;
}

async function completeOAuthLogin(user, req, res, redirectTarget) {
  const { owner } = await resolveAccountOwner(user);
  const statusError = evaluateAccountStatus(user, owner);

  if (statusError) {
    return res.status(statusError.status).json(statusError.body);
  }

  const tokens = await issueTokens(user, req, { rotateSessions: true });

  if (redirectTarget) {
    const redirectUrl = `${redirectTarget}?accessToken=${encodeURIComponent(tokens.accessToken)}&refreshToken=${encodeURIComponent(
      tokens.refreshToken
    )}`;

    return res.redirect(redirectUrl);
  }

  return res.json({ ...tokens, user: formatUserResponse(user) });
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
        const avatar = profile.photos && profile.photos[0] && profile.photos[0].value;

        const providerProfile = {
          email,
          name:
            profile.displayName ||
            [profile.name?.givenName, profile.name?.familyName].filter(Boolean).join(' ') ||
            'Google User',
          provider: 'google',
          providerId: profile.id || profile._json?.sub,
          avatar,
        };

        if (!providerProfile.providerId) {
          return done(null, false, { message: 'Google profile missing id' });
        }

        const user = await findOrCreateOAuthUser(providerProfile);

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
      user: formatUserResponse(user),
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

    const { accessToken, refreshToken } = await issueTokens(user, req, { rotateSessions: true });

    return res.json({
      accessToken,
      refreshToken,
      user: formatUserResponse(owner || user),
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

    await recordMfaVerification(user.id);

    const { accessToken, refreshToken } = await issueTokens(user, req, { rotateSessions: true });

    return res.json({
      accessToken,
      refreshToken,
      user: formatUserResponse(owner || user),
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

router.post('/logout-all', authenticateToken, requireRecentMfa, async (req, res) => {
  try {
    await prisma.refreshToken.updateMany({ where: { userId: req.user.id }, data: { revoked: true } });
    await prisma.sessionLog.updateMany({ where: { userId: req.user.id }, data: { revoked: true } });

    return res.json({ message: 'Logged out from all devices.' });
  } catch (error) {
    console.error('Logout-all error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
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

    await prisma.user.update({
      where: { id: user.id },
      data: { mfaEnabled: true, lastMfaVerifiedAt: new Date() },
    });

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
      ...formatUserResponse(user),
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

router.get('/oauth/:provider', (req, res) => {
  const provider = (req.params.provider || '').toLowerCase();

  if (!SUPPORTED_OAUTH_PROVIDERS.includes(provider)) {
    return res.status(400).json({ error: 'Unsupported provider' });
  }

  const callbackUrl = getCallbackUrl(req, provider);
  const state = req.query.redirect && req.query.redirect.startsWith(frontendBaseUrl) ? req.query.redirect : req.query.state;
  const authUrl = buildAuthUrl(provider, callbackUrl, state);

  if (!authUrl) {
    return res.status(400).json({ error: 'OAuth provider not configured' });
  }

  return res.redirect(authUrl);
});

router.get('/oauth/:provider/callback', async (req, res) => {
  const provider = (req.params.provider || '').toLowerCase();
  const { code, state } = req.query;

  if (!SUPPORTED_OAUTH_PROVIDERS.includes(provider)) {
    return res.status(400).json({ error: 'Unsupported provider' });
  }

  if (!code) {
    return res.status(400).json({ error: 'Missing authorization code' });
  }

  try {
    const callbackUrl = getCallbackUrl(req, provider);
    const profile = await exchangeCodeForProfile(provider, code, callbackUrl);
    const user = await findOrCreateOAuthUser(profile);
    const redirectTarget = resolveRedirectTarget(state);

    return await completeOAuthLogin(user, req, res, redirectTarget);
  } catch (error) {
    console.error(`${provider} OAuth callback error:`, error);
    return res.status(400).json({ error: 'OAuth callback failed' });
  }
});

router.post('/oauth/:provider/token', async (req, res) => {
  const provider = (req.params.provider || '').toLowerCase();
  const { code, redirectUri } = req.body || {};

  if (!SUPPORTED_OAUTH_PROVIDERS.includes(provider)) {
    return res.status(400).json({ error: 'Unsupported provider' });
  }

  if (!code) {
    return res.status(400).json({ error: 'Missing authorization code' });
  }

  try {
    const callbackUrl = redirectUri || getCallbackUrl(req, provider);
    const profile = await exchangeCodeForProfile(provider, code, callbackUrl);
    const user = await findOrCreateOAuthUser(profile);

    return await completeOAuthLogin(user, req, res);
  } catch (error) {
    console.error(`${provider} OAuth token exchange error:`, error);
    return res.status(400).json({ error: 'OAuth token exchange failed' });
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

      const redirectTarget = resolveRedirectTarget(req.query.state || req.query.redirect);

      return await completeOAuthLogin(dbUser, req, res, redirectTarget);
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

router.delete('/sessions/:id', authenticateToken, requireRecentMfa, async (req, res) => {
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
