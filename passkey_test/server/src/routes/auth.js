/**
 * Authentication Routes - Traditional username/password authentication
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const database = require('../models/database');
const config = require('../config');
const { authenticateToken } = require('../middleware/auth');
const { logAudit } = require('../utils/audit');

/**
 * POST /api/auth/register
 * 
 * Register a new user with username/password
 */
router.post('/register', async (req, res, next) => {
  try {
    const { username, email, password, displayName } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'Username, email, and password are required' 
      });
    }

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ 
        error: 'Username must be between 3 and 50 characters' 
      });
    }

    if (password.length < 8) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters' 
      });
    }

    // Check if user exists
    const existingUser = await database.get(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUser) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, config.security.bcryptRounds);

    // Create user
    const userId = uuidv4();
    await database.run(
      `INSERT INTO users (id, username, email, password_hash, display_name)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, username, email, passwordHash, displayName || username]
    );

    await logAudit(userId, 'user_registered', {
      username,
      email,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.status(201).json({
      success: true,
      userId,
      message: 'User registered successfully'
    });

  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/login
 * 
 * Login with username/password
 */
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Get user
    const user = await database.get(
      'SELECT * FROM users WHERE username = ? AND is_active = 1',
      [username]
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      await logAudit(user.id, 'login_failed', {
        reason: 'invalid_password',
        ip: req.ip,
        userAgent: req.get('user-agent')
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session token
    const token = jwt.sign(
      { 
        userId: user.id,
        type: 'password'
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    const sessionId = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await database.run(
      `INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [sessionId, user.id, token, expiresAt.toISOString(), req.ip, req.get('user-agent')]
    );

    // Update last login
    await database.run(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );

    await logAudit(user.id, 'login_success', {
      method: 'password',
      sessionId,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.display_name,
        credits: user.credits
      },
      expiresAt: expiresAt.toISOString()
    });

  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/auth/logout
 * 
 * Logout and invalidate session
 */
router.post('/logout', authenticateToken, async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (token) {
      await database.run(
        'UPDATE sessions SET is_active = 0 WHERE token = ?',
        [token]
      );
    }

    await logAudit(req.user.id, 'logout', {
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({ success: true, message: 'Logged out successfully' });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/auth/me
 * 
 * Get current user info
 */
router.get('/me', authenticateToken, async (req, res, next) => {
  try {
    const user = await database.get(
      `SELECT id, username, email, display_name, credits, created_at, last_login
       FROM users WHERE id = ?`,
      [req.user.id]
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const passkeys = await database.all(
      'SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?',
      [user.id]
    );

    res.json({
      user: {
        ...user,
        passkeyCount: passkeys[0].count
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/auth/password
 * 
 * Change password
 */
router.put('/password', authenticateToken, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ 
        error: 'Current password and new password required' 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        error: 'New password must be at least 8 characters' 
      });
    }

    // Get user
    const user = await database.get(
      'SELECT password_hash FROM users WHERE id = ?',
      [req.user.id]
    );

    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(newPassword, config.security.bcryptRounds);

    // Update password
    await database.run(
      'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [newPasswordHash, req.user.id]
    );

    await logAudit(req.user.id, 'password_changed', {
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({ success: true, message: 'Password changed successfully' });

  } catch (error) {
    next(error);
  }
});

module.exports = router;
