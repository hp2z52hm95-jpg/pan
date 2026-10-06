/**
 * Authentication Middleware
 */

const jwt = require('jsonwebtoken');
const config = require('../config');
const database = require('../models/database');

/**
 * Authenticate JWT token
 */
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Verify JWT
    const decoded = jwt.verify(token, config.jwt.secret);

    // Check if session is active
    const session = await database.get(
      'SELECT * FROM sessions WHERE token = ? AND is_active = 1',
      [token]
    );

    if (!session) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }

    // Check if session expired
    if (new Date() > new Date(session.expires_at)) {
      await database.run(
        'UPDATE sessions SET is_active = 0 WHERE id = ?',
        [session.id]
      );
      return res.status(401).json({ error: 'Session expired' });
    }

    // Attach user to request
    req.user = {
      id: decoded.userId,
      type: decoded.type
    };

    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    next(error);
  }
}

/**
 * Optional authentication (doesn't fail if no token)
 */
async function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = jwt.verify(token, config.jwt.secret);
      req.user = {
        id: decoded.userId,
        type: decoded.type
      };
    }

    next();

  } catch (error) {
    // Ignore auth errors for optional auth
    next();
  }
}

module.exports = {
  authenticateToken,
  optionalAuth
};
