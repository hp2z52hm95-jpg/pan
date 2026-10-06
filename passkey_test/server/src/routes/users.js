/**
 * User Routes - User management endpoints
 */

const express = require('express');
const router = express.Router();

const database = require('../models/database');
const { authenticateToken } = require('../middleware/auth');

/**
 * GET /api/users
 * 
 * List users (admin only in production)
 */
router.get('/', authenticateToken, async (req, res, next) => {
  try {
    const users = await database.all(
      `SELECT id, username, email, display_name, created_at, last_login, is_active, credits
       FROM users 
       ORDER BY created_at DESC 
       LIMIT 100`
    );

    res.json({ users });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/users/:id
 * 
 * Get user by ID
 */
router.get('/:id', authenticateToken, async (req, res, next) => {
  try {
    const user = await database.get(
      `SELECT id, username, email, display_name, created_at, last_login, is_active, credits
       FROM users WHERE id = ?`,
      [req.params.id]
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const passkeys = await database.all(
      'SELECT id, name, created_at, last_used FROM passkeys WHERE user_id = ?',
      [user.id]
    );

    res.json({ 
      user: {
        ...user,
        passkeys
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/users/:id
 * 
 * Delete user (admin only in production)
 */
router.delete('/:id', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.params.id;

    // Prevent users from deleting themselves (unless admin)
    if (userId === req.user.id) {
      return res.status(400).json({ 
        error: 'Cannot delete your own account' 
      });
    }

    const user = await database.get('SELECT * FROM users WHERE id = ?', [userId]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Soft delete (deactivate)
    await database.run(
      'UPDATE users SET is_active = 0 WHERE id = ?',
      [userId]
    );

    res.json({ success: true, message: 'User deactivated' });

  } catch (error) {
    next(error);
  }
});

module.exports = router;
