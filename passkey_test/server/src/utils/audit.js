/**
 * Audit Logging Utility
 */

const database = require('../models/database');

/**
 * Log an audit event
 */
async function logAudit(userId, action, details = {}) {
  try {
    await database.run(
      `INSERT INTO audit_log (user_id, action, details, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        userId,
        action,
        JSON.stringify(details),
        details.ip || null,
        details.userAgent || null
      ]
    );
  } catch (error) {
    console.error('Audit log error:', error);
    // Don't throw - audit logging shouldn't break the main flow
  }
}

/**
 * Get audit logs for a user
 */
async function getUserAuditLogs(userId, limit = 100) {
  return await database.all(
    `SELECT * FROM audit_log 
     WHERE user_id = ? 
     ORDER BY created_at DESC 
     LIMIT ?`,
    [userId, limit]
  );
}

module.exports = {
  logAudit,
  getUserAuditLogs
};
