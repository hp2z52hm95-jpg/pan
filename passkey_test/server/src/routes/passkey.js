/**
 * Passkey Routes - FIDO2/WebAuthn Registration and Authentication
 * 
 * These endpoints handle the complete passkey flow:
 * 1. Registration: User registers a new passkey
 * 2. Authentication: User authenticates with existing passkey
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const database = require('../models/database');
const config = require('../config');
const { authenticateToken } = require('../middleware/auth');
const { logAudit } = require('../utils/audit');

/**
 * POST /api/passkey/register/begin
 * 
 * Start passkey registration process
 * Returns WebAuthn registration options for the client
 */
router.post('/register/begin', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const user = await database.get('SELECT * FROM users WHERE id = ?', [userId]);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get existing passkeys for this user
    const existingPasskeys = await database.all(
      'SELECT credential_id FROM passkeys WHERE user_id = ?',
      [userId]
    );

    // Generate registration options
    const options = await generateRegistrationOptions({
      rpName: config.webauthn.rpName,
      rpID: config.webauthn.rpId,
      userID: userId,
      userName: user.username,
      userDisplayName: user.display_name || user.username,
      attestationType: 'none',
      excludeCredentials: existingPasskeys.map(pk => ({
        id: pk.credential_id,
        type: 'public-key',
        transports: ['internal', 'hybrid']
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred'
        // NOTE: no authenticatorAttachment restriction — allows platform
        // authenticators, password managers, and cross-platform security keys
      }
    });

    // Store challenge in database
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + config.webauthn.timeoutMs);

    await database.run(
      `INSERT INTO challenges (id, user_id, challenge, type, expires_at)
       VALUES (?, ?, ?, 'registration', ?)`,
      [challengeId, userId, options.challenge, expiresAt.toISOString()]
    );

    await logAudit(userId, 'passkey_registration_started', {
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      ...options,
      challengeId
    });

  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/passkey/register/complete
 * 
 * Complete passkey registration
 * Verifies the attestation and stores the credential
 */
router.post('/register/complete', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const { challengeId, response, deviceName } = req.body;

    if (!challengeId || !response) {
      return res.status(400).json({ error: 'Missing challengeId or response' });
    }

    // Get challenge from database
    const challenge = await database.get(
      `SELECT * FROM challenges 
       WHERE id = ? AND user_id = ? AND type = 'registration' AND used = 0`,
      [challengeId, userId]
    );

    if (!challenge) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    // Check if challenge expired
    if (new Date() > new Date(challenge.expires_at)) {
      await database.run('DELETE FROM challenges WHERE id = ?', [challengeId]);
      return res.status(400).json({ error: 'Challenge expired' });
    }

    // Verify registration response
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.webauthn.origin,
      expectedRPID: config.webauthn.rpId,
      requireUserVerification: false
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Verification failed' });
    }

    const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

    // Store passkey in database
    const passkeyId = uuidv4();
    const credentialIdBase64 = Buffer.from(credentialID).toString('base64url');
    const publicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64url');

    await database.run(
      `INSERT INTO passkeys 
       (id, user_id, credential_id, public_key, counter, name, transports)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        passkeyId,
        userId,
        credentialIdBase64,
        publicKeyBase64,
        counter,
        deviceName || 'Unnamed Device',
        JSON.stringify(response.response.transports || [])
      ]
    );

    // Mark challenge as used
    await database.run(
      'UPDATE challenges SET used = 1 WHERE id = ?',
      [challengeId]
    );

    await logAudit(userId, 'passkey_registered', {
      passkeyId,
      deviceName: deviceName || 'Unnamed Device',
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({
      success: true,
      passkeyId,
      message: 'Passkey registered successfully'
    });

  } catch (error) {
    console.error('Registration error:', error);
    next(error);
  }
});

/**
 * POST /api/passkey/authenticate/begin
 * 
 * Start passkey authentication process
 * Returns WebAuthn authentication options
 */
router.post('/authenticate/begin', async (req, res, next) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    // Get user
    const user = await database.get(
      'SELECT * FROM users WHERE username = ? AND is_active = 1',
      [username]
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get user's passkeys
    const passkeys = await database.all(
      'SELECT * FROM passkeys WHERE user_id = ?',
      [user.id]
    );

    if (passkeys.length === 0) {
      return res.status(400).json({ 
        error: 'No passkeys registered for this user',
        code: 'NO_PASSKEYS'
      });
    }

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      rpID: config.webauthn.rpId,
      allowCredentials: passkeys.map(pk => ({
        id: Buffer.from(pk.credential_id, 'base64url'),
        type: 'public-key',
        transports: JSON.parse(pk.transports || '[]')
      })),
      userVerification: 'preferred'
    });

    // Store challenge
    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + config.webauthn.timeoutMs);

    await database.run(
      `INSERT INTO challenges (id, user_id, challenge, type, expires_at)
       VALUES (?, ?, ?, 'authentication', ?)`,
      [challengeId, user.id, options.challenge, expiresAt.toISOString()]
    );

    res.json({
      ...options,
      challengeId,
      userId: user.id
    });

  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/passkey/authenticate/complete
 * 
 * Complete passkey authentication
 * Verifies the assertion and creates a session
 */
router.post('/authenticate/complete', async (req, res, next) => {
  try {
    const { challengeId, userId, response } = req.body;

    if (!challengeId || !userId || !response) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Get challenge
    const challenge = await database.get(
      `SELECT * FROM challenges 
       WHERE id = ? AND user_id = ? AND type = 'authentication' AND used = 0`,
      [challengeId, userId]
    );

    if (!challenge) {
      return res.status(400).json({ error: 'Invalid or expired challenge' });
    }

    // Check expiration
    if (new Date() > new Date(challenge.expires_at)) {
      await database.run('DELETE FROM challenges WHERE id = ?', [challengeId]);
      return res.status(400).json({ error: 'Challenge expired' });
    }

    // Get the passkey
    const credentialIdBase64 = Buffer.from(response.id, 'base64url').toString('base64url');
    const passkey = await database.get(
      'SELECT * FROM passkeys WHERE credential_id = ? AND user_id = ?',
      [credentialIdBase64, userId]
    );

    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found' });
    }

    // Verify authentication response
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.webauthn.origin,
      expectedRPID: config.webauthn.rpId,
      authenticator: {
        credentialPublicKey: Buffer.from(passkey.public_key, 'base64url'),
        credentialID: Buffer.from(passkey.credential_id, 'base64url'),
        counter: passkey.counter
      }
    });

    if (!verification.verified) {
      return res.status(401).json({ error: 'Authentication failed' });
    }

    // Update counter
    await database.run(
      'UPDATE passkeys SET counter = ?, last_used = CURRENT_TIMESTAMP WHERE id = ?',
      [verification.authenticationInfo.newCounter, passkey.id]
    );

    // Mark challenge as used
    await database.run(
      'UPDATE challenges SET used = 1 WHERE id = ?',
      [challengeId]
    );

    // Create session
    const jwt = require('jsonwebtoken');
    const sessionToken = jwt.sign(
      { 
        userId: userId,
        passkeyId: passkey.id,
        type: 'passkey'
      },
      config.jwt.secret,
      { expiresIn: config.jwt.expiresIn }
    );

    const sessionId = uuidv4();
    const sessionExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await database.run(
      `INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [sessionId, userId, sessionToken, sessionExpiresAt.toISOString(), req.ip, req.get('user-agent')]
    );

    // Update user last login
    await database.run(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [userId]
    );

    await logAudit(userId, 'passkey_authenticated', {
      passkeyId: passkey.id,
      sessionId,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    // Get user info
    const user = await database.get('SELECT * FROM users WHERE id = ?', [userId]);

    res.json({
      success: true,
      token: sessionToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.display_name,
        credits: user.credits
      },
      expiresAt: sessionExpiresAt.toISOString()
    });

  } catch (error) {
    console.error('Authentication error:', error);
    next(error);
  }
});

/**
 * GET /api/passkey/list
 * 
 * List all passkeys for authenticated user
 */
router.get('/list', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user.id;

    const passkeys = await database.all(
      `SELECT id, name, created_at, last_used, counter 
       FROM passkeys 
       WHERE user_id = ? 
       ORDER BY created_at DESC`,
      [userId]
    );

    res.json({ passkeys });

  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/passkey/:id
 * 
 * Delete a passkey
 */
router.delete('/:id', authenticateToken, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const passkeyId = req.params.id;

    const passkey = await database.get(
      'SELECT * FROM passkeys WHERE id = ? AND user_id = ?',
      [passkeyId, userId]
    );

    if (!passkey) {
      return res.status(404).json({ error: 'Passkey not found' });
    }

    // Check if user has other passkeys or password
    const passkeyCount = await database.get(
      'SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?',
      [userId]
    );

    if (passkeyCount.count === 1) {
      return res.status(400).json({ 
        error: 'Cannot delete last passkey. Register another passkey first.' 
      });
    }

    await database.run('DELETE FROM passkeys WHERE id = ?', [passkeyId]);

    await logAudit(userId, 'passkey_deleted', {
      passkeyId,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    res.json({ success: true, message: 'Passkey deleted' });

  } catch (error) {
    next(error);
  }
});

module.exports = router;
