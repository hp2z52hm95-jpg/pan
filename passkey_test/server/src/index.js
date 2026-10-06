/**
 * Pandora Passkey Server - Main Entry Point
 * 
 * FIDO2/WebAuthn authentication server for Pandora Tool
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const config = require('./config');
const database = require('./models/database');
const authRoutes = require('./routes/auth');
const passkeyRoutes = require('./routes/passkey');
const userRoutes = require('./routes/users');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: config.cors.origins,
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: config.security.rateLimitWindowMs,
  max: config.security.rateLimitMaxRequests,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/passkey', passkeyRoutes);
app.use('/api/users', userRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(config.env === 'development' && { stack: err.stack })
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Initialize database and start server
async function start() {
  try {
    await database.initialize();
    console.log('✓ Database initialized');

    app.listen(config.server.port, config.server.host, () => {
      console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Pandora Passkey Server                                  ║
║   FIDO2/WebAuthn Authentication                           ║
║                                                           ║
║   Server:    http://${config.server.host}:${config.server.port}              ║
║   RP ID:     ${config.webauthn.rpId.padEnd(40)}║
║   RP Name:   ${config.webauthn.rpName.padEnd(40)}║
║   Origin:    ${config.webauthn.origin.padEnd(40)}║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
      `);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

start();
