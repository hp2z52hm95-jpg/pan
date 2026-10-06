/**
 * Server Configuration
 */

module.exports = {
  env: process.env.NODE_ENV || 'development',
  
  server: {
    port: parseInt(process.env.PORT || '3000', 10),
    host: process.env.HOST || '0.0.0.0'
  },
  
  database: {
    path: process.env.DB_PATH || './database/pandora.db'
  },
  
  webauthn: {
    rpId: process.env.RP_ID || 'localhost',
    rpName: process.env.RP_NAME || 'Pandora Tool',
    origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',
    timeoutMs: parseInt(process.env.CHALLENGE_TIMEOUT_MS || '300000', 10)
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'change-this-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h'
  },
  
  session: {
    secret: process.env.SESSION_SECRET || 'change-this-in-production'
  },
  
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    rateLimitMaxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10)
  },
  
  cors: {
    origins: (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',')
  }
};
