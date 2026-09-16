import dotenv from 'dotenv';

dotenv.config();

const PLACEHOLDER_SECRETS = [
  'change-me-to-a-long-random-secret',
  'quantum-safe-secret-2026',
];

function fail(message) {
  console.error(`\x1b[31m[FATAL]\x1b[0m ${message}`);
  console.error('        Copy backend/.env.example to backend/.env and fill in real values.');
  console.error('        Generate a secret with: openssl rand -hex 32');
  process.exit(1);
}

const { JWT_SECRET } = process.env;

// A missing or well-known signing secret means every token in the system is
// forgeable, so refuse to boot rather than run insecurely (see improve.txt SEC-2).
if (!JWT_SECRET) fail('JWT_SECRET is not set.');
if (PLACEHOLDER_SECRETS.includes(JWT_SECRET)) fail('JWT_SECRET is still set to a well-known placeholder value.');
if (JWT_SECRET.length < 32) fail('JWT_SECRET is too short - use at least 32 characters.');

export const config = {
  jwtSecret: JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
  port: parseInt(process.env.PORT, 10) || 5000,
  mongoUri: process.env.MONGO_URI || 'mongodb://localhost:27017/qchat',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  nodeEnv: process.env.NODE_ENV || 'development',
  // Socket.io's default maxHttpBufferSize is 1MB, which silently kills the
  // connection for anything but tiny attachments. Keep the transport ceiling and
  // the enforced per-message ceiling in sync (see improve.txt OPS-4).
  maxMessageBytes: parseInt(process.env.MAX_MESSAGE_BYTES, 10) || 12 * 1024 * 1024,
};

export default config;
