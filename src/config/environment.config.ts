import { config } from 'dotenv';
import { EnvSchema, type Environment } from '../types/index';
import crypto from 'crypto';

// Load environment variables
config();

// Generate secure secrets if not provided (for development)
const generateSecret = (): string => {
  return crypto.randomBytes(64).toString('hex');
};

// Ensure required environment variables exist
if (!process.env.JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET must be provided in production');
  }
  console.warn(
    'JWT_SECRET not found, generating temporary secret for development'
  );
  process.env.JWT_SECRET = generateSecret();
}

if (!process.env.JWT_REFRESH_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_REFRESH_SECRET must be provided in production');
  }
  console.warn(
    'JWT_REFRESH_SECRET not found, generating temporary secret for development'
  );
  process.env.JWT_REFRESH_SECRET = generateSecret();
}

// Validate and parse environment variables
const parseEnvironment = (): Environment => {
  try {
    return EnvSchema.parse({
      NODE_ENV: process.env.NODE_ENV,
      PORT: process.env.PORT,
      JWT_SECRET: process.env.JWT_SECRET,
      JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
      FRONTEND_URL: process.env.FRONTEND_URL,
      DB_PATH: process.env.DB_PATH,
    });
  } catch (error) {
    console.error('Environment validation failed:', error);
    throw new Error('Invalid environment configuration');
  }
};

export const env: Environment = parseEnvironment();

// Configuration objects for different services
export const serverConfig = {
  port: env.PORT,
  host: '0.0.0.0',
  trustProxy: env.NODE_ENV === 'production',
};

export const databaseConfig = {
  path: env.DB_PATH,
  backup: {
    enabled: env.NODE_ENV === 'production',
    interval: 24 * 60 * 60 * 1000, // 24 hours
    retentionDays: 7,
  },
};

export const securityConfig = {
  jwt: {
    secret: env.JWT_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    algorithm: 'HS256' as const,
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  },
  bcrypt: {
    saltRounds: 12,
  },
  rateLimit: {
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // 5 attempts per window
      skipSuccessfulRequests: true,
    },
    api: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // 100 requests per window
      skipSuccessfulRequests: false,
    },
  },
  cors: {
    origin: env.FRONTEND_URL,
    credentials: true,
  },
};

export const logConfig = {
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: env.NODE_ENV === 'production' ? 'json' : 'simple',
  enableConsole: true,
  enableFile: env.NODE_ENV === 'production',
};

// Validation functions
export const validateConfiguration = (): void => {
  console.log('Validating configuration...');

  // Check JWT secret strength
  if (env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }

  if (env.JWT_REFRESH_SECRET.length < 32) {
    throw new Error('JWT_REFRESH_SECRET must be at least 32 characters long');
  }

  // Check if secrets are different
  if (env.JWT_SECRET === env.JWT_REFRESH_SECRET) {
    throw new Error('JWT_SECRET and JWT_REFRESH_SECRET must be different');
  }

  // Validate frontend URL format
  try {
    new URL(env.FRONTEND_URL);
  } catch (error) {
    throw new Error('FRONTEND_URL must be a valid URL');
  }

  console.log('Configuration validation passed');
};

// Development helper to show current configuration
export const showConfiguration = (): void => {
  if (env.NODE_ENV !== 'development') return;

  console.log('Current Configuration:');
  console.log(`   Environment: ${env.NODE_ENV}`);
  console.log(`   Port: ${env.PORT}`);
  console.log(`   Frontend URL: ${env.FRONTEND_URL}`);
  console.log(`   Database Path: ${env.DB_PATH}`);
  console.log(`   JWT Secret Length: ${env.JWT_SECRET.length} chars`);
  console.log(
    `   JWT Refresh Secret Length: ${env.JWT_REFRESH_SECRET.length} chars`
  );
};

// Export environment for direct access
export { env as environment };
export default env;
