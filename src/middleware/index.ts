// Central middleware exports following Node.js naming conventions
// Re-exports from modular middleware files with .middleware.ts suffix

// Authentication middleware
export {
  authenticateToken,
  optionalAuth,
  requireActiveUser,
} from './auth.middleware';

// Rate limiting middleware
export {
  createRateLimit,
  authRateLimit,
  apiRateLimit,
} from './rateLimit.middleware';

// Security middleware
export {
  helmetMiddleware,
  corsMiddleware,
  apiSecurityHeaders,
  securityConfig,
} from './security.middleware';

// Validation middleware
export {
  validateInput,
  csrfProtection,
  sanitizeInput,
} from './validation.middleware';

// Logging middleware
export {
  requestLogger,
  errorHandler,
} from './logging.middleware';
