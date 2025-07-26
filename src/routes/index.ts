import { Router } from 'express';
import { authController } from '../controllers/authControllers';
import { userController } from '../controllers/userControllers';
import {
  authenticateToken,
  requireActiveUser,
  validateInput,
  authRateLimit,
  apiRateLimit,
  csrfProtection,
  apiSecurityHeaders,
  sanitizeInput,
} from '../middleware/index';

const router = Router();

// Apply security headers to all API routes
router.use(apiSecurityHeaders);
router.use(sanitizeInput);

// Health check endpoint (no authentication required)
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'SMART Pump API is running',
    data: {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
    },
  });
});

// Auth routes with rate limiting
const authRouter = Router();
authRouter.use(authRateLimit); // Apply stricter rate limiting to auth endpoints

// Public auth endpoints
authRouter.post(
  '/login',
  authController.loginValidation,
  validateInput,
  authController.login
);

authRouter.post('/logout', authController.logout);

authRouter.post('/refresh', authController.refreshToken);

authRouter.get('/csrf-token', authController.getCsrfToken);

// Protected auth endpoints
authRouter.get(
  '/validate',
  authenticateToken,
  requireActiveUser,
  authController.validateToken
);

authRouter.post(
  '/change-password',
  authenticateToken,
  requireActiveUser,
  csrfProtection,
  authController.changePassword
);

// User routes with authentication
const userRouter = Router();
userRouter.use(apiRateLimit); // Apply general rate limiting
userRouter.use(authenticateToken); // All user routes require authentication
userRouter.use(requireActiveUser); // All user routes require active account

// User profile endpoints
userRouter.get('/profile', userController.getCurrentUser);

userRouter.get('/profile/:userId', userController.getUserProfile);

userRouter.put(
  '/profile',
  csrfProtection,
  userController.updateValidation,
  validateInput,
  userController.updateUser
);

userRouter.get('/balance', userController.getUserBalance);

userRouter.get('/summary', userController.getAccountSummary);

userRouter.delete('/account', csrfProtection, userController.deleteAccount);

// Mount routers
router.use('/auth', authRouter);
router.use('/user', userRouter);

// API documentation endpoint
router.get('/docs', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'SMART Pump API Documentation',
    data: {
      apiVersion: '1.0.0',
      baseUrl: '/api',
      endpoints: {
        auth: {
          'POST /auth/login': 'Authenticate user with email and password',
          'POST /auth/logout': 'Logout user and clear tokens',
          'POST /auth/refresh': 'Refresh access token using refresh token',
          'GET /auth/validate': 'Validate current access token',
          'GET /auth/csrf-token': 'Get CSRF token for form protection',
          'POST /auth/change-password':
            'Change user password (requires CSRF token)',
        },
        user: {
          'GET /user/profile': 'Get current user profile',
          'GET /user/profile/:userId': 'Get specific user profile (own only)',
          'PUT /user/profile': 'Update user profile (requires CSRF token)',
          'GET /user/balance': 'Get user account balance',
          'GET /user/summary': 'Get user account summary',
          'DELETE /user/account':
            'Deactivate user account (requires CSRF token)',
        },
        system: {
          'GET /health': 'API health check',
          'GET /docs': 'API documentation',
        },
      },
      authentication: {
        method: 'JWT Bearer Token or HTTP-only cookies',
        tokenExpiry: '15 minutes (access), 7 days (refresh)',
        csrfProtection: 'Required for state-changing operations',
      },
      rateLimiting: {
        auth: '5 requests per 15 minutes',
        general: '100 requests per 15 minutes',
      },
      security: {
        headers: 'Helmet.js with CSP',
        cors: 'Configured for frontend domain',
        validation: 'Zod schema validation',
        sanitization: 'Input sanitization middleware',
      },
    },
  });
});

// Catch-all for undefined routes
router.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    error: `Route ${req.method} ${req.originalUrl} does not exist`,
    availableEndpoints: [
      'GET /api/health',
      'GET /api/docs',
      'POST /api/auth/login',
      'POST /api/auth/logout',
      'GET /api/user/profile',
      'PUT /api/user/profile',
      'GET /api/user/balance',
    ],
  });
});

export default router;
