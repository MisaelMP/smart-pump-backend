import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import { validationResult } from 'express-validator';
import { authService } from '../services/authService';
import { ApiResponse, RateLimitConfig, SecurityConfig } from '../types/index';

// Rate limiting configurations
export const createRateLimit = (config: RateLimitConfig) => {
  return rateLimit({
    windowMs: config.windowMs,
    max: config.max,
    message: {
      success: false,
      message: config.message,
      error: 'Too many requests',
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req: Request, res: Response) => {
      res.status(429).json({
        success: false,
        message: config.message,
        error: 'Rate limit exceeded',
      } as ApiResponse);
    },
  });
};

// Authentication rate limiting (stricter)
export const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: 'Too many authentication attempts. Please try again later.',
});

// General API rate limiting
export const apiRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many API requests. Please try again later.',
});

// Security configuration
export const securityConfig: SecurityConfig = {
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:', 'http://placehold.it'],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        manifestSrc: ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    },
  },
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'X-CSRF-Token',
    ],
  },
};

// Helmet security middleware
export const helmetMiddleware = helmet({
  contentSecurityPolicy: securityConfig.helmet.contentSecurityPolicy,
  hsts: securityConfig.helmet.hsts,
  crossOriginEmbedderPolicy: false, // Needed for some modern web features
  crossOriginResourcePolicy: { policy: 'cross-origin' },
});

// CORS middleware
export const corsMiddleware = cors(securityConfig.cors);

// Input validation middleware
export const validateInput = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      message: 'Validation failed',
      error: 'Invalid input data',
      details: errors.array(),
    } as ApiResponse);
    return;
  }

  next();
};

// Authentication middleware
export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // Try to get token from Authorization header first
    const authHeader = req.headers.authorization;
    let token = authService.extractTokenFromHeader(authHeader);

    // Fallback to cookies if no Authorization header
    if (!token && req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      res.status(401).json({
        success: false,
        message: 'Access denied',
        error: 'No authentication token provided',
      } as ApiResponse);
      return;
    }

    const decoded = authService.verifyAccessToken(token);
    if (!decoded) {
      res.status(401).json({
        success: false,
        message: 'Access denied',
        error: 'Invalid or expired token',
      } as ApiResponse);
      return;
    }

    // Attach user info to request
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Authentication middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication error',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Optional authentication middleware (doesn't fail if no token)
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    let token = authService.extractTokenFromHeader(authHeader);

    if (!token && req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (token) {
      const decoded = authService.verifyAccessToken(token);
      if (decoded) {
        req.user = decoded;
      }
    }

    next();
  } catch (error) {
    // Don't fail for optional auth
    console.warn('Optional auth middleware warning:', error);
    next();
  }
};

// CSRF protection middleware
export const csrfProtection = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Skip CSRF for GET requests and OPTIONS
  if (req.method === 'GET' || req.method === 'OPTIONS') {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'] as string;

  if (!csrfToken) {
    res.status(403).json({
      success: false,
      message: 'CSRF token missing',
      error: 'CSRF protection required',
    } as ApiResponse);
    return;
  }

  if (!authService.verifyCsrfToken(csrfToken)) {
    res.status(403).json({
      success: false,
      message: 'Invalid CSRF token',
      error: 'CSRF protection failed',
    } as ApiResponse);
    return;
  }

  next();
};

// Error handling middleware
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  console.error('Unhandled error:', error);

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';

  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: isDevelopment ? error.message : 'Something went wrong',
    ...(isDevelopment && { stack: error.stack }),
  } as ApiResponse);
};

// Request logging middleware
export const requestLogger = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLevel = res.statusCode >= 400 ? 'error' : 'info';

    console.log(
      JSON.stringify({
        level: logLevel,
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        userId: req.user?.userId || 'anonymous',
        timestamp: new Date().toISOString(),
      })
    );
  });

  next();
};

// Security headers middleware for API responses
export const apiSecurityHeaders = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Prevent caching of sensitive API responses
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    Pragma: 'no-cache',
    Expires: '0',
    'Surrogate-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
  });

  next();
};

// Input sanitization middleware
export const sanitizeInput = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  // Basic input sanitization
  const sanitize = (obj: any): any => {
    if (typeof obj === 'string') {
      return obj.trim().replace(/<script[^>]*>.*?<\/script>/gi, '');
    }
    if (typeof obj === 'object' && obj !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitize(value);
      }
      return sanitized;
    }
    return obj;
  };

  if (req.body) {
    req.body = sanitize(req.body);
  }
  if (req.query) {
    req.query = sanitize(req.query);
  }
  if (req.params) {
    req.params = sanitize(req.params);
  }

  next();
};

// Active user check middleware
export const requireActiveUser = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      message: 'Authentication required',
      error: 'User not authenticated',
    } as ApiResponse);
    return;
  }

  if (!req.user.isActive) {
    res.status(403).json({
      success: false,
      message: 'Account inactive',
      error: 'Your account has been deactivated',
    } as ApiResponse);
    return;
  }

  next();
};
