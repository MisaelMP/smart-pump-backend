import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { SecurityConfig } from '../types/index';

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
