import { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { ApiResponse, RateLimitConfig } from '../types/index';

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
