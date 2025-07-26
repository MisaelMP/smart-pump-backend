import { Request, Response, NextFunction } from 'express';
import { validationResult } from 'express-validator';
import { authService } from '../services/auth.service';
import { ApiResponse } from '../types/index';

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

  // Sanitize request body
  if (req.body) {
    req.body = sanitize(req.body);
  }

  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    const sanitizedQuery = sanitize(req.query);
    // Clear existing query properties and replace with sanitized ones
    Object.keys(req.query).forEach((key) => {
      delete (req.query as any)[key];
    });
    Object.assign(req.query, sanitizedQuery);
  }

  // Sanitize route parameters
  if (req.params) {
    req.params = sanitize(req.params);
  }

  next();
};
