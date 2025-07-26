import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { ApiResponse } from '../types/index';

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
