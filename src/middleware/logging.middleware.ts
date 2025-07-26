import { Request, Response, NextFunction } from 'express';
import { ApiResponse } from '../types/index';

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

// Error handling middleware
export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  _next: NextFunction
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
