import { Request, Response } from 'express';
import { body } from 'express-validator';
import { LoginSchema } from '../types/index';
import { authService } from '../services/auth.service';
import { databaseService } from '../database/database';
import type { ApiResponse, LoginRequest } from '../types/index';

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication endpoints
 */

// Login validation rules
export const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
];

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Authentication]
 *     description: Authenticate user with email and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *           example:
 *             email: henderson.briggs@geeknet.net
 *             password: "23derd*334"
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *         headers:
 *           Set-Cookie:
 *             description: Authentication token (HTTP-only cookie)
 *             schema:
 *               type: string
 *               example: "auth-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Path=/; HttpOnly; Secure; SameSite=Strict"
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               error: "VALIDATION_ERROR"
 *               message: "Invalid login credentials format"
 *               details: ["Valid email is required", "Password must be at least 6 characters long"]
 *       401:
 *         description: Invalid credentials or inactive account
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             examples:
 *               invalid_credentials:
 *                 summary: Invalid email or password
 *                 value:
 *                   error: "INVALID_CREDENTIALS"
 *                   message: "Invalid email or password"
 *               inactive_account:
 *                 summary: Account deactivated
 *                 value:
 *                   error: "ACCOUNT_INACTIVE"
 *                   message: "Your account has been deactivated. Please contact support."
 *       429:
 *         description: Too many login attempts
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               error: "RATE_LIMIT_EXCEEDED"
 *               message: "Too many login attempts. Please try again later."
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               error: "INTERNAL_SERVER_ERROR"
 *               message: "An error occurred during login"
 */
// Login handler
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate request body
    const validationResult = LoginSchema.safeParse(req.body);
    if (!validationResult.success) {
      res.status(400).json({
        success: false,
        message: 'Invalid login credentials format',
        error: 'Validation failed',
        details: validationResult.error.errors,
      } as ApiResponse);
      return;
    }

    const { email, password }: LoginRequest = validationResult.data;

    // Validate credentials
    const user = await databaseService.validateUserCredentials(email, password);
    if (!user) {
      // Use generic message to prevent user enumeration
      res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        error: 'Authentication failed',
      } as ApiResponse);
      return;
    }

    // Check if user is active
    if (!user.isActive) {
      res.status(403).json({
        success: false,
        message: 'Account inactive',
        error: 'Your account has been deactivated',
      } as ApiResponse);
      return;
    }

    // Generate tokens
    const {
      accessToken,
      refreshToken,
      user: sanitizedUser,
    } = authService.generateTokens(user);

    // Set secure cookies
    res.cookie(
      'accessToken',
      accessToken,
      authService.createTokenCookieOptions(false)
    );
    res.cookie(
      'refreshToken',
      refreshToken,
      authService.createTokenCookieOptions(true)
    );

    // Generate CSRF token for form protection
    const csrfToken = authService.createCsrfToken();

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: sanitizedUser,
        accessToken, // Also provide in response for flexibility
        csrfToken,
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: User logout
 *     tags: [Authentication]
 *     description: Logout user and clear authentication cookies
 *     security:
 *       - cookieAuth: []
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Logout successful"
 *         headers:
 *           Set-Cookie:
 *             description: Cleared authentication cookies
 *             schema:
 *               type: string
 *               example: "accessToken=; Path=/api; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
// Logout handler
export const logout = async (_req: Request, res: Response): Promise<void> => {
  try {
    // Clear authentication cookies
    res.clearCookie('accessToken', {
      path: '/api',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.clearCookie('refreshToken', {
      path: '/api/auth/refresh',
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.status(200).json({
      success: true,
      message: 'Logout successful',
    } as ApiResponse);
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Logout failed',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Refresh token handler
export const refreshToken = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      res.status(401).json({
        success: false,
        message: 'Refresh token missing',
        error: 'Authentication required',
      } as ApiResponse);
      return;
    }

    // Verify refresh token
    const decoded = authService.verifyRefreshToken(refreshToken);
    if (!decoded) {
      res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
        error: 'Authentication failed',
      } as ApiResponse);
      return;
    }

    // Get user from database
    const user = await databaseService.findUserById(decoded.userId);
    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'User not found or inactive',
        error: 'Authentication failed',
      } as ApiResponse);
      return;
    }

    // Generate new access token
    const newAccessToken = authService.generateAccessToken(user);

    // Set new access token cookie
    res.cookie(
      'accessToken',
      newAccessToken,
      authService.createTokenCookieOptions(false)
    );

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: newAccessToken,
        user: authService.sanitizeUserForResponse(user),
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Token refresh failed',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Validate token handler
export const validateToken = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    // If we reach here, the token is valid (middleware validated it)
    const user = await databaseService.findUserById(req.user!.userId);

    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        message: 'User not found or inactive',
        error: 'Invalid token',
      } as ApiResponse);
      return;
    }

    res.status(200).json({
      success: true,
      message: 'Token is valid',
      data: {
        user: authService.sanitizeUserForResponse(user),
        isValid: true,
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Token validation error:', error);
    res.status(500).json({
      success: false,
      message: 'Token validation failed',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Get CSRF token handler
export const getCsrfToken = async (
  _req: Request,
  res: Response
): Promise<void> => {
  try {
    const csrfToken = authService.createCsrfToken();

    res.status(200).json({
      success: true,
      message: 'CSRF token generated',
      data: { csrfToken },
    } as ApiResponse);
  } catch (error) {
    console.error('CSRF token generation error:', error);
    res.status(500).json({
      success: false,
      message: 'CSRF token generation failed',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Change password handler
export const changePassword = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      res.status(400).json({
        success: false,
        message: 'Current password and new password are required',
        error: 'Missing required fields',
      } as ApiResponse);
      return;
    }

    // Get current user
    const user = await databaseService.findUserById(req.user!.userId);
    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
        error: 'Invalid user',
      } as ApiResponse);
      return;
    }

    // Validate current password
    const validUser = await databaseService.validateUserCredentials(
      user.email,
      currentPassword
    );
    if (!validUser) {
      res.status(401).json({
        success: false,
        message: 'Current password is incorrect',
        error: 'Authentication failed',
      } as ApiResponse);
      return;
    }

    // Validate new password strength
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      res.status(400).json({
        success: false,
        message:
          'New password must be at least 8 characters with uppercase, lowercase, number and special character',
        error: 'Weak password',
      } as ApiResponse);
      return;
    }

    // Update password
    const success = await databaseService.updatePassword(
      req.user!.userId,
      newPassword
    );
    if (!success) {
      res.status(500).json({
        success: false,
        message: 'Failed to update password',
        error: 'Database error',
      } as ApiResponse);
      return;
    }

    res.status(200).json({
      success: true,
      message: 'Password updated successfully',
    } as ApiResponse);
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({
      success: false,
      message: 'Password change failed',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Export auth controller object for backward compatibility
export const authController = {
  loginValidation,
  login,
  logout,
  refreshToken,
  validateToken,
  getCsrfToken,
  changePassword,
};

export default authController;
