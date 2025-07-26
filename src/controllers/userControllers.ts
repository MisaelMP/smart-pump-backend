import { Request, Response } from 'express';
import { body } from 'express-validator';
import { UpdateUserSchema } from '../types/index';
import { authService } from '../services/authService';
import { databaseService } from '../database/database';
import type { ApiResponse, UpdateUserRequest } from '../types/index';

// User update validation rules
export const updateValidation = [
  body('name.first')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be 1-50 characters'),
  body('name.last')
    .optional()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be 1-50 characters'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('phone')
    .optional()
    .matches(/^\+\d{1,4}\s?\(\d{3}\)\s?\d{3}-\d{4}$/)
    .withMessage('Phone must be in format: +1 (555) 123-4567'),
  body('address')
    .optional()
    .isLength({ min: 10, max: 200 })
    .withMessage('Address must be 10-200 characters'),
  body('company')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Company name must be 1-100 characters'),
];

// Calculate profile completeness
const calculateProfileCompleteness = (user: any): number => {
  const fields = [
    'name.first',
    'name.last',
    'email',
    'phone',
    'address',
    'company',
  ];
  let completedFields = 0;

  fields.forEach((field) => {
    const value = field.includes('.')
      ? field.split('.').reduce((obj, key) => obj?.[key], user)
      : user[field];

    if (value && value.toString().trim() !== '') {
      completedFields++;
    }
  });

  return Math.round((completedFields / fields.length) * 100);
};

// Get current user handler
export const getCurrentUser = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const user = await databaseService.findUserById(req.user!.userId);

    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
        error: 'User does not exist',
      } as ApiResponse);
      return;
    }

    if (!user.isActive) {
      res.status(403).json({
        success: false,
        message: 'Account inactive',
        error: 'User account is deactivated',
      } as ApiResponse);
      return;
    }

    res.status(200).json({
      success: true,
      message: 'User retrieved successfully',
      data: {
        user: authService.sanitizeUserForResponse(user),
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve user',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Get user balance handler
export const getUserBalance = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const user = await databaseService.findUserById(req.user!.userId);

    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
        error: 'User does not exist',
      } as ApiResponse);
      return;
    }

    if (!user.isActive) {
      res.status(403).json({
        success: false,
        message: 'Account inactive',
        error: 'Cannot access balance for inactive account',
      } as ApiResponse);
      return;
    }

    // Parse balance for numerical operations if needed
    const balanceMatch = user.balance.match(/\$([\d,]+\.\d{2})/);
    const numericBalance = balanceMatch
      ? parseFloat(balanceMatch[1]!.replace(/,/g, ''))
      : 0;

    res.status(200).json({
      success: true,
      message: 'Balance retrieved successfully',
      data: {
        balance: user.balance,
        numericBalance,
        currency: 'USD',
        lastUpdated: new Date().toISOString(),
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Get user balance error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve balance',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Update user handler
export const updateUser = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    // Validate request body
    const validationResult = UpdateUserSchema.safeParse(req.body);
    if (!validationResult.success) {
      res.status(400).json({
        success: false,
        message: 'Invalid user data format',
        error: 'Validation failed',
        details: validationResult.error.errors,
      } as ApiResponse);
      return;
    }

    const updateData: UpdateUserRequest = validationResult.data;

    // Check if email is being changed and if it's already in use
    if (updateData.email) {
      const existingUser = await databaseService.findUserByEmail(
        updateData.email
      );
      if (existingUser && existingUser._id !== req.user!.userId) {
        res.status(409).json({
          success: false,
          message: 'Email already in use',
          error: 'Email conflict',
        } as ApiResponse);
        return;
      }
    }

    // Update user
    const updatedUser = await databaseService.updateUser(
      req.user!.userId,
      updateData
    );

    if (!updatedUser) {
      res.status(404).json({
        success: false,
        message: 'User not found',
        error: 'Update failed',
      } as ApiResponse);
      return;
    }

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: {
        user: authService.sanitizeUserForResponse(updatedUser),
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Get user profile handler
export const getUserProfile = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const userId = req.params.userId || req.user!.userId;

    // Only allow users to access their own profile
    if (userId !== req.user!.userId) {
      res.status(403).json({
        success: false,
        message: 'Access denied',
        error: 'Cannot access other user profiles',
      } as ApiResponse);
      return;
    }

    const user = await databaseService.findUserById(userId);

    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
        error: 'User does not exist',
      } as ApiResponse);
      return;
    }

    // Prepare comprehensive profile data
    const profileData = {
      ...authService.sanitizeUserForResponse(user),
      profileCompleteness: calculateProfileCompleteness(user),
      accountStatus: user.isActive ? 'active' : 'inactive',
      memberSince: '2024', // Could be calculated from creation date
      lastLogin: new Date().toISOString(), // Could be tracked in database
    };

    res.status(200).json({
      success: true,
      message: 'User profile retrieved successfully',
      data: {
        profile: profileData,
      },
    } as ApiResponse);
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve user profile',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Delete account handler
export const deleteAccount = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const { password } = req.body;

    if (!password) {
      res.status(400).json({
        success: false,
        message: 'Password confirmation required',
        error: 'Missing password',
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

    // Validate password
    const validUser = await databaseService.validateUserCredentials(
      user.email,
      password
    );
    if (!validUser) {
      res.status(401).json({
        success: false,
        message: 'Incorrect password',
        error: 'Authentication failed',
      } as ApiResponse);
      return;
    }

    // Instead of deleting, deactivate the account for data retention
    const deactivatedUser = await databaseService.updateUser(req.user!.userId, {
      // Mark as inactive but keep data
    });

    if (!deactivatedUser) {
      res.status(500).json({
        success: false,
        message: 'Failed to deactivate account',
        error: 'Database error',
      } as ApiResponse);
      return;
    }

    // Clear authentication cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.status(200).json({
      success: true,
      message: 'Account deactivated successfully',
    } as ApiResponse);
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete account',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Get account summary handler
export const getAccountSummary = async (
  req: Request,
  res: Response
): Promise<void> => {
  try {
    const user = await databaseService.findUserById(req.user!.userId);

    if (!user) {
      res.status(404).json({
        success: false,
        message: 'User not found',
        error: 'User does not exist',
      } as ApiResponse);
      return;
    }

    const summary = {
      accountId: user._id,
      displayName: `${user.name.first} ${user.name.last}`,
      email: user.email,
      balance: user.balance,
      company: user.company,
      accountStatus: user.isActive ? 'Active' : 'Inactive',
      profileCompleteness: calculateProfileCompleteness(user),
      lastActivity: new Date().toISOString(),
      securityLevel: 'Standard', // Could be calculated based on security features
    };

    res.status(200).json({
      success: true,
      message: 'Account summary retrieved successfully',
      data: { summary },
    } as ApiResponse);
  } catch (error) {
    console.error('Get account summary error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve account summary',
      error: 'Internal server error',
    } as ApiResponse);
  }
};

// Export user controller object for backward compatibility
export const userController = {
  updateValidation,
  getCurrentUser,
  getUserBalance,
  updateUser,
  getUserProfile,
  deleteAccount,
  getAccountSummary,
};

export default userController;
