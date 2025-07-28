import jwt from 'jsonwebtoken';
import {
  TokenPayload,
  RefreshTokenPayload,
  User,
  AuthenticatedUser,
} from '../types/index';

// Auth service configuration
interface AuthConfig {
  jwtSecret: string;
  jwtRefreshSecret: string;
  accessTokenExpiry: string;
  refreshTokenExpiry: string;
}

// Create auth configuration
const createAuthConfig = (): AuthConfig => {
  const jwtSecret = process.env.JWT_SECRET;
  const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;

  if (!jwtSecret || !jwtRefreshSecret) {
    throw new Error('JWT secrets must be provided in environment variables');
  }

  return {
    jwtSecret,
    jwtRefreshSecret,
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  };
};

// Generate access token
const generateAccessToken = (config: AuthConfig, user: User): string => {
  const payload: TokenPayload = {
    userId: user._id,
    email: user.email,
    isActive: user.isActive,
  };

  return jwt.sign(payload, config.jwtSecret, {
    expiresIn: config.accessTokenExpiry,
    algorithm: 'HS256',
  } as jwt.SignOptions);
};

// Generate refresh token
const generateRefreshToken = (
  config: AuthConfig,
  user: User,
  tokenVersion: number = 1
): string => {
  const payload: RefreshTokenPayload = {
    userId: user._id,
    email: user.email,
    tokenVersion,
  };

  return jwt.sign(payload, config.jwtRefreshSecret, {
    expiresIn: config.refreshTokenExpiry,
    algorithm: 'HS256',
  } as jwt.SignOptions);
};

// Verify access token
const verifyAccessToken = (
  config: AuthConfig,
  token: string
): TokenPayload | null => {
  try {
    const decoded = jwt.verify(token, config.jwtSecret, {
      algorithms: ['HS256'],
    }) as TokenPayload;

    return decoded;
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      console.warn('Invalid JWT token:', error.message);
    } else if (error instanceof jwt.TokenExpiredError) {
      console.warn('JWT token expired:', error.message);
    } else {
      console.error('JWT verification error:', error);
    }
    return null;
  }
};

// Verify refresh token
const verifyRefreshToken = (
  config: AuthConfig,
  token: string
): RefreshTokenPayload | null => {
  try {
    const decoded = jwt.verify(token, config.jwtRefreshSecret, {
      algorithms: ['HS256'],
    }) as RefreshTokenPayload;

    return decoded;
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      console.warn('Invalid refresh token:', error.message);
    } else if (error instanceof jwt.TokenExpiredError) {
      console.warn('Refresh token expired:', error.message);
    } else {
      console.error('Refresh token verification error:', error);
    }
    return null;
  }
};

// Extract token from authorization header
const extractTokenFromHeader = (
  authHeader: string | undefined
): string | null => {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  return authHeader.substring(7); // Remove 'Bearer ' prefix
};

// Sanitize user for response (remove password)
const sanitizeUserForResponse = (user: User): AuthenticatedUser => {
  const { password: _password, ...userWithoutPassword } = user;
  return userWithoutPassword;
};

// Create token cookie options
const createTokenCookieOptions = (isRefreshToken: boolean = false) => {
  const maxAge = isRefreshToken
    ? 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
    : 15 * 60 * 1000; // 15 minutes in milliseconds

  const sameSite = process.env.NODE_ENV === 'production' ? 'none' : 'lax';
  
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: sameSite as 'none' | 'lax',
    maxAge,
    path: isRefreshToken ? '/api/auth/refresh' : '/api',
  };
};

// Generate both access and refresh tokens
const generateTokens = (
  config: AuthConfig,
  user: User,
  tokenVersion: number = 1
) => {
  const accessToken = generateAccessToken(config, user);
  const refreshToken = generateRefreshToken(config, user, tokenVersion);

  return {
    accessToken,
    refreshToken,
    user: sanitizeUserForResponse(user),
  };
};

// Decode token without verification
const decodeTokenWithoutVerification = (
  token: string
): TokenPayload | RefreshTokenPayload | null => {
  try {
    const decoded = jwt.decode(token) as TokenPayload | RefreshTokenPayload;
    return decoded;
  } catch (error) {
    console.error('Token decode error:', error);
    return null;
  }
};

// Check if token is expired
const isTokenExpired = (token: string): boolean => {
  const decoded = decodeTokenWithoutVerification(token);
  if (!decoded || !decoded.exp) {
    return true;
  }

  const currentTime = Math.floor(Date.now() / 1000);
  return decoded.exp < currentTime;
};

// Get token expiration time
const getTokenExpirationTime = (token: string): Date | null => {
  const decoded = decodeTokenWithoutVerification(token);
  if (!decoded || !decoded.exp) {
    return null;
  }

  return new Date(decoded.exp * 1000);
};

// Create CSRF token
const createCsrfToken = (config: AuthConfig): string => {
  // Simple CSRF token generation
  return jwt.sign(
    {
      purpose: 'csrf',
      timestamp: Date.now(),
    },
    config.jwtSecret,
    {
      expiresIn: '1h',
      algorithm: 'HS256',
    }
  );
};

// Verify CSRF token
const verifyCsrfToken = (config: AuthConfig, token: string): boolean => {
  try {
    const decoded = jwt.verify(token, config.jwtSecret, {
      algorithms: ['HS256'],
    }) as { purpose: string; timestamp: number };

    return decoded.purpose === 'csrf';
  } catch {
    return false;
  }
};

// Create auth service instance
const authConfig = createAuthConfig();

// Export functional auth service
export const authService = {
  generateAccessToken: (user: User) => generateAccessToken(authConfig, user),
  generateRefreshToken: (user: User, tokenVersion?: number) =>
    generateRefreshToken(authConfig, user, tokenVersion),
  verifyAccessToken: (token: string) => verifyAccessToken(authConfig, token),
  verifyRefreshToken: (token: string) => verifyRefreshToken(authConfig, token),
  extractTokenFromHeader,
  sanitizeUserForResponse,
  createTokenCookieOptions,
  generateTokens: (user: User, tokenVersion?: number) =>
    generateTokens(authConfig, user, tokenVersion),
  decodeTokenWithoutVerification,
  isTokenExpired,
  getTokenExpirationTime,
  createCsrfToken: () => createCsrfToken(authConfig),
  verifyCsrfToken: (token: string) => verifyCsrfToken(authConfig, token),
};

export default authService;
