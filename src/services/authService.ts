import jwt from 'jsonwebtoken';
import {
	TokenPayload,
	RefreshTokenPayload,
	User,
	AuthenticatedUser,
} from '../types/index.js';

class AuthService {
	private readonly jwtSecret: string;
	private readonly jwtRefreshSecret: string;
	private readonly accessTokenExpiry = '15m';
	private readonly refreshTokenExpiry = '7d';

	constructor() {
		this.jwtSecret = process.env.JWT_SECRET!;
		this.jwtRefreshSecret = process.env.JWT_REFRESH_SECRET!;

		if (!this.jwtSecret || !this.jwtRefreshSecret) {
			throw new Error('JWT secrets must be provided in environment variables');
		}
	}

	generateAccessToken(user: User): string {
		const payload: TokenPayload = {
			userId: user._id,
			email: user.email,
			isActive: user.isActive,
		};

		return jwt.sign(payload, this.jwtSecret, {
			expiresIn: this.accessTokenExpiry,
			algorithm: 'HS256',
		});
	}

	generateRefreshToken(user: User, tokenVersion: number = 1): string {
		const payload: RefreshTokenPayload = {
			userId: user._id,
			email: user.email,
			tokenVersion,
		};

		return jwt.sign(payload, this.jwtRefreshSecret, {
			expiresIn: this.refreshTokenExpiry,
			algorithm: 'HS256',
		});
	}

	verifyAccessToken(token: string): TokenPayload | null {
		try {
			const decoded = jwt.verify(token, this.jwtSecret, {
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
	}

	verifyRefreshToken(token: string): RefreshTokenPayload | null {
		try {
			const decoded = jwt.verify(token, this.jwtRefreshSecret, {
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
	}

	extractTokenFromHeader(authHeader: string | undefined): string | null {
		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return null;
		}

		return authHeader.substring(7); // Remove 'Bearer ' prefix
	}

	sanitizeUserForResponse(user: User): AuthenticatedUser {
		const { password, ...userWithoutPassword } = user;
		return userWithoutPassword;
	}

	createTokenCookieOptions(isRefreshToken: boolean = false) {
		const maxAge = isRefreshToken
			? 7 * 24 * 60 * 60 * 1000 // 7 days in milliseconds
			: 15 * 60 * 1000; // 15 minutes in milliseconds

		return {
			httpOnly: true,
			secure: process.env.NODE_ENV === 'production',
			sameSite: 'strict' as const,
			maxAge,
			path: isRefreshToken ? '/api/auth/refresh' : '/api',
		};
	}

	generateTokens(user: User, tokenVersion: number = 1) {
		const accessToken = this.generateAccessToken(user);
		const refreshToken = this.generateRefreshToken(user, tokenVersion);

		return {
			accessToken,
			refreshToken,
			user: this.sanitizeUserForResponse(user),
		};
	}

	decodeTokenWithoutVerification(
		token: string
	): TokenPayload | RefreshTokenPayload | null {
		try {
			const decoded = jwt.decode(token) as TokenPayload | RefreshTokenPayload;
			return decoded;
		} catch (error) {
			console.error('Token decode error:', error);
			return null;
		}
	}

	isTokenExpired(token: string): boolean {
		const decoded = this.decodeTokenWithoutVerification(token);
		if (!decoded || !decoded.exp) {
			return true;
		}

		const currentTime = Math.floor(Date.now() / 1000);
		return decoded.exp < currentTime;
	}

	getTokenExpirationTime(token: string): Date | null {
		const decoded = this.decodeTokenWithoutVerification(token);
		if (!decoded || !decoded.exp) {
			return null;
		}

		return new Date(decoded.exp * 1000);
	}

	createCsrfToken(): string {
		// Simple CSRF token generation
		return jwt.sign(
			{
				purpose: 'csrf',
				timestamp: Date.now(),
			},
			this.jwtSecret,
			{
				expiresIn: '1h',
				algorithm: 'HS256',
			}
		);
	}

	verifyCsrfToken(token: string): boolean {
		try {
			const decoded = jwt.verify(token, this.jwtSecret, {
				algorithms: ['HS256'],
			}) as { purpose: string; timestamp: number };

			return decoded.purpose === 'csrf';
		} catch (error) {
			return false;
		}
	}
}

export const authService = new AuthService();
export default authService;
