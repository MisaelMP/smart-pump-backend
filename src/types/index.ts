import { z } from 'zod';

// Database User Schema
export const UserSchema = z.object({
	_id: z.string(),
	guid: z.string().uuid(),
	isActive: z.boolean(),
	balance: z.string().regex(/^\$[\d,]+\.\d{2}$/),
	picture: z.string().url(),
	age: z.number().min(18).max(120),
	eyeColor: z.enum(['blue', 'brown', 'green', 'hazel', 'amber', 'gray']),
	name: z.object({
		first: z.string().min(1).max(50),
		last: z.string().min(1).max(50),
	}),
	company: z.string().min(1).max(100),
	email: z.string().email(),
	password: z.string().min(8),
	phone: z.string().regex(/^\+\d{1,4}\s?\(\d{3}\)\s?\d{3}-\d{4}$/),
	address: z.string().min(10).max(200),
});

export type User = z.infer<typeof UserSchema>;

// API Schemas
export const LoginSchema = z.object({
	email: z.string().email('Invalid email format'),
	password: z.string().min(8, 'Password must be at least 8 characters'),
});

export const UpdateUserSchema = z.object({
	name: z
		.object({
			first: z.string().min(1).max(50),
			last: z.string().min(1).max(50),
		})
		.optional(),
	email: z.string().email().optional(),
	phone: z
		.string()
		.regex(/^\+\d{1,4}\s?\(\d{3}\)\s?\d{3}-\d{4}$/)
		.optional(),
	address: z.string().min(10).max(200).optional(),
	company: z.string().min(1).max(100).optional(),
});

export type LoginRequest = z.infer<typeof LoginSchema>;
export type UpdateUserRequest = z.infer<typeof UpdateUserSchema>;

// API Response Types
export interface ApiResponse<T = unknown> {
	success: boolean;
	message: string;
	data?: T;
	error?: string;
}

export interface AuthenticatedUser {
	_id: string;
	guid: string;
	isActive: boolean;
	balance: string;
	name: {
		first: string;
		last: string;
	};
	email: string;
	company: string;
	phone: string;
	address: string;
	picture: string;
	age: number;
	eyeColor: string;
}

export interface TokenPayload {
	userId: string;
	email: string;
	isActive: boolean;
	iat?: number;
	exp?: number;
}

export interface RefreshTokenPayload {
	userId: string;
	email: string;
	tokenVersion: number;
	iat?: number;
	exp?: number;
}

// Database Schema
export interface DatabaseSchema {
	users: User[];
}

// Express Request Extensions
declare global {
	namespace Express {
		interface Request {
			user?: TokenPayload;
		}
	}
}

// Environment Variables Schema
export const EnvSchema = z.object({
	NODE_ENV: z
		.enum(['development', 'production', 'test'])
		.default('development'),
	PORT: z.string().regex(/^\d+$/).transform(Number).default('3001'),
	JWT_SECRET: z.string().min(32),
	JWT_REFRESH_SECRET: z.string().min(32),
	FRONTEND_URL: z.string().url().default('http://localhost:3000'),
	DB_PATH: z.string().default('./data/db.json'),
});

export type Environment = z.infer<typeof EnvSchema>;

// Rate Limiting Types
export interface RateLimitConfig {
	windowMs: number;
	max: number;
	message: string;
}

// Security Headers Config
export interface SecurityConfig {
	helmet: {
		contentSecurityPolicy: {
			directives: Record<string, string[]>;
		};
		hsts: {
			maxAge: number;
			includeSubDomains: boolean;
			preload: boolean;
		};
	};
	cors: {
		origin: string | string[];
		credentials: boolean;
		methods: string[];
		allowedHeaders: string[];
	};
}
