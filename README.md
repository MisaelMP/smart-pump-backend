# SMART Pump API

A modern, secure REST API for user management with JWT authentication, built with Node.js, Express, and TypeScript.

## What This Does

This API powers user authentication and account management for the SMART Pump application. It handles everything from secure login/logout to user profiles and account data—all while protecting against common security threats.

## Key Features

- **Secure Authentication**: JWT tokens with automatic refresh
- **Rate Limiting**: Prevents brute force attacks (5 login attempts per 15 minutes)
- **Cookie Security**: HttpOnly cookies with CSRF protection
- **User Management**: Profile, balance, and account summary endpoints
- **Input Validation**: All data validated and sanitized
- **API Documentation**: Built-in Swagger docs at `/api/docs`

## Quick Start

1. **Install dependencies**

   ```bash
   npm install
   ```

2. **Set up environment**

   ```bash
   cp .env.example .env
   # Edit .env with your settings (JWT secrets are auto-generated for development)
   ```

3. **Start the server**

   ```bash
   npm run dev
   ```

4. **Test it's working**
   - API: http://localhost:3001/api/health
   - Docs: http://localhost:3001/api/docs

## Try It Out

The API comes with test users ready to go:

```javascript
// Test accounts (password: "password123")
{
  email: "john.doe@example.com",
  name: "John Doe"
}
```

**Demo the Security Features:**

1. Try logging in with wrong password 5 times → Gets rate limited
2. Other endpoints (logout, refresh) still work fine
3. Shows production-ready brute force protection

## Project Structure

```
src/
├── controllers/     # Handle HTTP requests and responses
├── middleware/      # Authentication, validation, security
├── services/        # Business logic (JWT, auth)
├── routes/          # API endpoint definitions
├── config/          # Environment and OpenAPI setup
├── database/        # Simple JSON database
└── types/           # TypeScript type definitions
```

## Available Scripts

```bash
npm run dev          # Start development server with hot reload
npm run build        # Build for production
npm start           # Run production server
npm run lint        # Check code quality
npm run format      # Auto-format code
```

## API Endpoints

### Authentication

- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/logout` - Logout and clear tokens
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/validate` - Check if token is valid

### User Management

- `GET /api/user/profile` - Get user profile
- `PUT /api/user/profile` - Update profile
- `GET /api/user/balance` - Get account balance
- `GET /api/user/summary` - Get account summary

### System

- `GET /api/health` - Health check
- `GET /api/docs` - API documentation

## Security Features

- **JWT Authentication**: Short-lived access tokens (15 min) with long-lived refresh tokens (7 days)
- **Rate Limiting**: 5 login attempts per 15 minutes, 100 requests per 15 minutes for other endpoints
- **CSRF Protection**: Required for state-changing operations
- **Input Validation**: Zod schema validation on all inputs
- **Security Headers**: Helmet.js with CSP
- **Password Hashing**: bcrypt with salt rounds

## Tech Stack

- **Runtime**: Node.js + TypeScript
- **Framework**: Express.js
- **Authentication**: JWT + bcrypt
- **Database**: LowDB (JSON file storage)
- **Validation**: Zod
- **Documentation**: Swagger/OpenAPI
- **Security**: Helmet, Rate Limiting, CORS

## Configuration

Key environment variables:

```bash
NODE_ENV=development        # Environment mode
PORT=3001                  # Server port
JWT_SECRET=your_secret     # JWT signing secret
JWT_REFRESH_SECRET=secret  # Refresh token secret
FRONTEND_URL=http://localhost:3000  # CORS origin
```

## Development Notes

- **Hot Reload**: Uses `tsx watch` for instant restarts during development
- **Type Safety**: Full TypeScript coverage with strict mode
- **Code Quality**: ESLint + Prettier for consistent formatting
- **Modular Design**: Clean separation of concerns with middleware pattern
