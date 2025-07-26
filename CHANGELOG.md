# Changelog

All notable changes to the SMART Pump API will be documented here.

## [1.0.0] - 2025-01-26

### Added

- JWT-based authentication with access and refresh tokens
- Rate limiting for brute force protection (5 login attempts per 15 minutes)
- HttpOnly cookies with CSRF protection
- User management endpoints (profile, balance, account summary)
- Input validation and sanitization with Zod
- Swagger/OpenAPI documentation at `/api/docs`
- Modular middleware architecture
- Environment-based configuration
- Comprehensive logging with request tracking
- Development hot-reload with tsx

### Security Features

- Password hashing with bcrypt
- Helmet.js security headers
- CORS protection
- Input sanitization
- Structured error handling
- JWT token expiration (15min access, 7d refresh)

### API Endpoints

- Authentication: `/api/auth/*`
- User Management: `/api/user/*`
- System: `/api/health`, `/api/docs`

### Development Experience

- TypeScript with strict mode
- ESLint + Prettier code formatting
- Hot reload development server
- Clear project structure
- Comprehensive documentation
