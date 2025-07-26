import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { Application, Request, Response } from 'express';
import { env } from './environment.config.js';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'SMART Pump API',
      version: '1.0.0',
      description: 'API for SMART Pump User Management System',
      contact: {
        name: 'SMART Pump Team',
        email: 'support@smartpump.com',
      },
      license: {
        name: 'MIT',
        url: 'https://opensource.org/licenses/MIT',
      },
    },
    servers: [
      {
        url:
          env.NODE_ENV === 'production'
            ? 'https://api.smartpump.com'
            : `http://localhost:${env.PORT}`,
        description:
          env.NODE_ENV === 'production'
            ? 'Production server'
            : 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
        cookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'auth-token',
        },
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            _id: {
              type: 'string',
              description: 'Unique user identifier',
              example: '5410953eb0e0c0ae25608277',
            },
            guid: {
              type: 'string',
              description: 'Global unique identifier',
              example: 'eab0324c-75ef-49a1-9c49-be2d68f50b96',
            },
            isActive: {
              type: 'boolean',
              description: 'Whether the user account is active',
              example: true,
            },
            balance: {
              type: 'string',
              description: 'User account balance',
              example: '$3,585.69',
            },
            picture: {
              type: 'string',
              description: 'User profile picture URL',
              example: 'http://placehold.it/32x32',
            },
            age: {
              type: 'number',
              description: 'User age',
              example: 30,
            },
            eyeColor: {
              type: 'string',
              enum: ['blue', 'brown', 'green', 'hazel', 'amber', 'gray'],
              description: 'User eye color',
              example: 'blue',
            },
            name: {
              type: 'object',
              properties: {
                first: {
                  type: 'string',
                  description: 'First name',
                  example: 'Henderson',
                },
                last: {
                  type: 'string',
                  description: 'Last name',
                  example: 'Briggs',
                },
              },
              required: ['first', 'last'],
            },
            company: {
              type: 'string',
              description: 'Company name',
              example: 'GEEKNET',
            },
            email: {
              type: 'string',
              format: 'email',
              description: 'User email address',
              example: 'henderson.briggs@geeknet.net',
            },
            phone: {
              type: 'string',
              description: 'Phone number',
              example: '+1 (936) 451-3590',
            },
            address: {
              type: 'string',
              description: 'Physical address',
              example: '121 National Drive, Cotopaxi, Michigan, 8240',
            },
          },
          required: ['_id', 'email', 'name', 'isActive'],
        },
        LoginRequest: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: {
              type: 'string',
              format: 'email',
              description: 'User email address',
              example: 'henderson.briggs@geeknet.net',
            },
            password: {
              type: 'string',
              minLength: 6,
              description: 'User password',
              example: 'password123',
            },
          },
        },
        LoginResponse: {
          type: 'object',
          properties: {
            user: {
              $ref: '#/components/schemas/User',
              description: 'User information',
            },
            message: {
              type: 'string',
              description: 'Success message',
              example: 'Login successful',
            },
          },
        },
        UpdateUserRequest: {
          type: 'object',
          properties: {
            name: {
              type: 'object',
              properties: {
                first: { type: 'string', example: 'John' },
                last: { type: 'string', example: 'Doe' },
              },
            },
            company: {
              type: 'string',
              example: 'ACME Corp',
            },
            email: {
              type: 'string',
              format: 'email',
              example: 'john.doe@acme.com',
            },
            phone: {
              type: 'string',
              example: '+1 (555) 123-4567',
            },
            address: {
              type: 'string',
              example: '123 Main St, Anytown, USA, 12345',
            },
          },
        },
        BalanceInfo: {
          type: 'object',
          properties: {
            current: {
              type: 'string',
              description: 'Current balance',
              example: '$3,585.69',
            },
            available: {
              type: 'string',
              description: 'Available balance',
              example: '$3,585.69',
            },
            pending: {
              type: 'string',
              description: 'Pending transactions',
              example: '$0.00',
            },
          },
        },
        AccountSummary: {
          type: 'object',
          properties: {
            totalTransactions: {
              type: 'number',
              description: 'Total number of transactions',
              example: 42,
            },
            lastLogin: {
              type: 'string',
              format: 'date-time',
              description: 'Last login timestamp',
              example: '2024-01-15T10:30:00Z',
            },
            accountAge: {
              type: 'number',
              description: 'Account age in days',
              example: 365,
            },
          },
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            error: {
              type: 'string',
              description: 'Error code',
              example: 'INVALID_CREDENTIALS',
            },
            message: {
              type: 'string',
              description: 'Human-readable error message',
              example: 'Invalid email or password',
            },
            details: {
              type: 'array',
              items: { type: 'string' },
              description: 'Additional error details',
              example: [
                'Email is required',
                'Password must be at least 6 characters',
              ],
            },
          },
        },
        HealthResponse: {
          type: 'object',
          properties: {
            status: {
              type: 'string',
              example: 'healthy',
            },
            timestamp: {
              type: 'string',
              format: 'date-time',
              example: '2024-01-15T10:30:00Z',
            },
            version: {
              type: 'string',
              example: '1.0.0',
            },
          },
        },
      },
    },
    security: [{ bearerAuth: [] }, { cookieAuth: [] }],
  },
  apis: ['./src/routes/*.ts', './src/controllers/*.ts'], // Path to the API routes
};

const openAPISpec = swaggerJsdoc(options);

export const setupOpenAPI = (app: Application): void => {
  // Serve the OpenAPI documentation UI
  app.use(
    '/api/docs',
    swaggerUi.serve,
    swaggerUi.setup(openAPISpec, {
      customCss: `
      .swagger-ui .topbar { display: none; }
      .swagger-ui .info hgroup.main h2 { color: #3b82f6; }
      .swagger-ui .scheme-container { background: #f8fafc; padding: 20px; border-radius: 8px; }
    `,
      customSiteTitle: 'SMART Pump API Documentation',
      customfavIcon: '/favicon.ico',
      swaggerOptions: {
        persistAuthorization: true,
        displayRequestDuration: true,
        filter: true,
        tryItOutEnabled: true,
      },
    })
  );

  // Serve OpenAPI spec as JSON (following OpenAPI naming convention)
  app.get('/openapi.json', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(openAPISpec);
  });

  // Legacy endpoint for backward compatibility
  app.get('/api/docs.json', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(openAPISpec);
  });
};

export { openAPISpec };
