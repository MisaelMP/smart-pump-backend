import express from 'express';
import cookieParser from 'cookie-parser';
import { createServer } from 'http';
import {
  validateConfiguration,
  showConfiguration,
  serverConfig,
  env,
} from './config/enviorment';
import { databaseService } from './database/database';
import routes from './routes/index';
import {
  helmetMiddleware,
  corsMiddleware,
  errorHandler,
  requestLogger,
} from './middleware/index';

// Server state interface
interface ServerState {
  app: express.Application;
  server: ReturnType<typeof createServer> | null;
}

// Create Express application
const createApp = (): express.Application => {
  const app = express();
  return app;
};

// Setup configuration
const setupConfiguration = (): void => {
  try {
    validateConfiguration();
    showConfiguration();
  } catch (error) {
    console.error('Configuration error:', error);
    process.exit(1);
  }
};

// Setup middleware
const setupMiddleware = (app: express.Application): void => {
  // Trust proxy if in production (for proper IP detection behind load balancers)
  if (serverConfig.trustProxy) {
    app.set('trust proxy', 1);
  }

  // Security middleware (must be first)
  app.use(helmetMiddleware);
  app.use(corsMiddleware);

  // Request logging
  app.use(requestLogger);

  // Body parsing middleware
  app.use(
    express.json({
      limit: '10mb',
      strict: true,
    })
  );
  app.use(
    express.urlencoded({
      extended: true,
      limit: '10mb',
    })
  );

  // Cookie parsing
  app.use(cookieParser());

  console.log('Middleware configured');
};

// Setup routes
const setupRoutes = (app: express.Application): void => {
  // API routes
  app.use('/api', routes);

  // Root endpoint
  app.get('/', (_req, res) => {
    res.json({
      success: true,
      message: 'Welcome to SMART Pump API',
      data: {
        name: 'SMART Pump User Management System',
        version: '1.0.0',
        environment: env.NODE_ENV,
        apiDocumentation: '/api/docs',
        healthCheck: '/api/health',
        timestamp: new Date().toISOString(),
      },
    });
  });

  console.log('Routes configured');
};

// Graceful shutdown handler
const createGracefulShutdown =
  (server: ReturnType<typeof createServer> | null) =>
  async (signal: string): Promise<void> => {
    console.log(`Graceful shutdown initiated by ${signal}`);

    try {
      // Stop accepting new requests
      if (server) {
        server.close(() => {
          console.log('HTTP server closed');
        });
      }

      // Close database connection
      databaseService.close();
      console.log('Database connection closed');

      console.log('Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      console.error('Error during graceful shutdown:', error);
      process.exit(1);
    }
  };

// Setup error handling
const setupErrorHandling = (
  app: express.Application,
  gracefulShutdown: (signal: string) => Promise<void>
): void => {
  // Global error handler (must be last)
  app.use(errorHandler);

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    gracefulShutdown('UNHANDLED_REJECTION');
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
  });

  // Handle termination signals
  process.on('SIGTERM', () => {
    console.log('SIGTERM received');
    gracefulShutdown('SIGTERM');
  });

  process.on('SIGINT', () => {
    console.log('SIGINT received');
    gracefulShutdown('SIGINT');
  });

  console.log('Error handling configured');
};

// Handle server errors
const handleServerError = (error: NodeJS.ErrnoException): void => {
  if (error.syscall !== 'listen') {
    throw error;
  }

  switch (error.code) {
    case 'EACCES':
      console.error(`Port ${serverConfig.port} requires elevated privileges`);
      process.exit(1);
    case 'EADDRINUSE':
      console.error(`Port ${serverConfig.port} is already in use`);
      process.exit(1);
    default:
      throw error;
  }
};

// Log server start information
const logServerStart = (): void => {
  console.log('SMART Pump API Server Started');
  console.log(
    `Server running on http://${serverConfig.host}:${serverConfig.port}`
  );
  console.log(`Environment: ${env.NODE_ENV}`);
  console.log(
    `API Documentation: http://${serverConfig.host}:${serverConfig.port}/api/docs`
  );
  console.log(
    `Health Check: http://${serverConfig.host}:${serverConfig.port}/api/health`
  );

  if (env.NODE_ENV === 'development') {
    console.log(`Frontend URL: ${env.FRONTEND_URL}`);
    console.log(`Database: ${env.DB_PATH}`);
    console.log('');
    console.log('Development Test Users:');
    console.log(
      '   Email: henderson.briggs@geeknet.net | Password: TestPass123!'
    );
    console.log('   Email: lott.kramer@poshome.us | Password: TestPass456!');
    console.log('   Email: gibson.duke@zillar.com | Password: TestPass789!');
    console.log(
      '   Email: ruby.glenn@waterbaby.co.uk | Password: TestPass000!'
    );
    console.log('   WARNING: Development passwords only - not for production');
  }
};

// Initialize server state
const createServerState = (): ServerState => ({
  app: createApp(),
  server: null,
});

// Start server function
const startServer = async (state: ServerState): Promise<void> => {
  try {
    // Setup configuration
    setupConfiguration();

    // Setup middleware
    setupMiddleware(state.app);

    // Setup routes
    setupRoutes(state.app);

    // Create graceful shutdown handler
    const gracefulShutdown = createGracefulShutdown(state.server);

    // Setup error handling
    setupErrorHandling(state.app, gracefulShutdown);

    // Initialize database
    console.log('Initializing database...');
    await databaseService.initialize();

    // Start HTTP server
    state.server = createServer(state.app);

    state.server.listen(serverConfig.port, serverConfig.host, () => {
      logServerStart();
    });

    state.server.on('error', handleServerError);
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Create and export server functions
const serverState = createServerState();

export const server = {
  start: () => startServer(serverState),
  getApp: () => serverState.app,
};

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  server.start().catch((error) => {
    console.error('Server startup failed:', error);
    process.exit(1);
  });
}

export default server;
