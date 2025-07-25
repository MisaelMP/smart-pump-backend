import express from 'express';
import cookieParser from 'cookie-parser';
import { createServer } from 'http';
import {
	validateConfiguration,
	showConfiguration,
	serverConfig,
	env,
} from './config/enviorment.js';
import { databaseService } from './database/database.js';
import routes from './routes/index.js';
import {
	helmetMiddleware,
	corsMiddleware,
	errorHandler,
	requestLogger,
} from './middleware/index.js';

class SmartPumpServer {
	private app: express.Application;
	private server: ReturnType<typeof createServer> | null = null;

	constructor() {
		this.app = express();
		this.setupConfiguration();
		this.setupMiddleware();
		this.setupRoutes();
		this.setupErrorHandling();
	}

	private setupConfiguration(): void {
		try {
			validateConfiguration();
			showConfiguration();
		} catch (error) {
			console.error('❌ Configuration error:', error);
			process.exit(1);
		}
	}

	private setupMiddleware(): void {
		// Trust proxy if in production (for proper IP detection behind load balancers)
		if (serverConfig.trustProxy) {
			this.app.set('trust proxy', 1);
		}

		// Security middleware (must be first)
		this.app.use(helmetMiddleware);
		this.app.use(corsMiddleware);

		// Request logging
		this.app.use(requestLogger);

		// Body parsing middleware
		this.app.use(
			express.json({
				limit: '10mb',
				strict: true,
			})
		);
		this.app.use(
			express.urlencoded({
				extended: true,
				limit: '10mb',
			})
		);

		// Cookie parsing
		this.app.use(cookieParser());

		console.log('✅ Middleware configured');
	}

	private setupRoutes(): void {
		// API routes
		this.app.use('/api', routes);

		// Root endpoint
		this.app.get('/', (req, res) => {
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

		console.log('✅ Routes configured');
	}

	private setupErrorHandling(): void {
		// Global error handler (must be last)
		this.app.use(errorHandler);

		// Handle unhandled promise rejections
		process.on('unhandledRejection', (reason, promise) => {
			console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
			this.gracefulShutdown('UNHANDLED_REJECTION');
		});

		// Handle uncaught exceptions
		process.on('uncaughtException', (error) => {
			console.error('🚨 Uncaught Exception:', error);
			this.gracefulShutdown('UNCAUGHT_EXCEPTION');
		});

		// Handle termination signals
		process.on('SIGTERM', () => {
			console.log('📡 SIGTERM received');
			this.gracefulShutdown('SIGTERM');
		});

		process.on('SIGINT', () => {
			console.log('📡 SIGINT received');
			this.gracefulShutdown('SIGINT');
		});

		console.log('✅ Error handling configured');
	}

	private async gracefulShutdown(signal: string): Promise<void> {
		console.log(`🔄 Graceful shutdown initiated by ${signal}`);

		try {
			// Stop accepting new requests
			if (this.server) {
				this.server.close(() => {
					console.log('📡 HTTP server closed');
				});
			}

			// Close database connection
			await databaseService.close();
			console.log('📘 Database connection closed');

			console.log('✅ Graceful shutdown completed');
			process.exit(0);
		} catch (error) {
			console.error('❌ Error during graceful shutdown:', error);
			process.exit(1);
		}
	}

	async start(): Promise<void> {
		try {
			// Initialize database
			console.log('🔄 Initializing database...');
			await databaseService.initialize();

			// Start HTTP server
			this.server = createServer(this.app);

			this.server.listen(serverConfig.port, serverConfig.host, () => {
				console.log('🚀 SMART Pump API Server Started');
				console.log(
					`📡 Server running on http://${serverConfig.host}:${serverConfig.port}`
				);
				console.log(`🌐 Environment: ${env.NODE_ENV}`);
				console.log(
					`📚 API Documentation: http://${serverConfig.host}:${serverConfig.port}/api/docs`
				);
				console.log(
					`💚 Health Check: http://${serverConfig.host}:${serverConfig.port}/api/health`
				);

				if (env.NODE_ENV === 'development') {
					console.log(`🎯 Frontend URL: ${env.FRONTEND_URL}`);
					console.log(`📁 Database: ${env.DB_PATH}`);
					console.log('');
					console.log('👤 Test Users:');
					console.log(
						'   Email: henderson.briggs@geeknet.net | Password: 23derd*334'
					);
					console.log('   Email: lott.kramer@poshome.us | Password: 34oii+345');
					console.log('   Email: gibson.duke@zillar.com | Password: ndfadsf(d');
					console.log(
						'   Email: ruby.glenn@waterbaby.co.uk | Password: red^adl4'
					);
				}
			});

			this.server.on('error', (error: NodeJS.ErrnoException) => {
				if (error.syscall !== 'listen') {
					throw error;
				}

				switch (error.code) {
					case 'EACCES':
						console.error(
							`❌ Port ${serverConfig.port} requires elevated privileges`
						);
						process.exit(1);
						break;
					case 'EADDRINUSE':
						console.error(`❌ Port ${serverConfig.port} is already in use`);
						process.exit(1);
						break;
					default:
						throw error;
				}
			});
		} catch (error) {
			console.error('❌ Failed to start server:', error);
			process.exit(1);
		}
	}

	getApp(): express.Application {
		return this.app;
	}
}

// Start server if this file is run directly
if (require.main === module) {
	const server = new SmartPumpServer();
	server.start().catch((error) => {
		console.error('❌ Server startup failed:', error);
		process.exit(1);
	});
}

export { SmartPumpServer };
export default SmartPumpServer;
