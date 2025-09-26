import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';
import csurf from 'csurf';
import { ValidationPipe as GlobalValidationPipe } from './common/pipes/validation.pipe';
import { GlobalExceptionFilter } from './common/filters/global-exception.filter';
import { applyHelmetSecurity } from './security/helmet';
import type { AppConfig } from './config/configuration';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  // Use the configured pino logger
  app.useLogger(app.get(Logger));
  
  const config = app.get<ConfigService<AppConfig>>(ConfigService);
  const logger = app.get(Logger);
  
  // Get configuration values
  const port = config.get('port', 3000);
  const corsOrigins = config.get('corsOrigins', []);
  const cookieSecret = config.get('cookieSecret');
  const enableHelmet = config.get('enableHelmet', true);
  const enableCsrf = config.get('enableCsrf', true);
  const isProduction = config.get('nodeEnv') === 'production';

  // Apply security middleware
  if (enableHelmet) {
    applyHelmetSecurity(app);
    logger.log('Helmet security middleware enabled');
  }

  // Configure CORS
  app.enableCors({
    origin: corsOrigins.length > 0 ? corsOrigins : 'http://localhost:3001',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'x-request-id'],
  });

  // Cookie parser
  app.use(cookieParser(cookieSecret));

  // CSRF protection for state-changing operations
  if (enableCsrf) {
    const csrfProtection = csurf({
      cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        maxAge: 3600000, // 1 hour
      },
      ignoreMethods: ['GET', 'HEAD', 'OPTIONS'], // Allow safe methods
      value: (req) => {
        // Check multiple sources for CSRF token
        return req.headers['x-csrf-token'] ||
               req.headers['x-xsrf-token'] ||
               req.body?._csrf ||
               req.query?._csrf;
      },
    });

    // Apply CSRF protection to specific routes only
    app.use('/api/auth/refresh', csrfProtection);
    app.use('/api/auth/logout', csrfProtection);
    app.use('/api/users', csrfProtection);
    
    logger.log('CSRF protection enabled for sensitive routes');
  }

  // Global exception filter
  app.useGlobalFilters(new GlobalExceptionFilter());

  // Global validation pipe
  app.useGlobalPipes(new GlobalValidationPipe());

  // Set global prefix
  app.setGlobalPrefix('api');

  // Enable graceful shutdown
  app.enableShutdownHooks();

  await app.listen(port);
  
  logger.log(`🚀 Application is running on: http://localhost:${port}/api`);
  logger.log(`🌍 Environment: ${config.get('nodeEnv')}`);
  logger.log(`🛡️  Security: Helmet=${enableHelmet}, CSRF=${enableCsrf}`);
}

bootstrap().catch((error) => {
  console.error('Application failed to start:', error);
  process.exit(1);
});
