import helmet from 'helmet';
import { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export function applyHelmetSecurity(app: INestApplication) {
  const configService = app.get(ConfigService);
  const isProduction = configService.get('NODE_ENV') === 'production';
  const frontendUrl = configService.get('FRONTEND_URL') || configService.get('WEB_APP_URL');

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for development
          styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
          fontSrc: ["'self'", 'fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', '*.googleusercontent.com'],
          connectSrc: frontendUrl ? ["'self'", frontendUrl] : ["'self'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
          baseUri: ["'self'"],
          objectSrc: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false, // Disable for OAuth compatibility
      crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      hsts: isProduction ? {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true,
      } : false,
      noSniff: true,
      frameguard: { action: 'deny' },
      xssFilter: true,
    }),
  );
}
