import { registerAs } from '@nestjs/config';

export interface AppConfig {
  // Server
  port: number;
  nodeEnv: string;
  
  // Database
  databaseUrl: string;
  
  // JWT
  jwtAccessSecret: string;
  jwtRefreshSecret: string;
  jwtAccessExpiresIn: string;
  jwtRefreshExpiresIn: string;
  
  // Frontend/CORS
  frontendUrl: string;
  webAppUrl?: string;
  corsOrigins: string[];
  
  // Cookies
  cookieDomain?: string;
  cookieSecret: string;
  
  // Security
  enableHelmet: boolean;
  enableCsrf: boolean;
  
  // Rate Limiting
  rateLimitTtl: number;
  rateLimitMax: number;
  
  // Email
  smtpHost: string;
  smtpPort: number;
  smtpSecure: boolean;
  smtpUser: string;
  smtpPass: string;
  emailFrom: string;
  
  // OAuth
  googleClientId: string;
  googleClientSecret: string;
  
  // Monitoring
  sentryDsn?: string;
  logLevel: string;
}

export default registerAs('app', (): AppConfig => ({
  // Server
  port: parseInt(process.env.PORT ?? '3000', 10),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  
  // Database
  databaseUrl: process.env.DATABASE_URL!,
  
  // JWT
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET!,
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET!,
  jwtAccessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? '15m',
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '30d',
  
  // Frontend/CORS
  frontendUrl: process.env.FRONTEND_URL ?? process.env.WEB_APP_URL!,
  webAppUrl: process.env.WEB_APP_URL,
  corsOrigins: (process.env.CORS_ORIGINS ?? '').split(',').map(origin => origin.trim()),
  
  // Cookies
  cookieDomain: process.env.COOKIE_DOMAIN,
  cookieSecret: process.env.COOKIE_SECRET!,
  
  // Security
  enableHelmet: process.env.ENABLE_HELMET !== 'false',
  enableCsrf: process.env.ENABLE_CSRF !== 'false',
  
  // Rate Limiting
  rateLimitTtl: parseInt(process.env.RATE_LIMIT_TTL ?? '60', 10),
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX ?? '100', 10),
  
  // Email
  smtpHost: process.env.SMTP_HOST!,
  smtpPort: parseInt(process.env.SMTP_PORT!, 10),
  smtpSecure: process.env.SMTP_SECURE === 'true',
  smtpUser: process.env.SMTP_USER!,
  smtpPass: process.env.SMTP_PASS!,
  emailFrom: process.env.EMAIL_FROM!,
  
  // OAuth
  googleClientId: process.env.GOOGLE_CLIENT_ID!,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  
  // Monitoring
  sentryDsn: process.env.SENTRY_DSN,
  logLevel: process.env.LOG_LEVEL ?? 'info',
}));
