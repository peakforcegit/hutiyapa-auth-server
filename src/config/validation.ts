import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  // Server Configuration
  NODE_ENV: Joi.string()
    .valid('development', 'test', 'production')
    .default('development'),
  PORT: Joi.number()
    .port()
    .default(3000),

  // Database Configuration
  DATABASE_URL: Joi.string()
    .uri()
    .required()
    .description('PostgreSQL database connection string'),

  // JWT Configuration
  JWT_ACCESS_SECRET: Joi.string()
    .min(32)
    .required()
    .description('JWT access token secret (minimum 32 characters)'),
  JWT_REFRESH_SECRET: Joi.string()
    .min(32)
    .required()
    .description('JWT refresh token secret (minimum 32 characters)'),
  JWT_ACCESS_EXPIRES_IN: Joi.string()
    .default('15m')
    .description('JWT access token expiration time'),
  JWT_REFRESH_EXPIRES_IN: Joi.string()
    .default('30d')
    .description('JWT refresh token expiration time'),

  // Frontend/CORS Configuration
  FRONTEND_URL: Joi.string()
    .uri()
    .required()
    .description('Frontend application URL'),
  WEB_APP_URL: Joi.string()
    .uri()
    .optional()
    .description('Web application URL (alternative to FRONTEND_URL)'),
  CORS_ORIGINS: Joi.string()
    .required()
    .description('Comma-separated list of allowed CORS origins'),

  // Cookie Configuration
  COOKIE_DOMAIN: Joi.string()
    .optional()
    .description('Cookie domain for secure cookie settings'),
  COOKIE_SECRET: Joi.string()
    .min(32)
    .required()
    .description('Cookie signing secret'),

  // Security Configuration
  ENABLE_HELMET: Joi.boolean()
    .default(true)
    .description('Enable Helmet security middleware'),
  ENABLE_CSRF: Joi.boolean()
    .default(true)
    .description('Enable CSRF protection'),
  
  // Rate Limiting Configuration
  RATE_LIMIT_TTL: Joi.number()
    .integer()
    .positive()
    .default(60)
    .description('Rate limit window in seconds'),
  RATE_LIMIT_MAX: Joi.number()
    .integer()
    .positive()
    .default(100)
    .description('Maximum requests per window'),

  // Email Configuration
  SMTP_HOST: Joi.string()
    .required()
    .description('SMTP server hostname'),
  SMTP_PORT: Joi.number()
    .port()
    .required()
    .description('SMTP server port'),
  SMTP_SECURE: Joi.boolean()
    .default(false)
    .description('Use secure SMTP connection'),
  SMTP_USER: Joi.string()
    .required()
    .description('SMTP authentication username'),
  SMTP_PASS: Joi.string()
    .required()
    .description('SMTP authentication password'),
  EMAIL_FROM: Joi.string()
    .email()
    .required()
    .description('Default sender email address'),

  // OAuth Configuration
  GOOGLE_CLIENT_ID: Joi.string()
    .required()
    .description('Google OAuth client ID'),
  GOOGLE_CLIENT_SECRET: Joi.string()
    .required()
    .description('Google OAuth client secret'),
  GOOGLE_CALLBACK_URL: Joi.string()
    .uri()
    .required()
    .description('Google OAuth callback URL (must match in Google Console)'),

  // Optional Monitoring
  SENTRY_DSN: Joi.string()
    .uri()
    .optional()
    .description('Sentry DSN for error monitoring'),
  LOG_LEVEL: Joi.string()
    .valid('error', 'warn', 'info', 'debug', 'trace')
    .default('info')
    .description('Application log level'),
});

export function validateEnvironment(config: Record<string, unknown>) {
  const { error, value } = envValidationSchema.validate(config, {
    allowUnknown: true,
    abortEarly: false,
  });

  if (error) {
    throw new Error(`Environment validation failed: ${error.message}`);
  }

  return value;
}
