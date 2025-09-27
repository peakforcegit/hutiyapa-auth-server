import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { LoggerModule } from 'nestjs-pino';
import configuration from './config/configuration';
import { validateEnvironment } from './config/validation';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { HealthController } from './modules/health/health.controller';
import { HealthModule } from './modules/health/health.module';
import { PrismaModule } from './infra/prisma/prisma.module';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { OauthModule } from './modules/oauth/oauth.module';
import { EmailModule } from './modules/email/email.module';
import { TokensModule } from './modules/tokens/tokens.module';
import type { AppConfig } from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate: validateEnvironment,
      expandVariables: true,
    }),
    LoggerModule.forRootAsync({
      inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
        pinoHttp: {
          level: config.get<string>('app.logLevel', 'info'),
          transport: config.get<string>('app.nodeEnv') === 'development' ? {
            target: 'pino-pretty',
            options: {
              colorize: true,
              singleLine: true,
              ignore: 'pid,hostname',
            },
          } : undefined,
          redact: {
            paths: [
              'req.headers.authorization',
              'req.headers.cookie',
              'res.headers["set-cookie"]',
              'req.body.password',
              'req.body.confirmPassword',
              'req.body.oldPassword',
            ],
            censor: '[REDACTED]',
          },
          serializers: {
            req: (req: any) => ({
              id: req.id,
              method: req.method,
              url: req.url,
              remoteAddress: req.remoteAddress,
              remotePort: req.remotePort,
              userAgent: req.headers?.['user-agent'],
            }),
            res: (res: any) => ({
              statusCode: res.statusCode,
            }),
          },
          genReqId: (req: any) => {
            return req.headers['x-request-id'] || 
                   `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
          },
          autoLogging: {
            ignore: (req: any) => req.url === '/api/health' || req.url === '/health',
          },
        },
      }),
    }),
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => [
        {
          name: 'short',
          ttl: ((config.get<number>('app.rateLimitTtl', 60) as number) * 1000), // Convert to milliseconds
          limit: config.get<number>('app.rateLimitMax', 100) as number,
        },
        {
          name: 'medium',
          ttl: 300000, // 5 minutes
          limit: 500,
        },
        {
          name: 'long',
          ttl: 900000, // 15 minutes
          limit: 2000,
        },
      ],
    }),
    PrismaModule,
    HealthModule,
    UsersModule,
    AuthModule,
    OauthModule,
    EmailModule,
    TokensModule,
  ],
  controllers: [AppController, HealthController],
  providers: [AppService],
})
export class AppModule {}
