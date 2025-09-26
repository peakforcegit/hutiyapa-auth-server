import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import configuration from './config/configuration';
import { validate } from './config/validation';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { HealthController } from './modules/health/health.controller';
import { HealthModule } from './modules/health/health.module';
import { PrismaModule } from './infra/prisma/prisma.module';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { OauthModule } from './modules/oauth/oauth.module';
import { EmailModule } from './modules/email/email.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validate,
      expandVariables: true,
    }),
    PrismaModule,
    HealthModule,
    UsersModule,
    AuthModule,
    OauthModule,
    EmailModule,
  ],
  controllers: [AppController, HealthController],
  providers: [AppService],
})
export class AppModule {}
