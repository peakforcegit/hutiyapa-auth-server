import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { TokensService } from './tokens.service';
import { PrismaModule } from '../../infra/prisma/prisma.module';
import type { AppConfig } from '../../config/configuration';

@Module({
  imports: [
    PrismaModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('app.jwtAccessSecret'),
        signOptions: { expiresIn: config.get<string>('app.jwtAccessExpiresIn') },
      }),
    }),
  ],
  providers: [TokensService],
  exports: [TokensService],
})
export class TokensModule {}
