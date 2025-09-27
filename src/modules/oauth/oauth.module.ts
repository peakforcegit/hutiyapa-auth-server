import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { OauthController } from "./oauth.controller";
import { OauthService } from "./oauth.service";
import { UsersModule } from "../users/users.module";
import { AuthModule } from "../auth/auth.module";
import { GoogleStrategy } from "../auth/strategies/google.strategy";
import type { AppConfig } from "../../config/configuration";

@Module({
  imports: [
    UsersModule, 
    AuthModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('app.jwtAccessSecret'),
        signOptions: { expiresIn: config.get<string>('app.jwtAccessExpiresIn') },
      }),
    }),
  ],
  controllers: [OauthController],
  providers: [OauthService, GoogleStrategy],
})
export class OauthModule {}
