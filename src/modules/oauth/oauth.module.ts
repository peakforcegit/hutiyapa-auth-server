import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { OauthController } from "./oauth.controller";
import { OauthService } from "./oauth.service";
import { UsersModule } from "../users/users.module";
import { AuthModule } from "../auth/auth.module";
import { GoogleStrategy } from "../auth/strategies/google.strategy";

@Module({
  imports: [
    UsersModule, 
    AuthModule,
    JwtModule.registerAsync({
      useFactory: () => ({
        secret: process.env.JWT_ACCESS_SECRET,
        signOptions: { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' },
      }),
    }),
  ],
  controllers: [OauthController],
  providers: [OauthService, GoogleStrategy],
})
export class OauthModule {}
