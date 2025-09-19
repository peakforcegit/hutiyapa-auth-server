import { Module } from "@nestjs/common";
import { OauthController } from "./oauth.controller";
import { OauthService } from "./oauth.service";
import { UsersModule } from "../users/users.module";
import { AuthModule } from "../auth/auth.module";
import { GoogleStrategy } from "../auth/strategies/google.strategy";

@Module({
  imports: [UsersModule, AuthModule],
  controllers: [OauthController],
  providers: [OauthService, GoogleStrategy],
})
export class OauthModule {}
