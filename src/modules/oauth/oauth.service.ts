import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "../users/users.service";
import { PrismaService } from "../../infra/prisma/prisma.service";
import { JwtService } from "@nestjs/jwt";
import * as crypto from 'crypto';
import type { AppConfig } from "../../config/configuration";

@Injectable()
export class OauthService {
  constructor(
    private readonly users: UsersService,
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  private readonly config: ConfigService,
  ) {}

  async handleGoogleProfile(profile: {
    provider: 'google';
    googleId: string;
    email?: string;
    firstName?: string;
    lastName?: string;
    picture?: string;
  }) {
    // Try to find by google_id first
    let user = await this.prisma.users.findFirst({ where: { google_id: profile.googleId } });

    // If not found and email exists, try by email and link
    if (!user && profile.email) {
      user = await this.prisma.users.findUnique({ where: { email: profile.email } });
      if (user) {
        user = await this.prisma.users.update({
          where: { id: user.id },
          data: {
            google_id: profile.googleId,
            oauth_provider: 'google',
            is_oauth_user: true,
            oauth_profile_picture: profile.picture,
            updatedAt: new Date(),
          },
        });
      }
    }

    // If still not found, create new oauth user (without password)
    if (!user) {
      user = await this.prisma.users.create({
        data: {
          email: profile.email ?? `${profile.googleId}@users.noreply.google`,
          firstName: profile.firstName ?? '',
          lastName: profile.lastName ?? '',
          google_id: profile.googleId,
          oauth_provider: 'google',
          is_oauth_user: true,
          oauth_profile_picture: profile.picture,
          updatedAt: new Date(),
        },
      });
    }

    // Issue tokens (reuse existing flow)
    const access = await this.jwt.signAsync({ sub: user.id, email: user.email }, { 
      secret: this.config.get<string>('app.jwtAccessSecret'), 
      expiresIn: this.config.get<string>('app.jwtAccessExpiresIn') 
    });
    const refresh = await this.jwt.signAsync({ sub: user.id, email: user.email, typ: 'refresh' }, { 
      secret: this.config.get<string>('app.jwtRefreshSecret'), 
      expiresIn: this.config.get<string>('app.jwtRefreshExpiresIn') 
    });
    const decoded: any = this.jwt.decode(refresh);
    const expiresAt = new Date((decoded as any).exp * 1000);

    await this.prisma.refresh_tokens.create({
      data: {
        id: crypto.randomUUID(),
        token: refresh,
        userId: user.id,
        deviceInfo: 'google-oauth',
        ipAddress: undefined,
        expiresAt,
        updatedAt: new Date(),
        lastUsedAt: new Date(),
      },
    });

  const frontendUrl = this.config.get<string>('app.frontendUrl') || (this.config.get<string>('app.webAppUrl') as string);
    return { accessToken: access, refreshToken: refresh, redirectUrl: frontendUrl };
  }
}
