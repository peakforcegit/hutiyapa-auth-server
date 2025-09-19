import { Controller, Get, Req, Res, UseGuards } from "@nestjs/common";
import type { Request, Response } from 'express';
import { AuthGuard } from '@nestjs/passport';
import { OauthService } from './oauth.service';

@Controller("auth")
export class OauthController {
  constructor(private readonly oauth: OauthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth() {
    // Passport will redirect
  }

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleCallback(@Req() req: Request, @Res() res: Response) {
    try {
      // user info from Google strategy validate()
      const profile = (req as any).user as {
        provider: 'google';
        googleId: string;
        email?: string;
        firstName?: string;
        lastName?: string;
        picture?: string;
      };

      if (!profile) {
        console.error('OAuth callback: No user profile received');
        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
        return res.redirect(`${frontendUrl}/login?error=oauth_failed`);
      }

      const { accessToken, refreshToken, redirectUrl } = await this.oauth.handleGoogleProfile(profile);

      res.cookie('refresh_token', refreshToken, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 30 * 24 * 3600 * 1000 });
      return res.redirect(redirectUrl + `?accessToken=${encodeURIComponent(accessToken)}`);
    } catch (error) {
      console.error('OAuth callback error:', error);
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
      return res.redirect(`${frontendUrl}/login?error=oauth_failed`);
    }
  }
}
