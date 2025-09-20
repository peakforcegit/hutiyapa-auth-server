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

      console.log('OAuth callback successful, processing profile:', profile.email);
      const { accessToken, refreshToken, redirectUrl } = await this.oauth.handleGoogleProfile(profile);

      // Set cookies on the client domain (3001) instead of server domain (3000)
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        sameSite: 'lax' as const,
        secure: isProduction,
        domain: isProduction ? process.env.COOKIE_DOMAIN : undefined, // Don't set domain in development
        path: '/'
      };
      
      res.cookie('access_token', accessToken, { 
        ...cookieOptions,
        maxAge: 15 * 60 * 1000, // 15 minutes
      });
      
      res.cookie('refresh_token', refreshToken, { 
        ...cookieOptions,
        maxAge: 30 * 24 * 3600 * 1000, // 30 days
      });

      console.log('Cookies set with options:', cookieOptions);
      console.log('Redirecting to:', `${redirectUrl}/dashboard?auth=success&token=${encodeURIComponent(accessToken)}`);
      
      // Also pass access token in URL as backup
      return res.redirect(`${redirectUrl}/dashboard?auth=success&token=${encodeURIComponent(accessToken)}`);
    } catch (error) {
      console.error('OAuth callback error:', error);
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3001';
      return res.redirect(`${frontendUrl}/login?error=oauth_failed`);
    }
  }
}
