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
        const frontendUrl = process.env.FRONTEND_URL as string;
        return res.redirect(`${frontendUrl}/login?error=oauth_failed`);
      }

      console.log('OAuth callback successful, processing profile:', profile.email);
      const { accessToken, refreshToken, redirectUrl } = await this.oauth.handleGoogleProfile(profile);

      // Set secure refresh token cookie only
      const isProduction = process.env.NODE_ENV === 'production';
      const cookieDomain = process.env.COOKIE_DOMAIN;
      
      res.cookie('refresh_token', refreshToken, { 
        httpOnly: true,
        sameSite: 'lax' as const,
        secure: isProduction,
        domain: cookieDomain,
        path: '/api/auth',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });

      // Store access token temporarily in a secure session cookie for the frontend to retrieve
      res.cookie('oauth_access_token', accessToken, {
        httpOnly: false, // Frontend needs to read this once
        sameSite: 'lax' as const,
        secure: isProduction,
        domain: cookieDomain,
        path: '/',
        maxAge: 5 * 60 * 1000, // 5 minutes - just long enough for frontend to read and clear
      });

      console.log('Secure cookies set successfully');
      
      // Clean redirect without tokens in URL - SECURITY FIX
      return res.redirect(`${redirectUrl}/dashboard?auth=success`);
    } catch (error) {
      console.error('OAuth callback error:', error);
      const frontendUrl = process.env.FRONTEND_URL as string;
      return res.redirect(`${frontendUrl}/login?error=oauth_failed`);
    }
  }
}
