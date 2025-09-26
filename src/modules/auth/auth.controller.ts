import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import type { Response, Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: SignupDto, @Res({ passthrough: true }) res: Response) {
    try {
      console.log('Controller received signup DTO:', dto);
      const { accessToken, refreshToken } = await this.auth.signup(dto);
      res.cookie('refresh_token', refreshToken, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 30 * 24 * 3600 * 1000 });
      return { accessToken };
    } catch (error) {
      console.error('Signup controller error:', error);
      throw error;
    }
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() dto: LoginDto, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || undefined;
    const deviceInfo = req.headers['user-agent'];
    const { accessToken, refreshToken } = await this.auth.login(dto, ip, deviceInfo);
    res.cookie('refresh_token', refreshToken, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 30 * 24 * 3600 * 1000 });
    return { accessToken };
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = (req as any).cookies?.['refresh_token'] || req.cookies?.['refresh_token'];
    if (token) await this.auth.logout(token);
    res.clearCookie('refresh_token');
    return { success: true };
  }

  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.auth.requestPasswordReset(dto.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    return this.auth.resetPassword(dto.token, dto.password);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Req() req: Request) {
    const user = (req as any).user;
    
    // Get user details from database
    const userDetails = await this.auth.getUserProfile(user.userId);
    
    return {
      success: true,
      user: {
        id: userDetails.id,
        email: userDetails.email,
        firstName: userDetails.firstName,
        lastName: userDetails.lastName,
        avatar: userDetails.oauth_profile_picture,
        isOAuthUser: userDetails.is_oauth_user,
      },
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.refresh_token;
    
    if (!refreshToken) {
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(401).json({ success: false, message: 'No refresh token' });
    }

    try {
      const { accessToken } = await this.auth.refreshTokens(refreshToken);
      
      const isProduction = process.env.NODE_ENV === 'production';
      
      res.cookie('access_token', accessToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction,
        maxAge: 15 * 60 * 1000, // 15 minutes
        path: '/'
      });

      // Return access token so SPA can set Authorization header if cookies are blocked
      return { success: true, accessToken };
    } catch (error) {
      res.clearCookie('access_token');
      res.clearCookie('refresh_token');
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }
  }
}
