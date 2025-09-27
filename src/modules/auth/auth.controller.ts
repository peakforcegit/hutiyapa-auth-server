import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UseGuards, Logger, Param } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import type { Response, Request } from 'express';
import type { AppConfig } from '../../config/configuration';

@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);

  constructor(
    private readonly auth: AuthService,
    private readonly config: ConfigService,
  ) {}

  private getClientIp(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }

  private setSecureRefreshCookie(res: Response, refreshToken: string): void {
  const isProduction = this.config.get<string>('app.nodeEnv') === 'production';
  const cookieDomain = this.config.get<string>('app.cookieDomain');

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/api/auth',
      domain: cookieDomain,
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });
  }

  private clearRefreshCookie(res: Response): void {
  const cookieDomain = this.config.get<string>('app.cookieDomain');
    
    res.clearCookie('refresh_token', {
      httpOnly: true,
      path: '/api/auth',
      domain: cookieDomain,
    });
  }

  @Post('signup')
  async signup(
    @Body() dto: SignupDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ipAddress = this.getClientIp(req);
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    
    const { accessToken, refreshToken } = await this.auth.signup(dto, ipAddress, deviceInfo);
    
    this.setSecureRefreshCookie(res, refreshToken);
    
    return { accessToken };
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 attempts per minute
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const ipAddress = this.getClientIp(req);
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    
    this.logger.log(`Login attempt for ${dto.email} from ${ipAddress}`);
    
    const { accessToken, refreshToken } = await this.auth.login(dto, ipAddress, deviceInfo);
    
    this.setSecureRefreshCookie(res, refreshToken);
    
    return { accessToken };
  }

  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.['refresh_token'];
    const ipAddress = this.getClientIp(req);
    
    if (refreshToken) {
      await this.auth.logout(refreshToken);
      this.logger.log(`User logged out from ${ipAddress}`);
    }
    
    this.clearRefreshCookie(res);
    
    return { success: true };
  }

  @Post('forgot-password')
  @Throttle({ default: { limit: 3, ttl: 300000 } }) // 3 attempts per 5 minutes
  async forgotPassword(@Body() dto: ForgotPasswordDto, @Req() req: Request) {
    const ipAddress = this.getClientIp(req);
    this.logger.log(`Password reset request for ${dto.email} from ${ipAddress}`);
    
    return this.auth.requestPasswordReset(dto.email);
  }

  @Post('reset-password')
  @Throttle({ default: { limit: 5, ttl: 300000 } }) // 5 attempts per 5 minutes
  async resetPassword(@Body() dto: ResetPasswordDto, @Req() req: Request) {
    const ipAddress = this.getClientIp(req);
    this.logger.log(`Password reset attempt from ${ipAddress}`);
    
    return this.auth.resetPassword(dto.token, dto.password);
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getUserSessions(@Req() req: Request) {
    const user = (req as any).user;
    const sessions = await this.auth.getUserSessions(user.userId);
    
    return {
      success: true,
      sessions: sessions.map(session => ({
        id: session.id,
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress,
        createdAt: session.createdAt,
        lastUsedAt: session.lastUsedAt,
        expiresAt: session.expiresAt,
        isCurrent: false, // Could implement current session detection
      })),
    };
  }

  @Post('sessions/:sessionId/revoke')
  @UseGuards(JwtAuthGuard)
  async revokeSession(
    @Req() req: Request,
    @Param('sessionId') sessionId: string,
  ) {
    const user = (req as any).user;
    const ipAddress = this.getClientIp(req);
    
    await this.auth.revokeUserSession(user.userId, sessionId);
    
    this.logger.log(`Session ${sessionId} revoked for user ${user.userId} from ${ipAddress}`);
    
    return { success: true, message: 'Session revoked successfully' };
  }

  @Post('sessions/revoke-all')
  @UseGuards(JwtAuthGuard)
  async revokeAllSessions(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = (req as any).user;
    const ipAddress = this.getClientIp(req);
    
    await this.auth.revokeAllUserSessions(user.userId);
    
    // Clear the current refresh token as well
    this.clearRefreshCookie(res);
    
    this.logger.log(`All sessions revoked for user ${user.userId} from ${ipAddress}`);
    
    return { success: true, message: 'All sessions revoked successfully' };
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
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // 10 refresh attempts per minute
  async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies?.refresh_token;
    const ipAddress = this.getClientIp(req);
    const deviceInfo = req.headers['user-agent'] || 'Unknown Device';
    
    if (!refreshToken) {
      this.logger.warn(`Refresh attempt without token from ${ipAddress}`);
      this.clearRefreshCookie(res);
      return res.status(401).json({ success: false, message: 'No refresh token' });
    }

    try {
      const tokens = await this.auth.refreshTokens(refreshToken, ipAddress, deviceInfo);
      
      // Set new refresh token cookie
      this.setSecureRefreshCookie(res, tokens.refreshToken);
      
      return { 
        success: true, 
        accessToken: tokens.accessToken 
      };
    } catch (error) {
      this.logger.warn(`Token refresh failed from ${ipAddress}: ${error.message}`);
      this.clearRefreshCookie(res);
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }
  }
}
