import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ForgotPasswordDto, ResetPasswordDto } from './dtos/forgot.dto';
import type { Response, Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: SignupDto, @Res({ passthrough: true }) res: Response) {
    const { accessToken, refreshToken } = await this.auth.signup(dto);
    res.cookie('refresh_token', refreshToken, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 30 * 24 * 3600 * 1000 });
    return { accessToken };
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

  @Post('forgot')
  async forgot(@Body() _dto: ForgotPasswordDto) {
    // Implement email sending using resetPasswordToken fields in users table
    return { success: true };
  }

  @Post('reset')
  async reset(@Body() _dto: ResetPasswordDto) {
    // Implement reset using resetPasswordToken and resetPasswordExpires
    return { success: true };
  }
}
