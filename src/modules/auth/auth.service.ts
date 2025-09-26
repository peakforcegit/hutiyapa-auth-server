import { Injectable, UnauthorizedException, BadRequestException, NotFoundException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { EmailService } from '../email/email.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { randomUUID, randomBytes, createHash } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
  ) {}

  async signup(payload: SignupDto) {
    try {
      console.log('Signup payload received:', payload);
      
      const existing = await this.users.findByEmail(payload.email);
      if (existing) throw new BadRequestException('Email already in use');
      
      const passwordHash = await bcrypt.hash(payload.password, 10);
      console.log('Password hashed successfully');
      
      const user = await this.users.createLocal({
        email: payload.email,
        passwordHash,
        firstName: payload.firstName || '',
        lastName: payload.lastName || '',
      });
      console.log('User created successfully:', user.id);
      
      const tokens = await this.issueTokens(user.id, user.email);
      console.log('Tokens issued successfully');
      
      // Send welcome email (don't await to avoid blocking signup)
      this.emailService.sendWelcomeEmail(user.email, user.firstName || 'User').catch(err => {
        console.log('Welcome email failed, but signup succeeded:', err.message);
      });
      
      return tokens;
    } catch (error) {
      console.error('Signup error:', error);
      throw error;
    }
  }

  async login(payload: LoginDto, ipAddress?: string, deviceInfo?: string) {
    const user = await this.users.findByEmail(payload.email);
    if (!user || !user.password) throw new UnauthorizedException('Invalid credentials');
    const ok = await bcrypt.compare(payload.password, user.password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');
    await this.prisma.users.update({ where: { id: user.id }, data: { lastLoginAt: new Date(), loginCount: { increment: 1 } } });
    return this.issueTokens(user.id, user.email, ipAddress, deviceInfo);
  }

  private async issueTokens(userId: number, email: string, ipAddress?: string, deviceInfo?: string) {
    const accessPayload = { sub: userId, email };
    const refreshPayload = { sub: userId, email, typ: 'refresh' };
    const accessToken = await this.jwt.signAsync(accessPayload, { secret: process.env.JWT_ACCESS_SECRET, expiresIn: '15m' });
    const refreshToken = await this.jwt.signAsync(refreshPayload, { secret: process.env.JWT_REFRESH_SECRET, expiresIn: '30d' });
    const decoded: any = this.jwt.decode(refreshToken);
    const expiresAt = new Date((decoded as any).exp * 1000);
    
    await this.prisma.refresh_tokens.create({
      data: { id: randomUUID(), token: refreshToken, userId, deviceInfo, ipAddress, expiresAt, updatedAt: new Date(), lastUsedAt: new Date() },
    });
    return { accessToken, refreshToken };
  }

  async logout(refreshToken: string) {
    await this.prisma.refresh_tokens.updateMany({ where: { token: refreshToken }, data: { isRevoked: true, updatedAt: new Date() } });
    return { success: true };
  }

  async getUserProfile(userId: number) {
    const user = await this.prisma.users.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        oauth_profile_picture: true,
        is_oauth_user: true,
        createdAt: true,
        lastLoginAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  async refreshTokens(refreshToken: string) {
    try {
      // Verify refresh token
      const payload = await this.jwt.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET,
      });

      // Check if token exists in database and is not revoked
      const storedToken = await this.prisma.refresh_tokens.findFirst({
        where: {
          token: refreshToken,
          isRevoked: false,
          expiresAt: { gt: new Date() },
        },
      });

      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Update last used time
      await this.prisma.refresh_tokens.update({
        where: { id: storedToken.id },
        data: { lastUsedAt: new Date() },
      });

      // Generate new access token
      const accessPayload = { sub: payload.sub, email: payload.email };
      const accessToken = await this.jwt.signAsync(accessPayload, {
        secret: process.env.JWT_ACCESS_SECRET,
        expiresIn: '15m',
      });

      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Generate a password reset token and send email with reset link.
   */
  async requestPasswordReset(email: string) {
    const user = await this.users.findByEmail(email);
    // Do not reveal if user doesn't exist (security best practice)
    if (!user) return { success: true };

    // Create a random token and store a hashed version
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(rawToken).digest('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 minutes

    await this.prisma.users.update({
      where: { id: user.id },
      data: { resetPasswordToken: tokenHash, resetPasswordExpires: expires, updatedAt: new Date() },
    });

    try {
      // Send password reset email with proper error handling
      await this.emailService.sendPasswordResetEmail(email, rawToken);
    } catch (error) {
      // Log error but don't fail the request (fallback already logged in EmailService)
      console.error('Password reset email failed:', error.message);
    }

    return { success: true };
  }

  /**
   * Verify reset token and set new password.
   */
  async resetPassword(token: string, newPassword: string) {
    if (!token) throw new BadRequestException('Invalid token');

    const tokenHash = createHash('sha256').update(token).digest('hex');
    const now = new Date();

    const user = await this.prisma.users.findFirst({
      where: { resetPasswordToken: tokenHash, resetPasswordExpires: { gt: now } },
    });

    if (!user) throw new UnauthorizedException('Invalid or expired reset token');

    const passwordHash = await bcrypt.hash(newPassword, 10);

    await this.prisma.users.update({
      where: { id: user.id },
      data: {
        password: passwordHash,
        resetPasswordToken: null,
        resetPasswordExpires: null,
        lastPasswordChange: new Date(),
        updatedAt: new Date(),
      },
    });

    return { success: true };
  }
}
