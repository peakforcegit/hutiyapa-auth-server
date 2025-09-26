import { Injectable, UnauthorizedException, BadRequestException, NotFoundException, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../users/users.service';
import { EmailService } from '../email/email.service';
import { TokensService } from '../tokens/tokens.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { randomBytes, createHash } from 'crypto';
import type { AppConfig } from '../../config/configuration';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly users: UsersService,
    private readonly tokens: TokensService,
    private readonly prisma: PrismaService,
    private readonly emailService: EmailService,
    private readonly config: ConfigService<AppConfig>,
  ) {}

  async signup(payload: SignupDto, ipAddress?: string, deviceInfo?: string) {
    try {
      this.logger.log('Signup attempt for email:', payload.email);
      
      const existing = await this.users.findByEmail(payload.email);
      if (existing) {
        throw new BadRequestException('Email already in use');
      }
      
      const passwordHash = await bcrypt.hash(payload.password, 12); // Increased cost for better security
      
      const user = await this.users.createLocal({
        email: payload.email,
        passwordHash,
        firstName: payload.firstName || '',
        lastName: payload.lastName || '',
      });
      
      this.logger.log(`User created successfully: ${user.id}`);
      
      // Generate secure token pair
      const tokens = await this.tokens.generateTokenPair({
        userId: user.id,
        email: user.email,
        deviceInfo: deviceInfo || 'Web Browser',
        ipAddress,
      });
      
      // Send welcome email (don't await to avoid blocking signup)
      this.emailService.sendWelcomeEmail(user.email, user.firstName || 'User').catch(err => {
        this.logger.warn('Welcome email failed, but signup succeeded:', err.message);
      });
      
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      };
    } catch (error) {
      this.logger.error('Signup error:', error);
      throw error;
    }
  }

  async login(payload: LoginDto, ipAddress?: string, deviceInfo?: string) {
    const user = await this.users.findByEmail(payload.email);
    if (!user || !user.password) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    const isValidPassword = await bcrypt.compare(payload.password, user.password);
    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // Update login statistics
    await this.prisma.users.update({
      where: { id: user.id },
      data: {
        lastLoginAt: new Date(),
        loginCount: { increment: 1 },
        updatedAt: new Date(),
      },
    });
    
    // Generate secure token pair
    const tokens = await this.tokens.generateTokenPair({
      userId: user.id,
      email: user.email,
      deviceInfo: deviceInfo || 'Web Browser',
      ipAddress,
    });
    
    this.logger.log(`User ${user.id} logged in from ${ipAddress}`);
    
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async logout(refreshToken: string) {
    try {
      // Find the token and revoke it
      const tokenRecord = await this.prisma.refresh_tokens.findFirst({
        where: { 
          token: refreshToken,
          isRevoked: false 
        },
      });

      if (tokenRecord) {
        await this.tokens.revokeToken(tokenRecord.id);
        this.logger.log(`User ${tokenRecord.userId} logged out`);
      }

      return { success: true };
    } catch (error) {
      this.logger.error('Logout error:', error);
      return { success: true }; // Don't reveal internal errors
    }
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

  async refreshTokens(refreshToken: string, ipAddress?: string, deviceInfo?: string) {
    try {
      // Use TokensService for secure token rotation
      const newTokens = await this.tokens.rotateRefreshToken(
        refreshToken,
        ipAddress,
        deviceInfo,
      );

      return {
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
      };
    } catch (error) {
      this.logger.warn(`Token refresh failed from ${ipAddress}:`, error.message);
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

    const passwordHash = await bcrypt.hash(newPassword, 12); // Increased cost

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

    // Revoke all existing sessions for security
    await this.tokens.revokeAllUserTokens(user.id);
    
    this.logger.log(`Password reset completed for user ${user.id}`);

    return { success: true };
  }

  /**
   * Get user sessions for session management
   */
  async getUserSessions(userId: number) {
    return this.tokens.getUserSessions(userId);
  }

  /**
   * Revoke a specific user session
   */
  async revokeUserSession(userId: number, sessionId: string) {
    // Verify the session belongs to the user for security
    const sessions = await this.tokens.getUserSessions(userId);
    const sessionExists = sessions.find(s => s.id === sessionId);
    
    if (!sessionExists) {
      throw new NotFoundException('Session not found');
    }

    await this.tokens.revokeToken(sessionId);
    return { success: true };
  }

  /**
   * Revoke all user sessions
   */
  async revokeAllUserSessions(userId: number) {
    await this.tokens.revokeAllUserTokens(userId);
    return { success: true };
  }
}
