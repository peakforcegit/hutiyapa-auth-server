import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
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
}
