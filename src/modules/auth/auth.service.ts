import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersService,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async signup(payload: SignupDto) {
    const existing = await this.users.findByEmail(payload.email);
    if (existing) throw new BadRequestException('Email already in use');
    const passwordHash = await bcrypt.hash(payload.password, 10);
    const user = await this.users.createLocal({
      email: payload.email,
      passwordHash,
      name: [payload.firstName, payload.lastName].filter(Boolean).join(' ').trim() || null,
    });
    return this.issueTokens(user.id, user.email);
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
    const accessToken = await this.jwt.signAsync(accessPayload, { secret: process.env.JWT_ACCESS_SECRET, expiresIn: process.env.JWT_ACCESS_TTL || '15m' });
    const refreshToken = await this.jwt.signAsync(refreshPayload, { secret: process.env.JWT_REFRESH_SECRET, expiresIn: process.env.JWT_REFRESH_TTL || '30d' });
    const decoded: any = this.jwt.decode(refreshToken);
    const expiresAt = new Date((decoded as any).exp * 1000);
    await this.prisma.refresh_tokens.create({
      data: { id: crypto.randomUUID(), token: refreshToken, userId, deviceInfo, ipAddress, expiresAt, updatedAt: new Date(), lastUsedAt: new Date() },
    });
    return { accessToken, refreshToken };
  }

  async logout(refreshToken: string) {
    await this.prisma.refresh_tokens.updateMany({ where: { token: refreshToken }, data: { isRevoked: true, updatedAt: new Date() } });
    return { success: true };
  }
}
