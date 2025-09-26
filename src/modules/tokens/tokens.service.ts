import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../infra/prisma/prisma.service';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import type { AppConfig } from '../../config/configuration';

interface TokenPair {
  accessToken: string;
  refreshToken: string;
  refreshTokenId: string;
}

interface RefreshTokenData {
  userId: number;
  email: string;
  deviceInfo?: string;
  ipAddress?: string;
}

@Injectable()
export class TokensService {
  private readonly logger = new Logger(TokensService.name);

  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService<AppConfig>,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Generate a new token pair with secure refresh token storage
   */
  async generateTokenPair(data: RefreshTokenData): Promise<TokenPair> {
    const { userId, email, deviceInfo, ipAddress } = data;

    // Generate access token
    const accessPayload = { sub: userId, email };
    const accessToken = await this.jwt.signAsync(accessPayload, {
      secret: process.env.JWT_ACCESS_SECRET,
      expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
    });

    // Generate secure refresh token
    const refreshTokenRaw = crypto.randomBytes(32).toString('hex');
    const refreshTokenHash = await this.hashToken(refreshTokenRaw);
    const refreshTokenId = crypto.randomUUID();

    // Calculate expiration
    const expiresAt = this.calculateRefreshExpiry();

    // Store hashed refresh token
    await this.prisma.refresh_tokens.create({
      data: {
        id: refreshTokenId,
        token: refreshTokenHash, // Store hash, not raw token
        userId,
        deviceInfo: deviceInfo || 'Unknown',
        ipAddress: ipAddress || 'Unknown',
        expiresAt,
        isRevoked: false,
        updatedAt: new Date(),
        lastUsedAt: new Date(),
      },
    });

    this.logger.log(`Generated token pair for user ${userId} from ${ipAddress}`);

    return {
      accessToken,
      refreshToken: refreshTokenRaw,
      refreshTokenId,
    };
  }

  /**
   * Rotate refresh token with security checks
   */
  async rotateRefreshToken(
    refreshToken: string,
    ipAddress?: string,
    deviceInfo?: string,
  ): Promise<TokenPair> {
    // Find matching token record by comparing hashes
    const tokenRecord = await this.findValidRefreshToken(refreshToken);
    
    if (!tokenRecord) {
      this.logger.warn(`Invalid refresh token attempt from ${ipAddress}`);
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check for token reuse (security feature)
    if (tokenRecord.isRevoked) {
      this.logger.error(`Revoked token reuse detected for user ${tokenRecord.userId} from ${ipAddress}`);
      // Revoke all tokens for this user as a security measure
      await this.revokeAllUserTokens(tokenRecord.userId);
      throw new UnauthorizedException('Token reuse detected. All sessions revoked.');
    }

    // Update last used time
    await this.prisma.refresh_tokens.update({
      where: { id: tokenRecord.id },
      data: { lastUsedAt: new Date() },
    });

    // Get user data
    const user = await this.prisma.users.findUnique({
      where: { id: tokenRecord.userId },
      select: { id: true, email: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Revoke current token
    await this.revokeToken(tokenRecord.id);

    // Generate new token pair
    const newTokenPair = await this.generateTokenPair({
      userId: user.id,
      email: user.email,
      deviceInfo: deviceInfo || tokenRecord.deviceInfo || undefined,
      ipAddress: ipAddress || tokenRecord.ipAddress || undefined,
    });

    this.logger.log(`Rotated refresh token for user ${user.id} from ${ipAddress}`);
    
    return newTokenPair;
  }

  /**
   * Revoke a specific refresh token
   */
  async revokeToken(tokenId: string): Promise<void> {
    await this.prisma.refresh_tokens.update({
      where: { id: tokenId },
      data: {
        isRevoked: true,
        updatedAt: new Date(),
      },
    });

    this.logger.log(`Revoked refresh token ${tokenId}`);
  }

  /**
   * Revoke all refresh tokens for a user
   */
  async revokeAllUserTokens(userId: number): Promise<void> {
    const result = await this.prisma.refresh_tokens.updateMany({
      where: {
        userId,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
        updatedAt: new Date(),
      },
    });

    this.logger.log(`Revoked ${result.count} tokens for user ${userId}`);
  }

  /**
   * Get active sessions for a user
   */
  async getUserSessions(userId: number) {
    return this.prisma.refresh_tokens.findMany({
      where: {
        userId,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      select: {
        id: true,
        deviceInfo: true,
        ipAddress: true,
        createdAt: true,
        lastUsedAt: true,
        expiresAt: true,
      },
      orderBy: { lastUsedAt: 'desc' },
    });
  }

  /**
   * Clean up expired tokens (should be run periodically)
   */
  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.prisma.refresh_tokens.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } },
          { isRevoked: true, updatedAt: { lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }, // Remove revoked tokens older than 7 days
        ],
      },
    });

    this.logger.log(`Cleaned up ${result.count} expired/old refresh tokens`);
    return result.count;
  }

  private async hashToken(token: string): Promise<string> {
    return argon2.hash(token, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  private async verifyToken(hash: string, token: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, token);
    } catch {
      return false;
    }
  }

  private async findValidRefreshToken(refreshToken: string) {
    // Get all non-revoked, non-expired tokens
    const candidates = await this.prisma.refresh_tokens.findMany({
      where: {
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
      take: 100, // Reasonable limit for security
    });

    // Check each candidate by verifying the hash
    for (const candidate of candidates) {
      if (await this.verifyToken(candidate.token, refreshToken)) {
        return candidate;
      }
    }

    return null;
  }

  private calculateRefreshExpiry(): Date {
    const expiresIn = process.env.JWT_REFRESH_EXPIRES_IN || '30d';
    
    // Parse expiration string (supports: 30d, 24h, 60m, 3600s)
    const match = expiresIn.match(/^(\d+)([dhms])$/);
    if (!match) {
      throw new Error(`Invalid refresh token expiration format: ${expiresIn}`);
    }

    const [, value, unit] = match;
    const num = parseInt(value, 10);
    
    let milliseconds: number;
    switch (unit) {
      case 'd': milliseconds = num * 24 * 60 * 60 * 1000; break;
      case 'h': milliseconds = num * 60 * 60 * 1000; break;
      case 'm': milliseconds = num * 60 * 1000; break;
      case 's': milliseconds = num * 1000; break;
      default: throw new Error(`Unsupported time unit: ${unit}`);
    }

    return new Date(Date.now() + milliseconds);
  }
}
