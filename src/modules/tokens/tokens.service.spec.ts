import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';

// Mock external dependencies
jest.mock('argon2', () => ({
  hash: jest.fn(),
  verify: jest.fn(),
}));

import { TokensService } from '../../../src/modules/tokens/tokens.service';
import { PrismaService } from '../../../src/infra/prisma/prisma.service';

// Mock data
const mockUser = {
  id: 1,
  email: 'test@example.com',
};

const mockTokenRecord = {
  id: 'token-uuid-1',
  token: 'hashed-token',
  userId: 1,
  deviceInfo: 'Test Device',
  ipAddress: '127.0.0.1',
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  isRevoked: false,
  createdAt: new Date(),
  lastUsedAt: new Date(),
  updatedAt: new Date(),
};

describe('TokensService', () => {
  let service: TokensService;
  let prismaService: PrismaService;
  let configService: ConfigService;
  let jwtService: JwtService;

  const mockPrismaService = {
    refresh_tokens: {
      create: jest.fn(),
      findMany: jest.fn(),
      findFirst: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      deleteMany: jest.fn(),
    },
    users: {
      findUnique: jest.fn(),
    },
  };

  const mockConfigService = {
    get: jest.fn((key: string) => {
      const config = {
        jwtAccessSecret: 'test-access-secret',
        jwtRefreshSecret: 'test-refresh-secret',
        jwtAccessExpiresIn: '15m',
        jwtRefreshExpiresIn: '30d',
      };
      return config[key];
    }),
  };

  const mockJwtService = {
    signAsync: jest.fn(),
    decode: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TokensService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
      ],
    }).compile();

    service = module.get<TokensService>(TokensService);
    prismaService = module.get<PrismaService>(PrismaService);
    configService = module.get<ConfigService>(ConfigService);
    jwtService = module.get<JwtService>(JwtService);

    // Reset all mocks
    Object.values(mockPrismaService.refresh_tokens).forEach(mock => mock.mockReset());
    Object.values(mockPrismaService.users).forEach(mock => mock.mockReset());
    mockJwtService.signAsync.mockReset();
    mockJwtService.decode.mockReset();
  });

  describe('generateTokenPair', () => {
    it('should generate access and refresh tokens successfully', async () => {
      const tokenData = {
        userId: mockUser.id,
        email: mockUser.email,
        deviceInfo: 'Test Device',
        ipAddress: '127.0.0.1',
      };

      mockJwtService.signAsync.mockResolvedValue('test-access-token');
      mockPrismaService.refresh_tokens.create.mockResolvedValue(mockTokenRecord);

      const result = await service.generateTokenPair(tokenData);

      expect(result).toHaveProperty('accessToken', 'test-access-token');
      expect(result).toHaveProperty('refreshToken');
      expect(result).toHaveProperty('refreshTokenId');
      expect(mockJwtService.signAsync).toHaveBeenCalledWith(
        { sub: mockUser.id, email: mockUser.email },
        {
          secret: 'test-access-secret',
          expiresIn: '15m',
        }
      );
      expect(mockPrismaService.refresh_tokens.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          userId: mockUser.id,
          deviceInfo: 'Test Device',
          ipAddress: '127.0.0.1',
          isRevoked: false,
        }),
      });
    });

    it('should handle missing device info and IP address', async () => {
      const tokenData = {
        userId: mockUser.id,
        email: mockUser.email,
      };

      mockJwtService.signAsync.mockResolvedValue('test-access-token');
      mockPrismaService.refresh_tokens.create.mockResolvedValue(mockTokenRecord);

      const result = await service.generateTokenPair(tokenData);

      expect(result).toHaveProperty('accessToken');
      expect(mockPrismaService.refresh_tokens.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          deviceInfo: 'Unknown',
          ipAddress: 'Unknown',
        }),
      });
    });
  });

  describe('rotateRefreshToken', () => {
    it('should rotate refresh token successfully', async () => {
      const refreshToken = 'valid-refresh-token';
      const ipAddress = '127.0.0.1';

      // Mock finding valid token
      mockPrismaService.refresh_tokens.findMany.mockResolvedValue([mockTokenRecord]);
      mockPrismaService.refresh_tokens.update.mockResolvedValue(mockTokenRecord);
      mockPrismaService.users.findUnique.mockResolvedValue(mockUser);
      mockJwtService.signAsync.mockResolvedValue('new-access-token');
      mockPrismaService.refresh_tokens.create.mockResolvedValue({
        ...mockTokenRecord,
        id: 'new-token-id',
      });

      // Mock argon2 verify (this would need to be mocked at the module level in a real test)
      jest.spyOn(service as any, 'verifyToken').mockResolvedValue(true);

      const result = await service.rotateRefreshToken(refreshToken, ipAddress);

      expect(result).toHaveProperty('accessToken', 'new-access-token');
      expect(result).toHaveProperty('refreshToken');
      expect(mockPrismaService.refresh_tokens.update).toHaveBeenNthCalledWith(2, {
        where: { id: mockTokenRecord.id },
        data: { 
          isRevoked: true,
          updatedAt: expect.any(Date)
        },
      });
    });

    it('should throw UnauthorizedException for invalid refresh token', async () => {
      const refreshToken = 'invalid-refresh-token';

      mockPrismaService.refresh_tokens.findMany.mockResolvedValue([]);

      await expect(
        service.rotateRefreshToken(refreshToken)
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should revoke all user tokens on revoked token reuse', async () => {
      const refreshToken = 'reused-revoked-token';
      const revokedToken = { ...mockTokenRecord, isRevoked: true };

      mockPrismaService.refresh_tokens.findMany.mockResolvedValue([revokedToken]);
      mockPrismaService.refresh_tokens.updateMany.mockResolvedValue({ count: 1 });
      jest.spyOn(service as any, 'verifyToken').mockResolvedValue(true);

      await expect(
        service.rotateRefreshToken(refreshToken)
      ).rejects.toThrow('Token reuse detected. All sessions revoked.');

      expect(mockPrismaService.refresh_tokens.updateMany).toHaveBeenCalledWith({
        where: {
          userId: revokedToken.userId,
          isRevoked: false,
        },
        data: {
          isRevoked: true,
          updatedAt: expect.any(Date),
        },
      });
    });
  });

  describe('revokeToken', () => {
    it('should revoke a specific token', async () => {
      const tokenId = 'token-to-revoke';

      mockPrismaService.refresh_tokens.update.mockResolvedValue(mockTokenRecord);

      await service.revokeToken(tokenId);

      expect(mockPrismaService.refresh_tokens.update).toHaveBeenCalledWith({
        where: { id: tokenId },
        data: {
          isRevoked: true,
          updatedAt: expect.any(Date),
        },
      });
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should revoke all tokens for a user', async () => {
      const userId = 1;

      mockPrismaService.refresh_tokens.updateMany.mockResolvedValue({ count: 3 });

      await service.revokeAllUserTokens(userId);

      expect(mockPrismaService.refresh_tokens.updateMany).toHaveBeenCalledWith({
        where: {
          userId,
          isRevoked: false,
        },
        data: {
          isRevoked: true,
          updatedAt: expect.any(Date),
        },
      });
    });
  });

  describe('getUserSessions', () => {
    it('should return active sessions for a user', async () => {
      const userId = 1;
      const mockSessions = [mockTokenRecord];

      mockPrismaService.refresh_tokens.findMany.mockResolvedValue(mockSessions);

      const result = await service.getUserSessions(userId);

      expect(result).toEqual(mockSessions);
      expect(mockPrismaService.refresh_tokens.findMany).toHaveBeenCalledWith({
        where: {
          userId,
          isRevoked: false,
          expiresAt: { gt: expect.any(Date) },
        },
        select: expect.any(Object),
        orderBy: { lastUsedAt: 'desc' },
      });
    });
  });

  describe('cleanupExpiredTokens', () => {
    it('should clean up expired and old revoked tokens', async () => {
      mockPrismaService.refresh_tokens.deleteMany.mockResolvedValue({ count: 5 });

      const result = await service.cleanupExpiredTokens();

      expect(result).toBe(5);
      expect(mockPrismaService.refresh_tokens.deleteMany).toHaveBeenCalledWith({
        where: {
          OR: [
            { expiresAt: { lt: expect.any(Date) } },
            { 
              isRevoked: true, 
              updatedAt: { lt: expect.any(Date) } 
            },
          ],
        },
      });
    });
  });

  describe('Error handling', () => {
    it('should handle database errors gracefully', async () => {
      const tokenData = {
        userId: mockUser.id,
        email: mockUser.email,
      };

      mockJwtService.signAsync.mockResolvedValue('test-access-token');
      mockPrismaService.refresh_tokens.create.mockRejectedValue(new Error('Database error'));

      await expect(
        service.generateTokenPair(tokenData)
      ).rejects.toThrow('Database error');
    });

    it('should handle invalid expiration format', async () => {
      mockConfigService.get.mockReturnValue('invalid-format');

      const tokenData = {
        userId: mockUser.id,
        email: mockUser.email,
      };

      mockJwtService.signAsync.mockResolvedValue('test-access-token');

      await expect(
        service.generateTokenPair(tokenData)
      ).rejects.toThrow('Invalid refresh token expiration format');
    });
  });
});