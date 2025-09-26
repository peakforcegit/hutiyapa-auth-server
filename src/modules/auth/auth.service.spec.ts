import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, UnauthorizedException, NotFoundException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

// Mock external dependencies
jest.mock('argon2', () => ({
  hash: jest.fn(),
  verify: jest.fn(),
}));

jest.mock('bcrypt', () => ({
  hash: jest.fn(),
  compare: jest.fn(),
}));

import { AuthService } from '../../../src/modules/auth/auth.service';
import { UsersService } from '../../../src/modules/users/users.service';
import { EmailService } from '../../../src/modules/email/email.service';
import { TokensService } from '../../../src/modules/tokens/tokens.service';
import { PrismaService } from '../../../src/infra/prisma/prisma.service';

// Mock data
const mockUser = {
  id: 1,
  email: 'test@example.com',
  password: 'hashed-password',
  firstName: 'Test',
  lastName: 'User',
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockTokenPair = {
  accessToken: 'access-token',
  refreshToken: 'refresh-token',
  refreshTokenId: 'token-id',
};

describe('AuthService', () => {
  let service: AuthService;
  let usersService: UsersService;
  let tokensService: TokensService;
  let emailService: EmailService;
  let prismaService: PrismaService;

  const mockUsersService = {
    findByEmail: jest.fn(),
    createLocal: jest.fn(),
  };

  const mockTokensService = {
    generateTokenPair: jest.fn(),
    rotateRefreshToken: jest.fn(),
    revokeToken: jest.fn(),
    revokeAllUserTokens: jest.fn(),
    getUserSessions: jest.fn(),
  };

  const mockEmailService = {
    sendWelcomeEmail: jest.fn(),
    sendPasswordResetEmail: jest.fn(),
  };

  const mockPrismaService = {
    users: {
      update: jest.fn(),
      findFirst: jest.fn(),
      findUnique: jest.fn(),
    },
    refresh_tokens: {
      findFirst: jest.fn(),
    },
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: TokensService,
          useValue: mockTokensService,
        },
        {
          provide: EmailService,
          useValue: mockEmailService,
        },
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get<UsersService>(UsersService);
    tokensService = module.get<TokensService>(TokensService);
    emailService = module.get<EmailService>(EmailService);
    prismaService = module.get<PrismaService>(PrismaService);

    // Reset all mocks
    Object.values(mockUsersService).forEach(mock => mock.mockReset());
    Object.values(mockTokensService).forEach(mock => mock.mockReset());
    Object.values(mockEmailService).forEach(mock => mock.mockReset());
    Object.values(mockPrismaService.users).forEach(mock => mock.mockReset());
    Object.values(mockPrismaService.refresh_tokens).forEach(mock => mock.mockReset());
    
    // Reset bcrypt mocks
    (bcrypt.hash as jest.Mock).mockReset();
    (bcrypt.compare as jest.Mock).mockReset();
  });

  describe('signup', () => {
    const signupDto = {
      email: 'test@example.com',
      password: 'password123',
      firstName: 'Test',
      lastName: 'User',
    };

    it('should create a new user successfully', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);
      mockUsersService.createLocal.mockResolvedValue(mockUser);
      mockTokensService.generateTokenPair.mockResolvedValue(mockTokenPair);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(true);

      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');

      const result = await service.signup(signupDto, '127.0.0.1', 'Test Device');

      expect(result).toEqual({
        accessToken: mockTokenPair.accessToken,
        refreshToken: mockTokenPair.refreshToken,
      });
      expect(mockUsersService.findByEmail).toHaveBeenCalledWith(signupDto.email);
      expect(bcrypt.hash).toHaveBeenCalledWith(signupDto.password, 12);
      expect(mockUsersService.createLocal).toHaveBeenCalledWith({
        email: signupDto.email,
        passwordHash: 'hashed-password',
        firstName: signupDto.firstName,
        lastName: signupDto.lastName,
      });
      expect(mockTokensService.generateTokenPair).toHaveBeenCalledWith({
        userId: mockUser.id,
        email: mockUser.email,
        deviceInfo: 'Test Device',
        ipAddress: '127.0.0.1',
      });
    });

    it('should throw BadRequestException if email already exists', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);

      await expect(
        service.signup(signupDto)
      ).rejects.toThrow(BadRequestException);
      expect(mockUsersService.createLocal).not.toHaveBeenCalled();
    });

    it('should handle welcome email failure gracefully', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);
      mockUsersService.createLocal.mockResolvedValue(mockUser);
      mockTokensService.generateTokenPair.mockResolvedValue(mockTokenPair);
      mockEmailService.sendWelcomeEmail.mockRejectedValue(new Error('Email failed'));

      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');

      const result = await service.signup(signupDto);

      expect(result).toEqual({
        accessToken: mockTokenPair.accessToken,
        refreshToken: mockTokenPair.refreshToken,
      });
    });
  });

  describe('login', () => {
    const loginDto = {
      email: 'test@example.com',
      password: 'password123',
    };

    it('should login user successfully', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      mockPrismaService.users.update.mockResolvedValue(mockUser);
      mockTokensService.generateTokenPair.mockResolvedValue(mockTokenPair);

      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.login(loginDto, '127.0.0.1', 'Test Device');

      expect(result).toEqual({
        accessToken: mockTokenPair.accessToken,
        refreshToken: mockTokenPair.refreshToken,
      });
      expect(mockUsersService.findByEmail).toHaveBeenCalledWith(loginDto.email);
      expect(bcrypt.compare).toHaveBeenCalledWith(loginDto.password, mockUser.password);
      expect(mockPrismaService.users.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: {
          lastLoginAt: expect.any(Date),
          loginCount: { increment: 1 },
          updatedAt: expect.any(Date),
        },
      });
    });

    it('should throw UnauthorizedException for non-existent user', async () => {
      mockUsersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.login(loginDto)
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for invalid password', async () => {
      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.login(loginDto)
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException for user without password', async () => {
      const userWithoutPassword = { ...mockUser, password: null };
      mockUsersService.findByEmail.mockResolvedValue(userWithoutPassword);

      await expect(
        service.login(loginDto)
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('should logout user successfully', async () => {
      const refreshToken = 'valid-refresh-token';
      const tokenRecord = {
        id: 'token-id',
        userId: 1,
        isRevoked: false,
      };

      mockPrismaService.refresh_tokens.findFirst.mockResolvedValue(tokenRecord);
      mockTokensService.revokeToken.mockResolvedValue(undefined);

      const result = await service.logout(refreshToken);

      expect(result).toEqual({ success: true });
      expect(mockPrismaService.refresh_tokens.findFirst).toHaveBeenCalledWith({
        where: {
          token: refreshToken,
          isRevoked: false,
        },
      });
      expect(mockTokensService.revokeToken).toHaveBeenCalledWith(tokenRecord.id);
    });

    it('should handle logout without valid token gracefully', async () => {
      const refreshToken = 'invalid-refresh-token';

      mockPrismaService.refresh_tokens.findFirst.mockResolvedValue(null);

      const result = await service.logout(refreshToken);

      expect(result).toEqual({ success: true });
      expect(mockTokensService.revokeToken).not.toHaveBeenCalled();
    });

    it('should handle logout errors gracefully', async () => {
      const refreshToken = 'valid-refresh-token';

      mockPrismaService.refresh_tokens.findFirst.mockRejectedValue(new Error('DB Error'));

      const result = await service.logout(refreshToken);

      expect(result).toEqual({ success: true });
    });
  });

  describe('refreshTokens', () => {
    it('should refresh tokens successfully', async () => {
      const refreshToken = 'valid-refresh-token';
      const newTokenPair = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
      };

      mockTokensService.rotateRefreshToken.mockResolvedValue(newTokenPair);

      const result = await service.refreshTokens(refreshToken, '127.0.0.1', 'Test Device');

      expect(result).toEqual(newTokenPair);
      expect(mockTokensService.rotateRefreshToken).toHaveBeenCalledWith(
        refreshToken,
        '127.0.0.1',
        'Test Device'
      );
    });

    it('should throw UnauthorizedException on refresh failure', async () => {
      const refreshToken = 'invalid-refresh-token';

      mockTokensService.rotateRefreshToken.mockRejectedValue(new Error('Invalid token'));

      await expect(
        service.refreshTokens(refreshToken)
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('requestPasswordReset', () => {
    it('should send password reset email for existing user', async () => {
      const email = 'test@example.com';

      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      mockPrismaService.users.update.mockResolvedValue(mockUser);
      mockEmailService.sendPasswordResetEmail.mockResolvedValue(true);

      const result = await service.requestPasswordReset(email);

      expect(result).toEqual({ success: true });
      expect(mockUsersService.findByEmail).toHaveBeenCalledWith(email);
      expect(mockPrismaService.users.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: {
          resetPasswordToken: expect.any(String),
          resetPasswordExpires: expect.any(Date),
          updatedAt: expect.any(Date),
        },
      });
    });

    it('should return success for non-existent user (security)', async () => {
      const email = 'nonexistent@example.com';

      mockUsersService.findByEmail.mockResolvedValue(null);

      const result = await service.requestPasswordReset(email);

      expect(result).toEqual({ success: true });
      expect(mockPrismaService.users.update).not.toHaveBeenCalled();
    });

    it('should handle email sending failure gracefully', async () => {
      const email = 'test@example.com';

      mockUsersService.findByEmail.mockResolvedValue(mockUser);
      mockPrismaService.users.update.mockResolvedValue(mockUser);
      mockEmailService.sendPasswordResetEmail.mockRejectedValue(new Error('Email failed'));

      const result = await service.requestPasswordReset(email);

      expect(result).toEqual({ success: true });
    });
  });

  describe('resetPassword', () => {
    const resetToken = 'valid-reset-token';
    const newPassword = 'newpassword123';

    it('should reset password successfully', async () => {
      const userWithResetToken = {
        ...mockUser,
        resetPasswordToken: 'hashed-token',
        resetPasswordExpires: new Date(Date.now() + 30 * 60 * 1000),
      };

      mockPrismaService.users.findFirst.mockResolvedValue(userWithResetToken);
      mockPrismaService.users.update.mockResolvedValue(mockUser);
      mockTokensService.revokeAllUserTokens.mockResolvedValue(undefined);

      (bcrypt.hash as jest.Mock).mockResolvedValue('new-hashed-password');

      const result = await service.resetPassword(resetToken, newPassword);

      expect(result).toEqual({ success: true });
      expect(bcrypt.hash).toHaveBeenCalledWith(newPassword, 12);
      expect(mockPrismaService.users.update).toHaveBeenCalledWith({
        where: { id: userWithResetToken.id },
        data: {
          password: 'new-hashed-password',
          resetPasswordToken: null,
          resetPasswordExpires: null,
          lastPasswordChange: expect.any(Date),
          updatedAt: expect.any(Date),
        },
      });
      expect(mockTokensService.revokeAllUserTokens).toHaveBeenCalledWith(userWithResetToken.id);
    });

    it('should throw BadRequestException for empty token', async () => {
      await expect(
        service.resetPassword('', newPassword)
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw UnauthorizedException for invalid token', async () => {
      mockPrismaService.users.findFirst.mockResolvedValue(null);

      await expect(
        service.resetPassword(resetToken, newPassword)
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('Session Management', () => {
    it('should get user sessions', async () => {
      const userId = 1;
      const sessions = [{ id: 'session1' }, { id: 'session2' }];

      mockTokensService.getUserSessions.mockResolvedValue(sessions);

      const result = await service.getUserSessions(userId);

      expect(result).toEqual(sessions);
      expect(mockTokensService.getUserSessions).toHaveBeenCalledWith(userId);
    });

    it('should revoke specific user session', async () => {
      const userId = 1;
      const sessionId = 'session-to-revoke';
      const sessions = [{ id: sessionId }];

      mockTokensService.getUserSessions.mockResolvedValue(sessions);
      mockTokensService.revokeToken.mockResolvedValue(undefined);

      const result = await service.revokeUserSession(userId, sessionId);

      expect(result).toEqual({ success: true });
      expect(mockTokensService.revokeToken).toHaveBeenCalledWith(sessionId);
    });

    it('should throw NotFoundException for non-existent session', async () => {
      const userId = 1;
      const sessionId = 'non-existent-session';

      mockTokensService.getUserSessions.mockResolvedValue([]);

      await expect(
        service.revokeUserSession(userId, sessionId)
      ).rejects.toThrow(NotFoundException);
    });

    it('should revoke all user sessions', async () => {
      const userId = 1;

      mockTokensService.revokeAllUserTokens.mockResolvedValue(undefined);

      const result = await service.revokeAllUserSessions(userId);

      expect(result).toEqual({ success: true });
      expect(mockTokensService.revokeAllUserTokens).toHaveBeenCalledWith(userId);
    });
  });
});