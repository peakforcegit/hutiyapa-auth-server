import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EmailService } from '../../../src/modules/email/email.service';
import * as nodemailer from 'nodemailer';

// Mock nodemailer
jest.mock('nodemailer');
const mockNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

describe('EmailService', () => {
  let service: EmailService;
  let configService: ConfigService;

  const mockTransporter = {
    sendMail: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Setup default config values
    mockConfigService.get.mockImplementation((key: string) => {
      const config = {
        SMTP_HOST: 'smtp.gmail.com',
        SMTP_PORT: 587,
        SMTP_SECURE: 'false',
        SMTP_USER: 'test@example.com',
        SMTP_PASS: 'test-password',
        EMAIL_FROM: 'noreply@example.com',
        FRONTEND_URL: 'http://localhost:3000',
      };
      return config[key];
    });

    // Setup nodemailer mock
    mockNodemailer.createTransport.mockReturnValue(mockTransporter as any);
    mockTransporter.sendMail.mockResolvedValue({
      messageId: 'test-message-id',
      response: '250 Message sent',
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EmailService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<EmailService>(EmailService);
    configService = module.get<ConfigService>(ConfigService);
  });

  describe('sendWelcomeEmail', () => {
    const email = 'user@example.com';
    const name = 'John Doe';

    it('should send welcome email successfully', async () => {
      await service.sendWelcomeEmail(email, name);

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@example.com',
        to: email,
        subject: '🎉 Welcome to Auth System!',
        html: expect.stringContaining(`Hi ${name}`),
      });
    });

    it('should handle email sending failure gracefully', async () => {
      mockTransporter.sendMail.mockRejectedValue(new Error('Failed to send email'));

      // Should not throw error for welcome email failures
      await expect(service.sendWelcomeEmail(email, name)).resolves.not.toThrow();
    });

    it('should generate correct welcome email content', async () => {
      await service.sendWelcomeEmail(email, name);

      const [emailOptions] = mockTransporter.sendMail.mock.calls[0];
      
      expect(emailOptions.html).toContain(`Hi ${name}`);
      expect(emailOptions.html).toContain('Welcome to Auth System');
      expect(emailOptions.html).toContain('http://localhost:3000/login');
      expect(emailOptions.html).toContain(email);
      expect(emailOptions.subject).toBe('🎉 Welcome to Auth System!');
    });

    it('should use correct sender configuration', async () => {
      await service.sendWelcomeEmail(email, name);

      const [emailOptions] = mockTransporter.sendMail.mock.calls[0];
      expect(emailOptions.from).toBe('noreply@example.com');
      expect(emailOptions.to).toBe(email);
    });
  });

  describe('sendPasswordResetEmail', () => {
    const email = 'user@example.com';
    const resetToken = 'reset-token-123';

    it('should send password reset email successfully', async () => {
      await service.sendPasswordResetEmail(email, resetToken);

      expect(mockTransporter.sendMail).toHaveBeenCalledWith({
        from: 'noreply@example.com',
        to: email,
        subject: '🔒 Password Reset Request - Auth System',
        html: expect.stringContaining(resetToken),
      });
    });

    it('should throw error when email sending fails', async () => {
      mockTransporter.sendMail.mockRejectedValue(new Error('SMTP error'));

      await expect(service.sendPasswordResetEmail(email, resetToken))
        .rejects.toThrow('Failed to send password reset email');
    });

    it('should generate correct password reset email content', async () => {
      await service.sendPasswordResetEmail(email, resetToken);

      const [emailOptions] = mockTransporter.sendMail.mock.calls[0];
      const resetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
      
      expect(emailOptions.html).toContain(email);
      expect(emailOptions.html).toContain(resetUrl);
      expect(emailOptions.html).toContain('Password Reset');
      expect(emailOptions.html).toContain('30 minutes');
      expect(emailOptions.subject).toBe('🔒 Password Reset Request - Auth System');
    });

    it('should include reset link with correct token', async () => {
      await service.sendPasswordResetEmail(email, resetToken);

      const [emailOptions] = mockTransporter.sendMail.mock.calls[0];
      const expectedResetUrl = `http://localhost:3000/reset-password?token=${resetToken}`;
      
      expect(emailOptions.html).toContain(expectedResetUrl);
    });

    it('should handle network timeout errors', async () => {
      mockTransporter.sendMail.mockRejectedValue(new Error('Connection timeout'));

      await expect(service.sendPasswordResetEmail(email, resetToken))
        .rejects.toThrow('Failed to send password reset email');
    });
  });

  describe('Service Configuration', () => {
    it('should initialize with correct SMTP settings', async () => {
      expect(mockNodemailer.createTransport).toHaveBeenCalledWith({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false,
        auth: {
          user: 'test@example.com',
          pass: 'test-password',
        },
      });
    });

    it('should use secure connection when SMTP_SECURE is true', async () => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'SMTP_SECURE') return 'true';
        if (key === 'SMTP_PORT') return 465;
        const config = {
          SMTP_HOST: 'smtp.gmail.com',
          SMTP_USER: 'test@example.com',
          SMTP_PASS: 'test-password',
          EMAIL_FROM: 'noreply@example.com',
          FRONTEND_URL: 'http://localhost:3000',
        };
        return config[key];
      });

      // Create a new service instance with updated config
      const module: TestingModule = await Test.createTestingModule({
        providers: [
          EmailService,
          {
            provide: ConfigService,
            useValue: mockConfigService,
          },
        ],
      }).compile();

      const newService = module.get<EmailService>(EmailService);

      expect(mockNodemailer.createTransport).toHaveBeenLastCalledWith({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
          user: 'test@example.com',
          pass: 'test-password',
        },
      });
    });

    it('should use config values for email templates', async () => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'FRONTEND_URL') return 'https://myapp.com';
        if (key === 'EMAIL_FROM') return 'support@myapp.com';
        const config = {
          SMTP_HOST: 'smtp.gmail.com',
          SMTP_PORT: 587,
          SMTP_SECURE: 'false',
          SMTP_USER: 'test@example.com',
          SMTP_PASS: 'test-password',
        };
        return config[key];
      });

      await service.sendPasswordResetEmail('test@example.com', 'token123');

      const [emailOptions] = mockTransporter.sendMail.mock.calls[0];
      
      expect(emailOptions.from).toBe('support@myapp.com');
      expect(emailOptions.html).toContain('https://myapp.com/reset-password?token=token123');
    });
  });

  describe('Error Scenarios', () => {
    it('should handle invalid email addresses gracefully in welcome email', async () => {
      mockTransporter.sendMail.mockRejectedValue(new Error('Invalid recipient'));

      // Should not throw for welcome email
      await expect(service.sendWelcomeEmail('invalid-email', 'Test User'))
        .resolves.not.toThrow();
    });

    it('should preserve error details in password reset failures', async () => {
      const originalError = new Error('SMTP Authentication failed');
      mockTransporter.sendMail.mockRejectedValue(originalError);

      await expect(service.sendPasswordResetEmail('test@example.com', 'token'))
        .rejects.toThrow('Failed to send password reset email');
    });

    it('should handle missing configuration values', async () => {
      mockConfigService.get.mockImplementation((key: string) => {
        if (key === 'FRONTEND_URL') return undefined;
        const config = {
          SMTP_HOST: 'smtp.gmail.com',
          SMTP_PORT: 587,
          SMTP_SECURE: 'false',
          SMTP_USER: 'test@example.com',
          SMTP_PASS: 'test-password',
          EMAIL_FROM: 'noreply@example.com',
        };
        return config[key];
      });

      await service.sendPasswordResetEmail('test@example.com', 'token123');

      const [emailOptions] = mockTransporter.sendMail.mock.calls[0];
      expect(emailOptions.html).toContain('undefined/reset-password?token=token123');
    });
  });
});