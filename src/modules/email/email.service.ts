import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get('SMTP_HOST'),
      port: this.configService.get('SMTP_PORT'),
      secure: this.configService.get('SMTP_SECURE') === 'true',
      auth: {
        user: this.configService.get('SMTP_USER'),
        pass: this.configService.get('SMTP_PASS'),
      },
    });
  }

  async sendPasswordResetEmail(email: string, resetToken: string): Promise<void> {
    try {
      const frontendUrl = this.configService.get('FRONTEND_URL');
      const resetLink = `${frontendUrl}/reset-password?token=${resetToken}`;
      
      const mailOptions = {
        from: this.configService.get('EMAIL_FROM'),
        to: email,
        subject: '🔒 Password Reset Request - Auth System',
        html: this.getPasswordResetEmailTemplate(resetLink, email),
      };

      const result = await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent successfully to ${email}`);
      this.logger.debug(`Email message ID: ${result.messageId}`);
      
    } catch (error) {
      this.logger.error(`Failed to send password reset email to ${email}:`, error.message);
      
      // Fallback: Still log the reset link for development
      const frontendUrl = this.configService.get('FRONTEND_URL');
      const resetLink = `${frontendUrl}/reset-password?token=${resetToken}`;
      this.logger.warn(`[FALLBACK] Reset link for ${email}: ${resetLink}`);
      
      throw new Error('Failed to send password reset email');
    }
  }

  private getPasswordResetEmailTemplate(resetLink: string, email: string): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset Request</title>
    </head>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 28px;">🔒 Password Reset</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #333; margin-top: 0;">Hi there!</h2>
            
            <p style="margin: 20px 0;">We received a request to reset the password for your account associated with <strong>${email}</strong>.</p>
            
            <p style="margin: 20px 0;">If you requested this password reset, click the button below to create a new password:</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="${resetLink}" 
                   style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; 
                          padding: 12px 30px; 
                          text-decoration: none; 
                          border-radius: 5px; 
                          font-weight: bold; 
                          display: inline-block;
                          box-shadow: 0 2px 10px rgba(102, 126, 234, 0.3);">
                    Reset My Password
                </a>
            </div>
            
            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;"><strong>⚠️ Important:</strong></p>
                <ul style="margin: 10px 0; color: #856404;">
                    <li>This link will expire in <strong>30 minutes</strong></li>
                    <li>If you didn't request this reset, you can safely ignore this email</li>
                    <li>Your password will remain unchanged</li>
                </ul>
            </div>
            
            <p style="margin: 20px 0; color: #666; font-size: 14px;">
                If the button above doesn't work, copy and paste this link into your browser:<br>
                <span style="word-break: break-all; color: #667eea;">${resetLink}</span>
            </p>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            
            <p style="margin: 0; color: #999; font-size: 12px; text-align: center;">
                This email was sent from Auth System. If you have questions, please contact our support team.
            </p>
        </div>
        
    </body>
    </html>
    `;
  }

  async sendWelcomeEmail(email: string, name: string): Promise<void> {
    try {
      const mailOptions = {
        from: this.configService.get('EMAIL_FROM'),
        to: email,
        subject: '🎉 Welcome to Auth System!',
        html: this.getWelcomeEmailTemplate(name, email),
      };

      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Welcome email sent successfully to ${email}`);
      
    } catch (error) {
      this.logger.error(`Failed to send welcome email to ${email}:`, error.message);
      // Don't throw error for welcome email failures
    }
  }

  private getWelcomeEmailTemplate(name: string, email: string): string {
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to Auth System</title>
    </head>
    <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        
        <div style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 28px;">🎉 Welcome!</h1>
        </div>
        
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <h2 style="color: #333; margin-top: 0;">Hi ${name}!</h2>
            
            <p style="margin: 20px 0;">Welcome to Auth System! Your account has been successfully created.</p>
            
            <p style="margin: 20px 0;">You can now access all the features of our platform. If you have any questions, feel free to contact our support team.</p>
            
            <div style="text-align: center; margin: 30px 0;">
                <a href="${this.configService.get('FRONTEND_URL')}/login" 
                   style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); 
                          color: white; 
                          padding: 12px 30px; 
                          text-decoration: none; 
                          border-radius: 5px; 
                          font-weight: bold; 
                          display: inline-block;
                          box-shadow: 0 2px 10px rgba(17, 153, 142, 0.3);">
                    Start Exploring
                </a>
            </div>
            
            <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
            
            <p style="margin: 0; color: #999; font-size: 12px; text-align: center;">
                This email was sent to ${email}. If you have questions, please contact our support team.
            </p>
        </div>
        
    </body>
    </html>
    `;
  }
}