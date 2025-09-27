require('dotenv').config();
const nodemailer = require('nodemailer');
const { randomBytes, createHash } = require('crypto');

async function testDirectReset() {
  console.log('🔧 Testing direct password reset email...');
  
  // Create transporter
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  // Generate reset token
  const rawToken = randomBytes(32).toString('hex');
  const base = process.env.FRONTEND_URL || process.env.NEXT_PUBLIC_FRONTEND_URL || 'http://localhost:3001';
  const resetLink = `${base}/reset-password?token=${rawToken}`;
  
  console.log('📧 Sending to: sd.vikasvaibhav@gmail.com');
  console.log('🔗 Reset link: ' + resetLink);

  try {
    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: 'sd.vikasvaibhav@gmail.com',
      subject: '🔒 Password Reset Request - Debug Test',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Reset Test</h2>
          <p>Hi! This is a debug test for password reset functionality.</p>
          <p>Click the link below to reset your password:</p>
          <a href="${resetLink}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
          <p>Or copy this link: ${resetLink}</p>
        </div>
      `,
      text: `Password Reset Test\n\nClick this link to reset: ${resetLink}`
    });
    
    console.log('✅ Email sent successfully!');
    console.log('📧 Message ID:', info.messageId);
  } catch (error) {
    console.error('❌ Email failed:', error);
  }
}

testDirectReset();
