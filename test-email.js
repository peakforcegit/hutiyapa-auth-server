const nodemailer = require('nodemailer');
require('dotenv').config();

async function testEmail() {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });

  try {
    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: 'sd.vikasvaibhav@gmail.com',
      subject: 'Test Email from PeakForce',
      text: 'If you receive this, email configuration is working!',
    });
    console.log('✅ Email sent successfully:', info.messageId);
  } catch (error) {
    console.error('❌ Email failed:', error.message);
  }
}

testEmail();
