require('dotenv').config();
const { PrismaClient } = require('./generated/prisma');
const { randomBytes, createHash } = require('crypto');
const prisma = new PrismaClient();

async function generateValidToken() {
  try {
    console.log('🔧 Generating fresh valid token...');
    
    // Generate new token
    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(rawToken).digest('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 minutes
    
    console.log('Raw token:', rawToken);
    console.log('Token hash:', tokenHash);
    console.log('Expires at:', expires);
    
    // Update user with token
    const user = await prisma.users.update({
      where: { email: 'sd.vikasvaibhav@gmail.com' },
      data: { 
        resetPasswordToken: tokenHash, 
        resetPasswordExpires: expires,
        updatedAt: new Date()
      }
    });
    
    console.log('✅ Token updated for user ID:', user.id);
    console.log('🔗 Use this URL:');
    console.log(`http://localhost:3001/reset-password?token=${rawToken}`);
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await prisma.$disconnect();
  }
}

generateValidToken();