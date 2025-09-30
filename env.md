DATABASE_URL='postgresql://neondb_owner:npg_3tpYXNZdBuk1@ep-sweet-sunset-adxjjs2y-pooler.c-2.us-east-1.aws.neon.tech/auth_hutiyapa?sslmode=require&channel_binding=require&connect_timeout=60&pool_timeout=60&socket_timeout=60'
# Server
PORT=3000
NODE_ENV=development

# App
APP_NAME=auth-server
APP_URL=http://localhost:3000


# Security (placeholders)
JWT_ACCESS_SECRET=This-is-access-token-of-jwt-secret-key-8Hsg1buxWcYAu8WCAdAGgKtqJxJ0
JWT_REFRESH_SECRET=This-is-refresh-token-of-jwt-secret-key-8Hsg1buxWcYAu8WCAdAGgKthhh
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=30d

# Google OAuth (placeholders)
GOOGLE_CLIENT_ID="enter OAuth Client_Id"
GOOGLE_CLIENT_SECRET='Secret_Key_Id'
GOOGLE_CALLBACK_URL=http://localhost:3000/api/auth/google/callback

FRONTEND_URL=http://localhost:3001
CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Secret key for signing cookies
COOKIE_SECRET=super-secret-cookie-key-that-is-32-chars-long

# Email Configuration - Hostinger (peakforce.co.in)
SMTP_HOST=smtp.hostinger.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=vikasvaibhav@peakforce.co.in
SMTP_PASS=@Programmerviva1
EMAIL_FROM="vikasvaibhav@peakforce.co.in"