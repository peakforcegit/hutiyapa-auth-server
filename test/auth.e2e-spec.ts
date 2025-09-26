import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/infra/prisma/prisma.service';
import cookieParser from 'cookie-parser';
const request = require('supertest');

describe('Authentication E2E Tests', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  const testUser = {
    email: 'test-e2e@example.com',
    password: 'TestPassword123!',
    firstName: 'Test',
    lastName: 'User',
  };

  beforeAll(async () => {
    // Set test environment if not already set
    if (!process.env.NODE_ENV) {
      process.env.NODE_ENV = 'test';
    }

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.use(cookieParser());
    
    prisma = app.get(PrismaService);
    
    await app.init();

    // Clean up test user
    try {
      await prisma.users.deleteMany({
        where: { email: testUser.email },
      });
    } catch (error) {
      // Ignore cleanup errors
    }
  });

  afterAll(async () => {
    try {
      if (prisma) {
        await prisma.users.deleteMany({
          where: { email: testUser.email },
        });
        await prisma.$disconnect();
      }
    } catch (error) {
      // Ignore cleanup errors
    }
    
    if (app) {
      await app.close();
    }
  });

  describe('User Signup', () => {
    it('should register a new user successfully', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/signup')
        .send(testUser)
        .expect(201);

      expect(response.body).toHaveProperty('message');
      
      // Verify user was created
      const user = await prisma.users.findUnique({
        where: { email: testUser.email },
      });
      
      expect(user).toBeDefined();
      if (user) {
        expect(user.email).toBe(testUser.email);
        expect(user.firstName).toBe(testUser.firstName);
        expect(user.lastName).toBe(testUser.lastName);
        expect(user.password).not.toBe(testUser.password); // Should be hashed
      }
    });

    it('should not register duplicate users', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send(testUser)
        .expect(409);
    });

    it('should validate required fields', async () => {
      await request(app.getHttpServer())
        .post('/auth/signup')
        .send({
          email: 'invalid-email',
          password: '123', // Too short
        })
        .expect(400);
    });
  });

  describe('User Login', () => {
    it('should login with valid credentials', async () => {
      const response = await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user.email).toBe(testUser.email);

      // Check for cookies
      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should reject invalid credentials', async () => {
      await request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: 'wrongpassword',
        })
        .expect(401);
    });
  });

  describe('Security', () => {
    it('should include security headers', async () => {
      const response = await request(app.getHttpServer())
        .get('/health')
        .expect(200);

      // Check for helmet headers
      expect(response.headers['x-frame-options']).toBeDefined();
      expect(response.headers['x-content-type-options']).toBeDefined();
    });
  });
});