import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '../../../generated/prisma';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor() {
    super({
      datasources: {
        db: {
          url: process.env.DATABASE_URL,
        },
      },
      log: ['query', 'info', 'warn', 'error'],
    });
  }

  async onModuleInit(): Promise<void> { 
    try {
      await (this as any).$connect?.(); 
      console.log('Database connected successfully');
    } catch (error) {
      console.error('Database connection failed:', error);
      // Retry connection after a delay
      setTimeout(async () => {
        try {
          await (this as any).$connect?.();
          console.log('Database reconnected successfully');
        } catch (retryError) {
          console.error('Database retry connection failed:', retryError);
        }
      }, 5000);
    }
  }

  async enableShutdownHooks(app: INestApplication): Promise<void> {
    (this as any).$on?.('beforeExit', async () => { await app.close(); });
  }
}
