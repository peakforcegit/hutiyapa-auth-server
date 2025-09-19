import { INestApplication, Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '../../../generated/prisma';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit(): Promise<void> { await (this as any).$connect?.(); }
  async enableShutdownHooks(app: INestApplication): Promise<void> {
    (this as any).$on?.('beforeExit', async () => { await app.close(); });
  }
}
