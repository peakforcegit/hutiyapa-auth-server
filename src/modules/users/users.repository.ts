import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class UsersRepository {
  constructor(private readonly prisma: PrismaService) {}

  findByEmail(email: string) {
    return this.prisma.users.findUnique({ where: { email } });
  }

  createLocalUser(params: { email: string; passwordHash: string; firstName?: string; lastName?: string }) {
    const { email, passwordHash, firstName, lastName } = params;
    return this.prisma.users.create({
      data: {
        email,
        password: passwordHash,
        firstName: firstName ?? '',
        lastName: lastName ?? '',
        updatedAt: new Date(),
      },
    });
  }
}
