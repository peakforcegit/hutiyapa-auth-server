import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class UsersRepository {
  constructor(private readonly prisma: PrismaService) {}

  findByEmail(email: string) {
    return this.prisma.users.findUnique({ where: { email } });
  }

  createLocalUser(params: { email: string; passwordHash: string; name?: string | null }) {
    const { email, passwordHash, name } = params;
    return this.prisma.users.create({
      data: {
        email,
        password: passwordHash,
        firstName: name ?? '',
        lastName: '',
        updatedAt: new Date(),
      },
    });
  }
}
