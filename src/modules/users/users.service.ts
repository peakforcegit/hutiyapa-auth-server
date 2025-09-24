import { Injectable } from '@nestjs/common';
import { UsersRepository } from './users.repository';

@Injectable()
export class UsersService {
  constructor(private readonly usersRepo: UsersRepository) {}

  findByEmail(email: string) {
    return this.usersRepo.findByEmail(email);
  }

  createLocal(params: { email: string; passwordHash: string; firstName?: string; lastName?: string }) {
    return this.usersRepo.createLocalUser(params);
  }
}
