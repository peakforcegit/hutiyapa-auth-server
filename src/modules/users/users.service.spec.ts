import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from '../../../src/modules/users/users.service';
import { UsersRepository } from '../../../src/modules/users/users.repository';

// Mock data
const mockUser = {
  id: 1,
  email: 'test@example.com',
  password: 'hashed-password',
  firstName: 'Test',
  lastName: 'User',
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockCreateUserData = {
  email: 'new@example.com',
  passwordHash: 'hashed-password',
  firstName: 'New',
  lastName: 'User',
};

describe('UsersService', () => {
  let service: UsersService;
  let usersRepository: UsersRepository;

  const mockUsersRepository = {
    findByEmail: jest.fn(),
    createLocalUser: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: UsersRepository,
          useValue: mockUsersRepository,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    usersRepository = module.get<UsersRepository>(UsersRepository);

    // Reset all mocks
    Object.values(mockUsersRepository).forEach(mock => mock.mockReset());
  });

  describe('findByEmail', () => {
    it('should find user by email successfully', async () => {
      mockUsersRepository.findByEmail.mockResolvedValue(mockUser);

      const result = await service.findByEmail('test@example.com');

      expect(result).toEqual(mockUser);
      expect(mockUsersRepository.findByEmail).toHaveBeenCalledWith('test@example.com');
    });

    it('should return null if user not found', async () => {
      mockUsersRepository.findByEmail.mockResolvedValue(null);

      const result = await service.findByEmail('nonexistent@example.com');

      expect(result).toBeNull();
      expect(mockUsersRepository.findByEmail).toHaveBeenCalledWith('nonexistent@example.com');
    });

    it('should handle repository errors', async () => {
      const error = new Error('Database connection failed');
      mockUsersRepository.findByEmail.mockRejectedValue(error);

      await expect(service.findByEmail('test@example.com')).rejects.toThrow('Database connection failed');
    });
  });

  describe('createLocal', () => {
    it('should create local user successfully', async () => {
      const newUser = { ...mockUser, ...mockCreateUserData };
      mockUsersRepository.createLocalUser.mockResolvedValue(newUser);

      const result = await service.createLocal(mockCreateUserData);

      expect(result).toEqual(newUser);
      expect(mockUsersRepository.createLocalUser).toHaveBeenCalledWith(mockCreateUserData);
    });

    it('should create user with minimal data', async () => {
      const minimalData = {
        email: 'minimal@example.com',
        passwordHash: 'hashed-password',
      };
      const minimalUser = { ...mockUser, ...minimalData };
      mockUsersRepository.createLocalUser.mockResolvedValue(minimalUser);

      const result = await service.createLocal(minimalData);

      expect(result).toEqual(minimalUser);
      expect(mockUsersRepository.createLocalUser).toHaveBeenCalledWith(minimalData);
    });

    it('should handle repository errors during creation', async () => {
      const error = new Error('Email already exists');
      mockUsersRepository.createLocalUser.mockRejectedValue(error);

      await expect(service.createLocal(mockCreateUserData)).rejects.toThrow('Email already exists');
    });

    it('should handle creation with optional fields', async () => {
      const dataWithOptionalFields = {
        email: 'optional@example.com',
        passwordHash: 'hashed-password',
        firstName: 'Optional',
        lastName: 'User',
      };
      const userWithOptionalFields = { ...mockUser, ...dataWithOptionalFields };
      mockUsersRepository.createLocalUser.mockResolvedValue(userWithOptionalFields);

      const result = await service.createLocal(dataWithOptionalFields);

      expect(result).toEqual(userWithOptionalFields);
      expect(mockUsersRepository.createLocalUser).toHaveBeenCalledWith(dataWithOptionalFields);
    });
  });

  describe('Service Integration', () => {
    it('should handle multiple operations in sequence', async () => {
      // First, try to find a user
      mockUsersRepository.findByEmail.mockResolvedValue(null);
      
      const existingUser = await service.findByEmail('new@example.com');
      expect(existingUser).toBeNull();

      // Then create the user
      const newUser = { ...mockUser, email: 'new@example.com' };
      mockUsersRepository.createLocalUser.mockResolvedValue(newUser);
      
      const createdUser = await service.createLocal({
        email: 'new@example.com',
        passwordHash: 'hashed-password',
        firstName: 'New',
        lastName: 'User',
      });

      expect(createdUser).toEqual(newUser);
      expect(mockUsersRepository.findByEmail).toHaveBeenCalledWith('new@example.com');
      expect(mockUsersRepository.createLocalUser).toHaveBeenCalledWith({
        email: 'new@example.com',
        passwordHash: 'hashed-password',
        firstName: 'New',
        lastName: 'User',
      });
    });

    it('should properly delegate all calls to repository', async () => {
      const email = 'delegate@example.com';
      const userData = {
        email,
        passwordHash: 'hashed-password',
        firstName: 'Delegate',
        lastName: 'Test',
      };

      // Test findByEmail delegation
      mockUsersRepository.findByEmail.mockResolvedValue(mockUser);
      await service.findByEmail(email);
      expect(mockUsersRepository.findByEmail).toHaveBeenCalledWith(email);

      // Test createLocal delegation
      mockUsersRepository.createLocalUser.mockResolvedValue(mockUser);
      await service.createLocal(userData);
      expect(mockUsersRepository.createLocalUser).toHaveBeenCalledWith(userData);
    });
  });
});