import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import bcrypt from 'bcrypt';
import path from 'path';
import fs from 'fs/promises';
import {
  DatabaseSchema,
  User,
  UserSchema,
  UpdateUserRequest,
} from '../types/index';

// Database state
interface DatabaseState {
  db: Low<DatabaseSchema> | null;
  dbPath: string;
  saltRounds: number;
}

// Create database state
const createDatabaseState = (
  dbPath: string = './data/db.json'
): DatabaseState => ({
  db: null,
  dbPath: path.resolve(dbPath),
  saltRounds: 12,
});

// Initialize database
const initializeDatabase = async (
  state: DatabaseState
): Promise<DatabaseState> => {
  try {
    // Ensure directory exists
    const dbDir = path.dirname(state.dbPath);
    await fs.mkdir(dbDir, { recursive: true });

    const adapter = new JSONFile<DatabaseSchema>(state.dbPath);
    const db = new Low(adapter, { users: [] });

    await db.read();

    // Initialize with mock data if database is empty
    if (!db.data.users || db.data.users.length === 0) {
      await seedDatabase({ ...state, db });
    }

    console.log(`Database initialized at ${state.dbPath}`);
    return { ...state, db };
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw new Error('Failed to initialize database');
  }
};

// Seed database with mock data
const seedDatabase = async (
  state: DatabaseState & { db: Low<DatabaseSchema> }
): Promise<void> => {
  const mockUsers: Omit<User, 'password'>[] = [
    {
      _id: '5410953eb0e0c0ae25608277',
      guid: 'eab0324c-75ef-49a1-9c49-be2d68f50b96',
      isActive: true,
      balance: '$3,585.69',
      picture: 'http://placehold.it/32x32',
      age: 30,
      eyeColor: 'blue' as const,
      name: {
        first: 'Henderson',
        last: 'Briggs',
      },
      company: 'GEEKNET',
      email: 'henderson.briggs@geeknet.net',
      phone: '+1 (936) 451-3590',
      address: '121 National Drive, Cotopaxi, Michigan, 8240',
    },
    {
      _id: '5410953eee9a5b30c3eea476',
      guid: 'b26ea5d1-d8db-4106-91a2-57f42a5c7e9e',
      isActive: false,
      balance: '$3,230.56',
      picture: 'http://placehold.it/32x32',
      age: 30,
      eyeColor: 'brown' as const,
      name: {
        first: 'Boyd',
        last: 'Small',
      },
      company: 'ENDIPINE',
      email: 'boyd.small@endipine.biz',
      phone: '+1 (814) 437-3837',
      address: '261 Willow Street, Whipholt, Louisiana, 2879',
    },
    {
      _id: '5410953ea3e25180277b2a40',
      guid: 'd5464d51-b4bf-4a4b-a5f7-fc2c8933ab45',
      isActive: true,
      balance: '$1,668.20',
      picture: 'http://placehold.it/32x32',
      age: 33,
      eyeColor: 'green' as const,
      name: {
        first: 'Lott',
        last: 'Kramer',
      },
      company: 'POSHOME',
      email: 'lott.kramer@poshome.us',
      phone: '+1 (983) 565-2711',
      address: '743 Ryder Avenue, Marenisco, South Dakota, 4752',
    },
    {
      _id: '5410953eada96439866e0a30',
      guid: '5a98f752-22fe-499c-8288-ad0218c89552',
      isActive: true,
      balance: '$1,656.46',
      picture: 'http://placehold.it/32x32',
      age: 35,
      eyeColor: 'brown' as const,
      name: {
        first: 'Gibson',
        last: 'Duke',
      },
      company: 'ZILLAR',
      email: 'gibson.duke@zillar.com',
      phone: '+1 (971) 473-2320',
      address: '110 Roosevelt Place, Salunga, South Carolina, 9434',
    },
    {
      _id: '5410953e099f716e02f32e05',
      guid: '584de54b-fa74-480d-90a4-b1b38cd02685',
      isActive: true,
      balance: '$1,778.30',
      picture: 'http://placehold.it/32x32',
      age: 23,
      eyeColor: 'green' as const,
      name: {
        first: 'Ruby',
        last: 'Glenn',
      },
      company: 'WATERBABY',
      email: 'ruby.glenn@waterbaby.co.uk',
      phone: '+1 (800) 433-3997',
      address: '622 Fanchon Place, Kohatk, Marshall Islands, 8665',
    },
  ];

  // Generate test passwords for development (secure random for production)
  const usersWithHashedPasswords: User[] = await Promise.all(
    mockUsers.map(async (user, index) => {
      let password: string;

      if (process.env.NODE_ENV === 'development') {
        // Known passwords for development testing only
        const testPasswords = [
          'TestPass123!',
          'TestPass456!',
          'TestPass789!',
          'TestPass000!',
          'TestPass111!',
        ];
        password = testPasswords[index] || 'TestPassDefault!';
      } else {
        // Generate cryptographically secure random password for production
        password = require('crypto').randomBytes(16).toString('hex');
      }

      const hashedPassword = await bcrypt.hash(password, state.saltRounds);
      return { ...user, password: hashedPassword };
    })
  );

  state.db.data.users = usersWithHashedPasswords;
  await state.db.write();

  console.log(`Seeded database with ${usersWithHashedPasswords.length} users`);
};

// Find user by email
const findUserByEmail = async (
  state: DatabaseState,
  email: string
): Promise<User | null> => {
  if (!state.db) throw new Error('Database not initialized');

  await state.db.read();
  const user = state.db.data.users.find(
    (u) => u.email.toLowerCase() === email.toLowerCase()
  );
  return user || null;
};

// Find user by ID
const findUserById = async (
  state: DatabaseState,
  id: string
): Promise<User | null> => {
  if (!state.db) throw new Error('Database not initialized');

  await state.db.read();
  const user = state.db.data.users.find((u) => u._id === id);
  return user || null;
};

// Validate user credentials
const validateUserCredentials = async (
  state: DatabaseState,
  email: string,
  password: string
): Promise<User | null> => {
  const user = await findUserByEmail(state, email);
  if (!user || !user.isActive) {
    return null;
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  return isValidPassword ? user : null;
};

// Update user
const updateUser = async (
  state: DatabaseState,
  userId: string,
  updates: UpdateUserRequest
): Promise<User | null> => {
  if (!state.db) throw new Error('Database not initialized');

  await state.db.read();

  const userIndex = state.db.data.users.findIndex((u) => u._id === userId);
  if (userIndex === -1) {
    return null;
  }

  const currentUser = state.db.data.users[userIndex]!;
  const updatedUser: User = {
    ...currentUser,
    // Only include defined update fields
    ...(updates.company !== undefined && { company: updates.company }),
    ...(updates.email !== undefined && { email: updates.email }),
    ...(updates.phone !== undefined && { phone: updates.phone }),
    ...(updates.address !== undefined && { address: updates.address }),
    // Merge name object properly if provided
    name: updates.name
      ? { ...currentUser.name, ...updates.name }
      : currentUser.name,
  };

  // Validate the updated user
  try {
    UserSchema.parse(updatedUser);
  } catch (error) {
    throw new Error('Invalid user data after update');
  }

  state.db.data.users[userIndex] = updatedUser;
  await state.db.write();

  return updatedUser;
};

// Get all users
const getAllUsers = async (state: DatabaseState): Promise<User[]> => {
  if (!state.db) throw new Error('Database not initialized');

  await state.db.read();
  return state.db.data.users;
};

// Update password
const updatePassword = async (
  state: DatabaseState,
  userId: string,
  newPassword: string
): Promise<boolean> => {
  if (!state.db) throw new Error('Database not initialized');

  await state.db.read();

  const userIndex = state.db.data.users.findIndex((u) => u._id === userId);
  if (userIndex === -1) {
    return false;
  }

  const hashedPassword = await bcrypt.hash(newPassword, state.saltRounds);
  state.db.data.users[userIndex]!.password = hashedPassword;
  await state.db.write();

  return true;
};

// Close database connection
const closeDatabase = (): void => {
  // LowDB doesn't require explicit closing
  console.log('Database connection closed');
};

// Create database service instance
const databaseState = createDatabaseState();

// Export functional database service
export const databaseService = {
  initialize: () =>
    initializeDatabase(databaseState).then((newState) =>
      Object.assign(databaseState, newState)
    ),
  findUserByEmail: (email: string) => findUserByEmail(databaseState, email),
  findUserById: (id: string) => findUserById(databaseState, id),
  validateUserCredentials: (email: string, password: string) =>
    validateUserCredentials(databaseState, email, password),
  updateUser: (userId: string, updates: UpdateUserRequest) =>
    updateUser(databaseState, userId, updates),
  getAllUsers: () => getAllUsers(databaseState),
  updatePassword: (userId: string, newPassword: string) =>
    updatePassword(databaseState, userId, newPassword),
  close: closeDatabase,
};

export default databaseService;
