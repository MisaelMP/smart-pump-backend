import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import bcrypt from 'bcrypt';
import path from 'path';
import {
	DatabaseSchema,
	User,
	UserSchema,
	UpdateUserRequest,
} from '../types/index.js';

class DatabaseService {
	private db: Low<DatabaseSchema> | null = null;
	private readonly dbPath: string;
	private readonly saltRounds = 12;

	constructor(dbPath: string = './data/db.json') {
		this.dbPath = path.resolve(dbPath);
	}

	async initialize(): Promise<void> {
		try {
			const adapter = new JSONFile<DatabaseSchema>(this.dbPath);
			this.db = new Low(adapter, { users: [] });

			await this.db.read();

			// Initialize with mock data if database is empty
			if (!this.db.data.users || this.db.data.users.length === 0) {
				await this.seedDatabase();
			}

			console.log(`✅ Database initialized at ${this.dbPath}`);
		} catch (error) {
			console.error('❌ Database initialization failed:', error);
			throw new Error('Failed to initialize database');
		}
	}

	private async seedDatabase(): Promise<void> {
		if (!this.db) throw new Error('Database not initialized');

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

		// Hash passwords for all users
		const usersWithHashedPasswords: User[] = await Promise.all(
			mockUsers.map(async (user, index) => {
				const originalPasswords = [
					'23derd*334',
					'_4rhododfj',
					'34oii+345',
					'ndfadsf(d',
					'red^adl4',
				];

				const hashedPassword = await bcrypt.hash(
					originalPasswords[index]!,
					this.saltRounds
				);
				return { ...user, password: hashedPassword };
			})
		);

		this.db.data.users = usersWithHashedPasswords;
		await this.db.write();

		console.log(
			`✅ Seeded database with ${usersWithHashedPasswords.length} users`
		);
	}

	async findUserByEmail(email: string): Promise<User | null> {
		if (!this.db) throw new Error('Database not initialized');

		await this.db.read();
		const user = this.db.data.users.find(
			(u) => u.email.toLowerCase() === email.toLowerCase()
		);
		return user || null;
	}

	async findUserById(id: string): Promise<User | null> {
		if (!this.db) throw new Error('Database not initialized');

		await this.db.read();
		const user = this.db.data.users.find((u) => u._id === id);
		return user || null;
	}

	async validateUserCredentials(
		email: string,
		password: string
	): Promise<User | null> {
		const user = await this.findUserByEmail(email);
		if (!user || !user.isActive) {
			return null;
		}

		const isValidPassword = await bcrypt.compare(password, user.password);
		return isValidPassword ? user : null;
	}

	async updateUser(
		userId: string,
		updates: UpdateUserRequest
	): Promise<User | null> {
		if (!this.db) throw new Error('Database not initialized');

		await this.db.read();

		const userIndex = this.db.data.users.findIndex((u) => u._id === userId);
		if (userIndex === -1) {
			return null;
		}

		const currentUser = this.db.data.users[userIndex]!;
		const updatedUser: User = {
			...currentUser,
			...updates,
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

		this.db.data.users[userIndex] = updatedUser;
		await this.db.write();

		return updatedUser;
	}

	async getAllUsers(): Promise<User[]> {
		if (!this.db) throw new Error('Database not initialized');

		await this.db.read();
		return this.db.data.users;
	}

	async updatePassword(userId: string, newPassword: string): Promise<boolean> {
		if (!this.db) throw new Error('Database not initialized');

		await this.db.read();

		const userIndex = this.db.data.users.findIndex((u) => u._id === userId);
		if (userIndex === -1) {
			return false;
		}

		const hashedPassword = await bcrypt.hash(newPassword, this.saltRounds);
		this.db.data.users[userIndex]!.password = hashedPassword;
		await this.db.write();

		return true;
	}

	async close(): Promise<void> {
		// LowDB doesn't require explicit closing
		console.log('📘 Database connection closed');
	}
}

export const databaseService = new DatabaseService();
export default databaseService;
