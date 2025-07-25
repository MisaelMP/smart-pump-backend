// Development script to create test users with known passwords
// Usage: tsx scripts/create-test-users.ts

import bcrypt from 'bcrypt';

interface TestUserInput {
	email: string;
	password: string;
	name: { first: string; last: string };
}

const TEST_USERS: TestUserInput[] = [
	{
		email: 'henderson.briggs@geeknet.net',
		password: 'TestPass123!',
		name: { first: 'Henderson', last: 'Briggs' },
	},
	{
		email: 'lott.kramer@poshome.us',
		password: 'TestPass456!',
		name: { first: 'Lott', last: 'Kramer' },
	},
	{
		email: 'gibson.duke@zillar.com',
		password: 'TestPass789!',
		name: { first: 'Gibson', last: 'Duke' },
	},
	{
		email: 'ruby.glenn@waterbaby.co.uk',
		password: 'TestPass000!',
		name: { first: 'Ruby', last: 'Glenn' },
	},
];

const SALT_ROUNDS = 12;

const hashPassword = async (password: string): Promise<string> =>
	bcrypt.hash(password, SALT_ROUNDS);

const logUserCredentials = (email: string, password: string): void => {
	console.log(`${email} | ${password}`);
};

const validateEnvironment = (): void => {
	if (process.env.NODE_ENV !== 'development') {
		console.error('This script should only run in development');
		process.exit(1);
	}
};

const createTestUsers = async (): Promise<void> => {
	console.log('Creating test users with known passwords...');

	await Promise.all(
		TEST_USERS.map(async (user) => {
			await hashPassword(user.password);
			logUserCredentials(user.email, user.password);
		})
	);

	console.log('\nTest user credentials shown above');
	console.log('Only use these in development environment');
};

const main = async (): Promise<void> => {
	try {
		validateEnvironment();
		await createTestUsers();
	} catch (error) {
		console.error('Error creating test users:', error);
		process.exit(1);
	}
};

main();
