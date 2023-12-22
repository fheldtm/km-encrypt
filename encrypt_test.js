const crypto = require('crypto');

const encrypt = (text, password) => {
	const algorithm = 'aes-256-ctr';
	const iv = crypto.randomBytes(16);
	const cipher = crypto.createCipheriv(algorithm, crypto.createHash('sha256').update(password).digest(), iv);
	const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
	return iv.toString('hex') + ':' + encrypted.toString('hex');
}

const decrypt = (hash, password) => {
	const algorithm = 'aes-256-ctr';
	const textParts = hash.split(':');
	const iv = Buffer.from(textParts.shift() || '', 'hex');
	const encryptedText = Buffer.from(textParts.join(':'), 'hex');
	const decipher = crypto.createDecipheriv(algorithm, crypto.createHash('sha256').update(password).digest(), iv);
	const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
	return decrypted.toString();
}

const password = '1';

const encrypted = encrypt('Hello World', password);
console.log(`Encrypted: ${encrypted}`);

const decrypted = decrypt(encrypted, password);
console.log(`Decrypted: ${decrypted}`);