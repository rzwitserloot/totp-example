package org.projectlombok.security.totpexample;

import java.security.SecureRandom;

public final class Crypto {
	private static final String KEYCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	
	private final SecureRandom random;
	
	public Crypto() {
		this.random = new SecureRandom();
	}
	
	public String generateRandomKey(int length) {
		return generate(KEYCHARS, length);
	}
	
	public String generate(String alphabet, int length) {
		char[] out = new char[length];
		for (int i = 0; i < length; i++) {
			out[i] = alphabet.charAt(random.nextInt(alphabet.length()));
		}
		return new String(out);
	}
	
	public String hashPassword(char[] password) {
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		return BCrypt.generate(password, salt, 10);
	}
	
	public boolean verifyPassword(String hash, char[] password) {
		return BCrypt.checkPassword(hash, password);
	}
}
