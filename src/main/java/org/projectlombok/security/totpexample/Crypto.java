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
}
