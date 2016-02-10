package org.projectlombok.security.totpexample;

import java.security.SecureRandom;

public final class Crypto {
	private static final String KEYCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	private final SecureRandom random;
	
	public Crypto() {
		this.random = new SecureRandom();
	}
	
	public String generateRandomKey(int length) {
		char[] out = new char[length];
		for (int i = 0; i < length; i++) {
			out[i] = KEYCHARS.charAt(random.nextInt(KEYCHARS.length()));
		}
		return new String(out);
	}
}
