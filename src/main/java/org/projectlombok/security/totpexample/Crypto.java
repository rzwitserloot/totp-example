package org.projectlombok.security.totpexample;

import java.security.SecureRandom;

/**
 * You should generally have a single instance of {@code SecureRandom} which your server uses for all its secure random needs.
 * 
 * This class serves as a container for this concept. It also abstracts the password hash algorithm.
 */
public final class Crypto {
	private static final String KEYCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	
	private final SecureRandom random;
	
	public Crypto() {
		this.random = new SecureRandom();
	}
	
	/**
	 * Generates a new random string of {@code length} characters; each character is alphanumeric and should pass unharmed through all mainstream escaping and encoding mechanisms.
	 * 
	 * @param length The length of the random string to be generated.
	 * @return {@code length} random characters.
	 */
	public String generateRandomKey(int length) {
		return generate(KEYCHARS, length);
	}
	
	/**
	 * Generates a new random string of {@code length} characters; each character is taken, uniformly randomly, from {@code alphabet}.
	 * 
	 * @param length The length of the random string to be generated.
	 * @return {@code length} random characters.
	 */
	public String generate(String alphabet, int length) {
		char[] out = new char[length];
		for (int i = 0; i < length; i++) {
			out[i] = alphabet.charAt(random.nextInt(alphabet.length()));
		}
		return new String(out);
	}
	
	/**
	 * Hashes a provided password into a string you should store someplace; a password can later be verified with this string.
	 * 
	 * This string cannot be used to recover the password, and it is hard to brute force a list to figure out which one, if any, is the right password.
	 * 
	 * @param password A password
	 * @return A string which can later be used (with {@link #verifyPassword(String, char[])}) to verify a user entered this password.
	 */
	public String hashPassword(char[] password) {
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		return BCrypt.generate(password, salt, 10);
	}
	
	
	/**
	 * Verifies if a password is the same as one entered earlier and provided to {@link #hashPassword(char[])}.
	 * 
	 * @param hash The string returned earlier by a call to {@code hashPassword}.
	 * @param password The password, as entered by a user trying to confirm their identity.
	 */
	public boolean verifyPassword(String hash, char[] password) {
		return BCrypt.checkPassword(hash, password);
	}
}
