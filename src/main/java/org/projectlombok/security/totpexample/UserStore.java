package org.projectlombok.security.totpexample;

import org.projectlombok.security.totpexample.Totp.TotpData;

/**
 * An abstraction for a storage mechanism for a user's data, including their password hashes and TOTP secrets.
 * 
 * Generally implemented in the form of database queries.
 */
public interface UserStore {
	/**
	 * Enable TOTP for this user.
	 * 
	 * @param username Enable TOTP for the user with this username
	 * @param secret The TOTP secret. Store this in the database; you must return it later in the {@link #getTotpData(String)} call.
	 * @param lastSuccessfulTick The last tick to be verified with TOTP. Store this in the database; you must return it later in the {@link #getTotpData(String)} call.
	 */
	void enableTotp(String username, String secret, long lastSuccessfulTick);
	
	/**
	 * Retrieve TOTP data registered with this user store earlier.
	 * 
	 * This data is created/updated with one of these calls:<ul>
	 * <li>{@link #enableTotp(String, String, long)} or</li>
	 * <li>{@link #createUserWithTotp(String, char[], String, long)} or</li>
	 * <li>{@link #updateLastSuccessfulTickAndClearFailureCount(String, long)}</li>
	 * </ul>
	 */
	TotpData getTotpData(String username);
	
	/**
	 * Update the TOTP data for this user; should only succeed if this user isn't locked out.
	 * 
	 * This data must be returned in the {@link #getTotpData(String)} call.
	 */
	void updateLastSuccessfulTick(String username, long lastSuccessfulTick);
	
	/**
	 * Update the TOTP data for this user, marking the user as locked out (they have to go through a troubleshooting step to re-enable their account).
	 */
	void markLockedOut(String username);
	
	/**
	 * Update the TOTP data for this user, marking the user as no longer locked out.
	 */
	void clearLockedOut(String username);
	
	/**
	 * Create a new user in the user store.
	 * 
	 * @param username The username of the user (fail if this username already exists).
	 * @param password The password of the user. Don't store this directly, but hash it using BCrypt, SCrypt, Argon2, PBKDF, or another safe password hasher. (MD5, SHA256, etc are not safe!)
	 * @param secret The TOTP secret which must be stored verbatim.
	 * @param lastSuccessfulTick Must also be stored verbatim.
	 */
	void createUserWithTotp(String username, char[] password, String secret, long lastSuccessfulTick);
	
	/**
	 * Check if a username exists in the user store.
	 */
	boolean userExists(String username);
	
	/**
	 * Verify if the provided password is the password of this user.
	 */
	boolean verifyPassword(String username, char[] password);
	
	/** Return a long lived session id, generally intended to be stored via a cookie. */
	String createNewLongLivedSession(String username);
	
	/**
	 * Destroy a long lived session created earlier with {@link #createNewLongLivedSession(String)}.
	 */
	void destroyLongLivedSession(String sessionId);
	
	/**
	 * Find a long lived session created earlier with {@link #createNewLongLivedSession(String)}.
	 */
	String getUserFromSessionKey(String sessionKey);
}
