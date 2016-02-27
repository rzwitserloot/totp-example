package org.projectlombok.security.totpexample;

/**
 * Thrown to indicate a short lived session is not found or has expired.
 */
public class SessionNotFoundException extends SessionStoreException {
	public SessionNotFoundException(String key) {
		super("Session not found: " + key);
	}
}
