package org.projectlombok.security.totpexample;

public class SessionNotFoundException extends SessionStoreException {
	public SessionNotFoundException(String key) {
		super("Session not found: " + key);
	}
}
