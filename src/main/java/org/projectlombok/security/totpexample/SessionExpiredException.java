package org.projectlombok.security.totpexample;

public class SessionExpiredException extends SessionStoreException {
	public SessionExpiredException(String key) {
		super("Session expired: " + key);
	}
}
