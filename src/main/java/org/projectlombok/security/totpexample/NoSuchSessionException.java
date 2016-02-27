package org.projectlombok.security.totpexample;

/**
 * Thrown if a request is made for a short-lived session but it has expired or isn't found.
 */
public class NoSuchSessionException extends SessionStoreException {
	private final String sessionKey;
	
	public NoSuchSessionException(String sessionKey) {
		super("No such session: " + sessionKey);
		this.sessionKey = sessionKey;
	}
	
	public String getSessionKey() {
		return sessionKey;
	}
}
