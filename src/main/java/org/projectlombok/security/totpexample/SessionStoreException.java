package org.projectlombok.security.totpexample;

/**
 * General exception when there are issues (generally, corruption) in the session store.
 */
public class SessionStoreException extends RuntimeException {
	public SessionStoreException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public SessionStoreException(String message) {
		super(message);
	}
	
	public SessionStoreException(Throwable cause) {
		super(cause);
	}
}
