package org.projectlombok.security.totpexample;

/**
 * General exception when there are issues (generally, corruption) in the user store.
 */
public class UserStoreException extends RuntimeException {
	public UserStoreException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public UserStoreException(String message) {
		super(message);
	}
	
	public UserStoreException(Throwable cause) {
		super(cause);
	}
}
