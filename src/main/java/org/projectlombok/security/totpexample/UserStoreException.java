package org.projectlombok.security.totpexample;

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
