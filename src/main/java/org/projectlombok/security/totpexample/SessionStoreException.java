package org.projectlombok.security.totpexample;

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
