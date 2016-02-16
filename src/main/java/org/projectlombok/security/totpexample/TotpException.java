package org.projectlombok.security.totpexample;

public class TotpException extends RuntimeException {
	public TotpException() {
	}
	
	public TotpException(String message, Throwable cause) {
		super(message, cause);
	}
	
	public TotpException(String message) {
		super(message);
	}
	
	public TotpException(Throwable cause) {
		super(cause);
	}
}
