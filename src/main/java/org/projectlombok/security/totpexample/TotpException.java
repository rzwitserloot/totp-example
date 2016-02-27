package org.projectlombok.security.totpexample;

/**
 * Generalized exception if there are unexpected problems verifying or setting up TOTP codes. Incorrect codes are handled via return values and not with this exception.
 */
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
