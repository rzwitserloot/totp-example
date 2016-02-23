package org.projectlombok.security.totpexample;

import org.projectlombok.security.totpexample.Totp.TotpData;

public interface UserStore {
	void enableTotp(String username, String secret, long lastSuccessfulTick);
	TotpData getTotpData(String username);
	void updateLastSuccessfulTickAndClearFailureCount(String username, long lastSuccessfulTick);
	int incrementFailureCount(String username);
	void createUserWithTotp(String username, char[] password, String secret, long lastSuccessfulTick);
	boolean userExists(String username);
	boolean verifyPassword(String username, char[] password);
}
