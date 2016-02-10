package org.projectlombok.security.totpexample;

public interface SessionStore {
	Session create(long expiresAt) throws SessionStoreException;
	Session get(String sessionKey) throws SessionStoreException;
}
