package org.projectlombok.security.totpexample;

public interface SessionStore {
	Session create(long ttl) throws SessionStoreException;
	Session get(String sessionKey) throws SessionStoreException;
}
