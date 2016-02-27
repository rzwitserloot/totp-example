package org.projectlombok.security.totpexample;

/**
 * Represents a short-lived session store, used to communicate pertinent data from one page load to another.
 * 
 * This is not the session store for long lived sessions (sessions which are stored using long-lived mechanisms like cookies and which live for hours or more).
 */
public interface SessionStore {
	/**
	 * Creates sessions in the session store.
	 * 
	 * @param ttl Time-to-live; a session expires automatically after this many milliseconds.
	 * @throws SessionStoreException If the session store is corrupt.
	 */
	Session create(long ttl) throws SessionStoreException;
	
	/**
	 * Fetches sessions from the session store.
	 * 
	 * @return The session associated with the given key.
	 * @throws NoSuchSessionException If this session doesn't exist or has expired. (subclass of SessionStoreException).
	 * @throws SessionStoreException If the session store is corrupt.
	 */
	Session get(String sessionKey) throws SessionStoreException, NoSuchSessionException;
}
