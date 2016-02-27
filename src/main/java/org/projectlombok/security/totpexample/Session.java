package org.projectlombok.security.totpexample;

/**
 * Represents short-lived 'mostly single use' sessions, to let servlets communicate securely through the user's browser.
 */
public interface Session {
	/**
	 * Returns the session key.
	 * 
	 * @return The session key; this session object can be recreated by passing the key to the session store.
	 */
	String getSessionKey();
	
	/**
	 * Store a key/value pair in this session. Given this session and the same key, the value can be retrieved later.
	 * 
	 * @param key The key for this key/value pair; may not be {@code null} and may not be empty.
	 * @param value The value for this key/value pair; may noy be {@code null}.
	 */
	Session put(String key, String value);
	
	/**
	 * Retrieve the value that goes with the provided key.
	 * 
	 * @param key The key for the key/value pair you want to look up.
	 * @param defaultValue The value to return when the key is not in this session.
	 */
	String getOrDefault(String key, String defaultValue);
}
