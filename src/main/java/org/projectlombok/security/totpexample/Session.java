package org.projectlombok.security.totpexample;

public interface Session {
	String getSessionKey();
	/*
	 * @param key not null not empty
	 * @param value not null
	 */
	Session put(String key, String value);
	String getOrDefault(String key, String defaultValue);
}