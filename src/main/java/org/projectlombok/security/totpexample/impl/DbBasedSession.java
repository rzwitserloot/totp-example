package org.projectlombok.security.totpexample.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionExpiredException;
import org.projectlombok.security.totpexample.SessionStoreException;

class DbBasedSession implements Session {
	private final DbBasedSessionStore store;
	private final int sessionId;
	private final String sessionKey;
	
	public DbBasedSession(DbBasedSessionStore store, int sessionId, String sessionKey) {
		this.sessionKey = sessionKey;
		this.store = store;
		this.sessionId = sessionId;
	}
	
	@Override public String getSessionKey() {
		return sessionKey;
	}
	
	@Override public Session put(String key, String value) {
		if (key == null) throw new NullPointerException("key");
		if (value == null) throw new NullPointerException("value");
		if (key.isEmpty()) throw new IllegalArgumentException("key is empty");
		
		try (Connection connection = store.createConnection()) {
			ensureSession(connection);
			try (PreparedStatement s = connection.prepareStatement("merge into SESSIONVALUES (SESSION, KEY, VALUE) key (SESSION, KEY) values (?, ?, ?);")) {
				s.setInt(1, sessionId);
				s.setString(2, key);
				s.setString(3, value);
				s.execute();
			}
			connection.commit();
		} catch (SQLException e) {
			throw new SessionStoreException(e);
		}
		
		return this;
	}
	
	private void ensureSession(Connection connection) {
		try (PreparedStatement s = connection.prepareStatement("select ID from SESSIONSTORE where id = ? and EXPIRES >= now();")) {
			s.setInt(1, sessionId);
			try (ResultSet result = s.executeQuery()) {
				if (!result.next()) throw new SessionExpiredException(sessionKey);
			}
		} catch (SQLException e) {
			throw new SessionStoreException(e);
		}
	}
	
	@Override public String getOrDefault(String key, String defaultValue) {
		if (key == null) throw new NullPointerException("key");
		if (key.isEmpty()) throw new IllegalArgumentException("key is empty");
		
		try (Connection connection = store.createConnection()) {
			ensureSession(connection);
			try (PreparedStatement s = connection.prepareStatement("select VALUE from SESSIONVALUES where SESSION = ? and KEY = ?;")) {
				s.setInt(1, sessionId);
				s.setString(2, key);
				try (ResultSet result = s.executeQuery()) {
					String value = null;
					if (result.next()) value = result.getString(1);
					result.close();
					connection.commit();
					return value != null ? value : defaultValue;
				}
			}
		} catch (SQLException e) {
			throw new SessionStoreException(e);
		}
	}
}
