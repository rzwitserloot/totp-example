package org.projectlombok.security.totpexample.impl;

import java.io.File;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;

import org.projectlombok.security.totpexample.Crypto;
import org.projectlombok.security.totpexample.Session;
import org.projectlombok.security.totpexample.SessionNotFoundException;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.SessionStoreException;

public class DbBasedSessionStore implements SessionStore {
	private final Crypto crypto;
	private final File dbDir = new File("./db");
	
	public DbBasedSessionStore(Crypto crypto) {
		if (crypto == null) throw new NullPointerException("crypto");
		this.crypto = crypto;
		this.dbDir.mkdirs();
	}
	
	Connection createConnection() throws SQLException {
		Connection connection = DriverManager.getConnection("jdbc:h2:./db/sessions;DB_CLOSE_DELAY=60");
		connection.setAutoCommit(false);
		return connection;
	}
	
	@Override public Session create(long ttl) {
		long expiresAt = System.currentTimeMillis() + ttl;
		String sessionKey = crypto.generateRandomKey(12);
		try (Connection connection = createConnection()) {
			ensureSessionTables(connection);
			try (PreparedStatement s = connection.prepareStatement("insert into SESSIONSTORE (KEY, EXPIRES) values (?, ?);", Statement.RETURN_GENERATED_KEYS)) {
				s.setString(1, sessionKey);
				s.setTimestamp(2, new Timestamp(expiresAt));
				s.executeUpdate();
				try (ResultSet result = s.getGeneratedKeys()) {
					result.next();
					int id = result.getInt(1);
					result.close();
					connection.commit();
					return new DbBasedSession(this, id, sessionKey);
				}
			}
		} catch (SQLException e) {
			throw new SessionStoreException(e);
		}
	}
	
	private void ensureSessionTables(Connection connection) throws SQLException {
		DatabaseMetaData meta = connection.getMetaData();
		boolean available;
		try (ResultSet tables = meta.getTables(null, null, "SESSIONSTORE", null)) {
			available = tables.next();
		}
		
		if (available) {
			try (Statement s = connection.createStatement()) {
				s.execute("delete from SESSIONSTORE where EXPIRES < now();");
			}
		} else {
			try (Statement s = connection.createStatement()) {
				s.execute(
					"create table SESSIONSTORE (" +
					"ID int identity, " +
					"KEY varchar not null unique, " +
					"EXPIRES timestamp not null" +
					");");
				
				s.execute(
					"create table SESSIONVALUES (" +
					"ID int identity, " +
					"SESSION int not null, " +
					"KEY varchar not null, " +
					"VALUE varchar not null, " +
					"unique(SESSION, KEY), " +
					"foreign key (SESSION) references SESSIONSTORE on delete cascade" +
					");");
			}
		}
		connection.commit();
	}
	
	@Override public Session get(String sessionKey) {
		try (Connection connection = createConnection()) {
			ensureSessionTables(connection);
			try (PreparedStatement s = connection.prepareStatement("select id from SESSIONSTORE where KEY = ? and EXPIRES >= now();")) {
				s.setString(1, sessionKey);
				try (ResultSet result = s.executeQuery()) {
					if (result.next()) {
						int id = result.getInt(1);
						result.close();
						connection.commit();
						return new DbBasedSession(this, id, sessionKey);
					}
					throw new SessionNotFoundException(sessionKey);
				}
			}
		} catch (SQLException e) {
			throw new SessionStoreException(e);
		}
	}
}
