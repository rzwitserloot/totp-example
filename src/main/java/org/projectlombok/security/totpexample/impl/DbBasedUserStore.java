package org.projectlombok.security.totpexample.impl;

import java.io.File;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.projectlombok.security.totpexample.Crypto;
import org.projectlombok.security.totpexample.UserStore;
import org.projectlombok.security.totpexample.UserStoreException;
import org.projectlombok.security.totpexample.Totp.TotpData;

public class DbBasedUserStore implements UserStore {
	private final Crypto crypto;
	private final File dbDir = new File("./db");
	
	public DbBasedUserStore(Crypto crypto) {
		if (crypto == null) throw new NullPointerException("crypto");
		this.crypto = crypto;
		this.dbDir.mkdirs();
	}
	
	Connection createConnection() throws SQLException {
		Connection connection = DriverManager.getConnection("jdbc:h2:./db/users;DB_CLOSE_DELAY=60");
		connection.setAutoCommit(false);
		return connection;
	}
	
	private void ensureUserTables(Connection connection) throws SQLException {
		DatabaseMetaData meta = connection.getMetaData();
		boolean available;
		try (ResultSet tables = meta.getTables(null, null, "USERSTORE", null)) {
			available = tables.next();
		}
		
		if (!available) {
			try (Statement s = connection.createStatement()) {
				// These could of course be a single table (integrate columns 'LASTTICK', 'FAILCOUNT', and 'SECRET' from TOTPSTORE into USERSTORE.
				// Here we use 2 tables, to show how to update an existing installation without modifying a table. This setup is also nice if you
				// don't force every user to enable TOTP right away.
				s.execute(
					"create table USERSTORE (" +
					"ID int identity, " +
					"USERNAME varchar not null unique, " +
					"PASSWORDHASH varchar not null" +
					");");
				
				s.execute(
					"create table TOTPSTORE (" +
					"ID int identity, " +
					"USERNAME varchar not null unique, " +
					"LASTTICK bigint not null, " +
					"FAILCOUNT int not null, " +
					"SECRET varchar not null, " +
					"foreign key (USERNAME) references USERSTORE(USERNAME) on delete cascade" +
					");");
			}
		}
		connection.commit();
	}
	
	@Override public boolean userExists(String username) {
		boolean exists = false;
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement checkUser = connection.prepareStatement("select ID from USERSTORE where USERNAME = ? limit 1;")) {
				checkUser.setString(1, username);
				try (ResultSet result = checkUser.executeQuery()) {
					exists = result.next();
				}
			}
			connection.commit();
			return exists;
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public boolean verifyPassword(String username, char[] password) {
		String passHash = null;
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement checkUser = connection.prepareStatement("select PASSWORDHASH from USERSTORE where USERNAME = ? limit 1;")) {
				checkUser.setString(1, username);
				try (ResultSet result = checkUser.executeQuery()) {
					if (result.next()) {
						passHash = result.getString(1);
					}
				}
			}
			connection.commit();
			
			if (passHash == null) {
				return false;
			}
			return crypto.verifyPassword(passHash, password);
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public void createUserWithTotp(String username, char[] password, String secret, long lastSuccessfulTick) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (
				PreparedStatement createUser = connection.prepareStatement("insert into USERSTORE (USERNAME, PASSWORDHASH) values (?, ?);");
				PreparedStatement createTotp = connection.prepareStatement("insert into TOTPSTORE (USERNAME, SECRET, LASTTICK, FAILCOUNT) values (?, ?, ?, ?);")) {
				createUser.setString(1, username);
				createUser.setString(2, crypto.hashPassword(password));
				createTotp.setString(1, username);
				createTotp.setString(2, secret);
				createTotp.setLong(3, lastSuccessfulTick);
				createTotp.setInt(4, 0);
				createUser.executeUpdate();
				createTotp.executeUpdate();
				connection.commit();
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public void enableTotp(String username, String secret, long lastSuccessfulTick) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement s = connection.prepareStatement("insert into TOTPSTORE (USERNAME, SECRET, LASTTICK, FAILCOUNT) values (?, ?, ?, ?);")) {
				s.setString(1, username);
				s.setString(2, secret);
				s.setLong(3, lastSuccessfulTick);
				s.setInt(4, 0);
				s.executeUpdate();
				connection.commit();
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public TotpData getTotpData(String username) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement s = connection.prepareStatement("select SECRET, FAILCOUNT, LASTTICK from TOTPSTORE where USERNAME = ?;")) {
				s.setString(1, username);
				try (ResultSet results = s.executeQuery()) {
					if (!results.next()) return null;
					TotpData out = new TotpData(results.getString(1), results.getInt(2), results.getLong(3));
					results.close();
					s.close();
					connection.commit();
					return out;
				}
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public void updateLastSuccessfulTickAndClearFailureCount(String username, long lastSuccessfulTick) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement s = connection.prepareStatement("update TOTPSTORE set FAILCOUNT = ?, LASTTICK = ? where USERNAME = ?;")) {
				s.setInt(1, 0);
				s.setLong(2, lastSuccessfulTick);
				s.setString(3, username);
				s.executeUpdate();
				connection.commit();
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public int incrementFailureCount(String username) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (
				PreparedStatement read = connection.prepareStatement("select FAILCOUNT from TOTPSTORE where USERNAME = ?;");
				PreparedStatement write = connection.prepareStatement("update TOTPSTORE set FAILCOUNT = ? where USERNAME = ? and FAILCOUNT = ?;")) {
				
				read.setString(1, username);
				write.setString(2, username);
				int lastFailCount = -1;
				while (true) {
					try (ResultSet results = read.executeQuery()) {
						if (!results.next()) throw new UserStoreException("User not found in TOTP store: " + username);
						lastFailCount = results.getInt(1);
					}
					
					write.setInt(1, lastFailCount + 1);
					write.setInt(3, lastFailCount);
					if (0 != write.executeUpdate()) break;
				}
				connection.commit();
				return lastFailCount + 1;
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
}
