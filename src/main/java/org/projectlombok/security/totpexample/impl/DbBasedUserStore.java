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
import java.util.concurrent.TimeUnit;

import org.projectlombok.security.totpexample.Crypto;
import org.projectlombok.security.totpexample.UserStore;
import org.projectlombok.security.totpexample.UserStoreException;
import org.projectlombok.security.totpexample.Totp.TotpData;

/**
 * This is an embedded DB engine (based on {@code h2database.com}) based implementation of the {@code UserStore} interface.
 */
public class DbBasedUserStore implements UserStore {
	private static final long DEFAULT_USERSESSION_EXPIRY = TimeUnit.DAYS.toMillis(5);
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
		
		if (available) {
			try (Statement s = connection.createStatement()) {
				s.execute("delete from USERSESSIONSTORE where EXPIRES < now();");
			}
		} else {
			try (Statement s = connection.createStatement()) {
				// USERSTORE+TOTPSTORE could of course be a single table (integrate columns 'LASTTICK', 'LOCKEDOUT', and 'SECRET' from TOTPSTORE into USERSTORE).
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
					"LOCKEDOUT boolean not null, " +
					"SECRET varchar not null, " +
					"foreign key (USERNAME) references USERSTORE(USERNAME) on delete cascade" +
					");");
				
				s.execute(
					"create table USERSESSIONSTORE (" +
					"ID int identity, " +
					"USERID int not null, " +
					"SESSIONKEY varchar not null, " +
					"EXPIRES timestamp not null, " +
					"foreign key (USERID) references USERSTORE(ID) on delete cascade" +
					");");
				
				s.execute("create index on USERSESSIONSTORE(SESSIONKEY);");
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
				PreparedStatement createTotp = connection.prepareStatement("insert into TOTPSTORE (USERNAME, SECRET, LASTTICK, LOCKEDOUT) values (?, ?, ?, ?);")) {
				createUser.setString(1, username);
				createUser.setString(2, crypto.hashPassword(password));
				createTotp.setString(1, username);
				createTotp.setString(2, secret);
				createTotp.setLong(3, lastSuccessfulTick);
				createTotp.setBoolean(4, false);
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
			try (PreparedStatement s = connection.prepareStatement("insert into TOTPSTORE (USERNAME, SECRET, LASTTICK, LOCKEDOUT) values (?, ?, ?, ?);")) {
				s.setString(1, username);
				s.setString(2, secret);
				s.setLong(3, lastSuccessfulTick);
				s.setBoolean(4, false);
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
			try (PreparedStatement s = connection.prepareStatement("select SECRET, LOCKEDOUT, LASTTICK from TOTPSTORE where USERNAME = ?;")) {
				s.setString(1, username);
				try (ResultSet results = s.executeQuery()) {
					if (!results.next()) return null;
					TotpData out = new TotpData(results.getString(1), results.getBoolean(2), results.getLong(3));
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
	
	@Override public void updateLastSuccessfulTick(String username, long lastSuccessfulTick) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement s = connection.prepareStatement("update TOTPSTORE set LASTTICK = ? where USERNAME = ? and not LOCKEDOUT;")) {
				s.setLong(1, lastSuccessfulTick);
				s.setString(2, username);
				int upd = s.executeUpdate();
				connection.commit();
				if (upd == 0) {
					throw new UserStoreException("user is locked out.");
				}
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public void markLockedOut(String username) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement write = connection.prepareStatement("update TOTPSTORE set LOCKEDOUT = ? where USERNAME = ?;")) {
				write.setBoolean(1, true);
				write.setString(2, username);
				write.executeUpdate();
				connection.commit();
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public void clearLockedOut(String username) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (PreparedStatement write = connection.prepareStatement("update TOTPSTORE set LOCKEDOUT = ? where USERNAME = ?;")) {
				write.setBoolean(1, false);
				write.setString(2, username);
				write.executeUpdate();
				connection.commit();
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public String createNewLongLivedSession(String username) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (
				PreparedStatement findUserId = connection.prepareStatement("select ID from USERSTORE where USERNAME = ? limit 1;");
				PreparedStatement addSessionKey = connection.prepareStatement("insert into USERSESSIONSTORE (USERID, SESSIONKEY, EXPIRES) values (?, ?, ?);")) {
				
				findUserId.setString(1, username);
				Integer userId = null;
				try (ResultSet results = findUserId.executeQuery()) {
					if (results.next()) {
						userId = results.getInt(1);
					}
				}
				
				if (userId == null) {
					throw new UserStoreException("user does not exist: " + username);
				}
				addSessionKey.setInt(1, userId);
				String sessionKey = crypto.generateRandomKey(32);
				addSessionKey.setString(2, sessionKey);
				addSessionKey.setTimestamp(3, new Timestamp(System.currentTimeMillis() + DEFAULT_USERSESSION_EXPIRY));
				addSessionKey.executeUpdate();
				connection.commit();
				return sessionKey;
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public void destroyLongLivedSession(String sessionId) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			try (
				PreparedStatement findUserId = connection.prepareStatement("select USERID from USERSESSIONSTORE where SESSIONKEY = ? limit 1;");
				PreparedStatement deleteSessions = connection.prepareStatement("delete from USERSESSIONSTORE where USERID = ?;")) {
				
				findUserId.setString(1, sessionId);
				Integer userId = null;
				try (ResultSet results = findUserId.executeQuery()) {
					if (results.next()) {
						userId = results.getInt(1);
					}
				}
				
				if (userId == null) {
					connection.commit();
					return;
				}
				deleteSessions.setInt(1, userId);
				deleteSessions.executeUpdate();
				connection.commit();
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
	
	@Override public String getUserFromSessionKey(String sessionKey) {
		try (Connection connection = createConnection()) {
			ensureUserTables(connection);
			String username = null;
			try (PreparedStatement findName = connection.prepareStatement("select USERNAME from USERSESSIONSTORE inner join USERSTORE on USERSESSIONSTORE.USERID = USERSTORE.ID where SESSIONKEY = ? and EXPIRES >= ? limit 1;")) {
				findName.setString(1, sessionKey);
				findName.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
				try (ResultSet results = findName.executeQuery()) {
					if (results.next()) {
						username = results.getString(1);
					}
				}
				connection.commit();
				return username;
			}
		} catch (SQLException e) {
			throw new UserStoreException(e);
		}
	}
}
