package org.projectlombok.security.totpexample;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Totp {
	public static final String SESSIONKEY_USERNAME = "totpUsername";
	public static final String SESSIONKEY_URI = "totpUri";
	public static final String SESSIONKEY_SECRET = "totpSecret";
	private static final long KEY_VALIDATION_WINDOW = TimeUnit.SECONDS.toMillis(30);
	private static final long[] DELTAS;
	private static final TotpResult[] ACTION;
	
	static {
		long[] d = new long[11];
		TotpResult[] t = new TotpResult[11];
		int o = 0;
		for (int i = 0; i < 3; i++) {
			d[o] = i;
			t[o++] = TotpResult.SUCCESS;
		}
		for (int i = 3; i < 6; i++) {
			d[o] = i;
			t[o++] = TotpResult.CLOCK_MISMATCH_NEARBY;
		}
		for (int i = 118; i < 123; i++) {
			d[o] = i;
			t[o++] = TotpResult.CLOCK_MISMATCH_DST;
		}
		DELTAS = d;
		ACTION = t;
	}
	
	private static final String BASE32CHARS = "abcdefghijklmnopqrstuvwxyz234567";
	private static final long SETUP_PROCEDURE_TTL = TimeUnit.HOURS.toMillis(1);
	private static final int LOCKOUT_LIMIT = 5;
	
	private final UserStore users;
	private final SessionStore sessions;
	private final Crypto crypto;
	
	public Totp(UserStore users, SessionStore sessions, Crypto crypto) {
		this.users = users;
		this.sessions = sessions;
		this.crypto = crypto;
	}
	
	public static final class TotpData {
		private final String secret;
		private final int failureCount;
		private final long lastSuccessfulTick;
		
		public TotpData(String secret, int failureCount, long lastSuccessfulTick) {
			this.secret = secret;
			this.failureCount = failureCount;
			this.lastSuccessfulTick = lastSuccessfulTick;
		}
		
		public int getFailureCount() {
			return failureCount;
		}
		
		public String getSecret() {
			return secret;
		}
		
		public long getLastSuccessfulTick() {
			return lastSuccessfulTick;
		}
	}
	
	private final class CodeVerification {
		TotpResult result;
		long tick;
		
		CodeVerification(TotpResult result, long tick) {
			this.result = result;
			this.tick = tick;
		}
	}
	
	public enum TotpResult {
		SUCCESS,
		ALREADY_LOCKED_OUT,
		NOW_LOCKED_OUT,
		CLOCK_MISMATCH_NEARBY,
		CLOCK_MISMATCH_DST,
		CODE_VERIFICATION_FAILURE,
		CODE_ALREADY_USED,
		SESSION_EXPIRED,
		INVALID_INPUT;
		
		public boolean isSuccess() {
			return this == SUCCESS;
		}
		
		public boolean isLockedOut() {
			return this == ALREADY_LOCKED_OUT || this == NOW_LOCKED_OUT;
		}
		
		public boolean isCodeVerificationFailure() {
			return this == CLOCK_MISMATCH_NEARBY || this == CLOCK_MISMATCH_DST || this == TotpResult.CODE_VERIFICATION_FAILURE || this == NOW_LOCKED_OUT;
		}
	}
	
	/**
	 * Generates a new TOTP key pair for the given user.
	 */
	public Session startSetupTotp(String username, String applicationName) {
		String secret = crypto.generate(BASE32CHARS, 16);
		Session session = sessions.create(SETUP_PROCEDURE_TTL);
		String uri = toUri(username, applicationName, secret);
		session.put(SESSIONKEY_SECRET, secret);
		session.put(SESSIONKEY_URI, uri);
		session.put(SESSIONKEY_USERNAME, username);
		return session;
	}
	
	public TotpResult finishSetupTotp(Session session, String verificationCode) {
		if (session == null) return TotpResult.SESSION_EXPIRED;
		String secret = session.getOrDefault(SESSIONKEY_SECRET, null);
		String username = session.getOrDefault(SESSIONKEY_USERNAME, null);
		if (secret == null || username == null) throw new TotpException("TOTP setup process not started");
		CodeVerification result = verifyCode(secret, verificationCode, 0L);
		if (result.result == TotpResult.SUCCESS) {
			// TODO review all these session.getOrDefaults; I'd really just rather do a getAndItNeedsToBeThere kind of call here. It should be, but bad stuff happens if this password isn't in here.
			String password = session.getOrDefault("password", null);
			users.createUserWithTotp(username, password, secret, result.tick - 1);
		}
		return result.result;
	}
	
	/**
	 * TODO SECURITY: Do *NOT* give any feedback on the TotpStatus of any user unless they have already entered the correct password.
	 */
	public TotpData startCheckTotp(String username) {
		return users.getTotpData(username);
	}
	
	/**
	 * @param sessionKey A session started with {@link #startCheckTotp(String)}.
	 */
	public TotpResult finishCheckTotp(String sessionKey, String verificationCode) {
		Session session = sessions.get(sessionKey);
		if (session == null) throw new TotpException("Session expired / nonexistent");
		String username = session.getOrDefault("username", null);
		TotpData userData = users.getTotpData(username);
		if (userData.getFailureCount() >= LOCKOUT_LIMIT) return TotpResult.ALREADY_LOCKED_OUT;
		CodeVerification result = verifyCode(userData.getSecret(), verificationCode, userData.getLastSuccessfulTick());
		if (result.result == TotpResult.SUCCESS) {
			users.updateLastSuccessfulTickAndClearFailureCount(username, result.tick);
			return result.result;
		}
		
		if (result.result.isCodeVerificationFailure()) {
			if (users.incrementFailureCount(username) >= LOCKOUT_LIMIT) return TotpResult.NOW_LOCKED_OUT;
			return result.result;
		}
		
		return result.result;
	}
	
	private static String toUri(String username, String application, String secret) {
		String app = urlSafe(application);
		String user = urlSafe(username);
		return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%1$s", app, user, secret);
	}
	
	private CodeVerification verifyCode(String secret, String verificationCode, long lastSuccessfulTick) {
		byte[] secretBytes = toBytes(secret);
		long tick = System.currentTimeMillis() / KEY_VALIDATION_WINDOW;
		
		for (int i = 0; i < DELTAS.length; i++) {
			long d = DELTAS[i];
			
			long t = tick + d;
			if (calculateCode(secretBytes, t).equals(verificationCode)) {
				if (t <= lastSuccessfulTick) return new CodeVerification(TotpResult.CODE_ALREADY_USED, t);
				return new CodeVerification(ACTION[i], t);
			}
			if (d != 0) {
				t = tick - d;
				if (calculateCode(secretBytes, t).equals(verificationCode)) {
					if (t <= lastSuccessfulTick) return new CodeVerification(TotpResult.CODE_ALREADY_USED, t);
					return new CodeVerification(ACTION[i], t);
				}
			}
		}
		
		return new CodeVerification(TotpResult.CODE_VERIFICATION_FAILURE, 0L);
	}
	
	private static String urlSafe(String value) {
		try {
			// Google Authenticator doesn't handle '+' correctly
			return URLEncoder.encode(value, "UTF8").replace("+", "%20");
		} catch (UnsupportedEncodingException e) {
			throw new Error("Broken JVM");
		}
	}
	
	private static String calculateCode(byte[] secret, long time) {
		Key keySpec = new SecretKeySpec(secret, "HmacSHA1");
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA1");
			mac.init(keySpec);
		} catch (NoSuchAlgorithmException e) {
			// TODO review what kind of exception this should be.
			throw new InternalError("HmacSHA1 algorithm is not available; check your JVM security settings, they may have been restricted");
		} catch (InvalidKeyException e) {
			throw new TotpException("Invalid secret");
		}
		byte[] hashedTimestamp = mac.doFinal(bigEndian(time));
		int offset = hashedTimestamp[19] & 0xF;
		long truncatedHash = 0L;
		
		for (int i = 0; i < 4; i++) {
			truncatedHash = (truncatedHash << 8) | (hashedTimestamp[offset + i] & 0xff);
		}
		
		truncatedHash = (truncatedHash & 0x7fff_ffff) % 1_000_000;
		return String.format("%06d", truncatedHash);
	}
	
	private static byte[] bigEndian(long value) {
		byte[] bytes = new byte[8];
		for (int i = 7; i >= 0; i--) {
			bytes[i] = (byte) (value & 0xffL);
			value >>= 8;
		}
		return bytes;
	}
	
	private static byte[] toBytes(String secret) {
		byte[] result = new byte[10];
		decode32(secret, result, 0, 0);
		decode32(secret, result, 8, 5);
		return result;
	}
	
	private static void decode32(String secret, byte[] bytes, int secretOffset, int byteOffset) {
		int[] values = new int[8];
		for (int i = 0; i < 8; i++) {
			values[i] = BASE32CHARS.indexOf(secret.charAt(i + secretOffset));
		}
		bytes[0 + byteOffset] = (byte) ((((values[0] & 0x1f) << 3) | ((values[1] & 0x1c) >> 2)) & 0xff);
		bytes[1 + byteOffset] = (byte) ((((values[1] & 0x03) << 6) | ((values[2] & 0x1f) << 1) | ((values[3] & 0x10) >> 4)) & 0xff);
		bytes[2 + byteOffset] = (byte) ((((values[3] & 0x0f) << 4) | ((values[4] & 0x1e) >> 1)) & 0xff);
		bytes[3 + byteOffset] = (byte) ((((values[4] & 0x01) << 7) | ((values[5] & 0x1f) << 2) | ((values[6] & 0x18) >> 3)) & 0xff);
		bytes[4 + byteOffset] = (byte) ((((values[6] & 0x07) << 5) | (values[7] & 0x1f)) & 0xff);
	}
}
